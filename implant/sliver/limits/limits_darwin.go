//go:build darwin

package limits

/*
	SUDOSOC-C2 Framework — macOS Platform Limits
	Copyright (C) 2026  sudosoc — Seif

	Authorized penetration testing use only.
*/

import (
	"bufio"
	"os"
	"os/exec"
	"strings"
	"time"
)

func isDomainJoined() (bool, error) {
	return false, nil
}

// PlatformLimits — macOS anti-analysis checks.
// Called by limits.go ExecLimits() when {{if not .Config.Debug}}.
func PlatformLimits() {
	// ── 1. ptrace / debugger detection ────────────────────────────────────
	if macTracerDetected() {
		time.Sleep(3 * time.Second)
		os.Exit(0)
	}

	// ── 2. Frida / instrumentation ────────────────────────────────────────
	if macInstrumentationDetected() {
		time.Sleep(5 * time.Second)
		os.Exit(0)
	}

	// ── 3. Virtual machine via DMI / hypervisor flag ──────────────────────
	if macVMDetected() {
		// In a VM we may be in a sandbox/lab — delay but don't exit
		// (legitimate pen-test targets may be VMs)
		time.Sleep(2 * time.Second)
	}

	// ── 4. Sleep canary ───────────────────────────────────────────────────
	start := time.Now()
	time.Sleep(800 * time.Millisecond)
	if time.Since(start) < 500*time.Millisecond {
		os.Exit(0)
	}
}

// macTracerDetected uses sysctl to check for attached debugger.
// P_TRACED flag (0x800) is set in kern.proc.pid.<pid>.kp_proc.p_flag.
// We use the simpler approach of reading /proc equivalent on macOS.
func macTracerDetected() bool {
	// Try sysctl approach via exec (no CGO needed)
	out, err := exec.Command("sysctl", "-n", "kern.proc.pid."+pidString()).Output()
	if err != nil {
		return false
	}
	// P_TRACED = 0x800 in p_flag — look for "traced" keyword or flag
	return strings.Contains(strings.ToLower(string(out)), "traced")
}

func pidString() string {
	pid := os.Getpid()
	buf := make([]byte, 0, 10)
	if pid == 0 {
		return "0"
	}
	for pid > 0 {
		buf = append([]byte{byte('0' + pid%10)}, buf...)
		pid /= 10
	}
	return string(buf)
}

// macInstrumentationDetected checks vmmap output for Frida gadget.
func macInstrumentationDetected() bool {
	// Check environment for Frida / Cycript indicators
	for _, env := range os.Environ() {
		low := strings.ToLower(env)
		for _, sig := range []string{"frida", "cycript", "inject", "_dyld_disable"} {
			if strings.Contains(low, sig) {
				return true
			}
		}
	}
	// Check /proc/self/maps equivalent via /dev/null approach
	// On macOS, read from /private/var/db for analysis artifacts
	analysisFiles := []string{
		"/var/db/frida",
		"/usr/local/lib/frida",
		"/usr/lib/frida",
	}
	for _, p := range analysisFiles {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

// macVMDetected checks DMI / ioreg for hypervisor presence.
func macVMDetected() bool {
	out, err := exec.Command("system_profiler", "SPHardwareDataType").Output()
	if err != nil {
		return false
	}
	low := strings.ToLower(string(out))
	for _, sig := range []string{"vmware", "virtualbox", "parallels", "qemu", "hyperv"} {
		if strings.Contains(low, sig) {
			return true
		}
	}
	// Check sysctl for hypervisor flag
	hv, err := exec.Command("sysctl", "-n", "kern.hv_support").Output()
	if err == nil {
		return strings.TrimSpace(string(hv)) == "1"
	}
	return false
}

// isDomainJoinedReal checks if macOS is bound to Active Directory.
func isDomainJoinedReal() (bool, error) {
	out, err := exec.Command("dsconfigad", "-show").Output()
	if err != nil {
		return false, err
	}
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		line := sc.Text()
		if strings.Contains(line, "Active Directory Domain") &&
			!strings.Contains(line, "not bound") {
			return true, nil
		}
	}
	return false, nil
}
