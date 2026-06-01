//go:build !windows

package dcshadow

import "time"

type GUID16 [16]byte
func (g GUID16) String() string { return "" }

type DCShadowConfig struct {
	Domain       string
	FakeDCName   string
	FakeFQDN     string
	InvocationID GUID16
	RealDC       string
	Site         string
	RPCPort      uint16
	WaitTimeout  time.Duration
}

type FakeDCRegistration struct {
	ComputerDN string
	ServerDN   string
	NtdsDN     string
	Config     *DCShadowConfig
}

type Change struct {
	ObjectDN   string
	ObjectGUID [16]byte
	Attrs      []AttrChange
}

type AttrChange struct {
	AttrType uint32
	Values   [][]byte
}

type DCShadowResult struct {
	ChangesApplied  int
	ChangesRejected int
	ReplicationTime time.Duration
	Errors          []string
}

type LDAPConnection struct{}
type RPCServer struct{}

func DefaultConfig(_, _ string) *DCShadowConfig         { return nil }
func Connect(_ string) (*LDAPConnection, error)           { return nil, nil }
func PushChanges(_ *DCShadowConfig, _ []Change) (*DCShadowResult, error) { return nil, nil }
func AddGroupMember(_ [16]byte, _, _ string) Change       { return Change{} }
func SetSIDHistory(_ [16]byte, _ string, _ []byte) Change { return Change{} }
func SetPassword(_ [16]byte, _, _ string) Change          { return Change{} }

func (c *LDAPConnection) Close()                                          {}
func (c *LDAPConnection) AddObject(_ string, _ map[string][]string) error { return nil }
func (c *LDAPConnection) ModifyObject(_ string, _ int, _ map[string][]string) error { return nil }
func (c *LDAPConnection) DeleteObject(_ string) error                     { return nil }
func (c *LDAPConnection) SearchOne(_, _, _ string) (string, error)        { return "", nil }
