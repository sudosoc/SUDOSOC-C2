//go:build !windows

package kerberos

import "time"

const (
	EtypeRC4HMAC = 23
	EtypeAES128  = 17
	EtypeAES256  = 18
)

type ForgedTicket struct {
	Raw       []byte
	Etype     int
	Domain    string
	Username  string
	ServicePN string
}

type GoldenTicketConfig struct {
	Domain       string
	DomainSID    []byte
	Username     string
	UserID       uint32
	Groups       []uint32
	ExtraSIDs    [][]byte
	KrbtgtNTHash []byte
	KrbtgtAES256 []byte
	Lifetime     time.Duration
	Etype        int
}

type DiamondTicketConfig struct {
	RealTGT        []byte
	Etype          int
	KrbtgtKey      []byte
	AddGroups      []uint32
	AddExtraSIDs   [][]byte
	OverrideUserID uint32
}

type SapphireConfig struct {
	TargetUser  string
	OurTGT      []byte
	OurEtype    int
	KrbtgtKey   []byte
	Domain      string
	ServiceName string
}

type PAC struct{}
type ValidationInfo struct{}
type LSAHandle struct{}

func ForgeGolden(_ *GoldenTicketConfig) (*ForgedTicket, error)   { return nil, nil }
func ForgeDiamond(_ *DiamondTicketConfig) (*ForgedTicket, error) { return nil, nil }
func ForgeSapphire(_ *SapphireConfig) (*ForgedTicket, error)     { return nil, nil }
func OpenLSA(_ bool) (*LSAHandle, error)                          { return nil, nil }
func (h *LSAHandle) Close()                                       {}
func (h *LSAHandle) InjectTicket(_ *ForgedTicket, _ interface{}) error { return nil }
func RC4HMACEncrypt(_, _ []byte, _ uint32, _ []byte) ([]byte, error)  { return nil, nil }
func AES256CTSEncrypt(_, _ []byte, _ uint32, _ []byte) ([]byte, error) { return nil, nil }
