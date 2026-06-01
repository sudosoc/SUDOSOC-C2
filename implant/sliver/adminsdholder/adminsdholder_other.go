//go:build !windows

package adminsdholder

import "time"

const (
	AccessGenericAll  = uint32(0x10000000)
	AccessFullControl = uint32(0x001F01FF)
)

const (
	AccessAllowedACEType = byte(0x00)
	AccessDeniedACEType  = byte(0x01)
	AceFlagInherited     = byte(0x10)
)

type GrantConfig struct {
	DC             string
	Domain         string
	BeneficiarySID string
	AccessMask     uint32
	AceFlags       byte
}

type GrantResult struct {
	AdminSDHolderDN  string
	BeneficiarySID   string
	PreviousACECount int
	NewACECount      int
	AlreadyPresent   bool
}

type SDPropResult struct {
	DC            string
	TriggeredAt   time.Time
	EstimatedDone time.Time
}

type SecurityDescriptor struct{}

func ParseSecurityDescriptor(_ []byte) (*SecurityDescriptor, error) { return nil, nil }
func (sd *SecurityDescriptor) Raw() []byte                           { return nil }
func (sd *SecurityDescriptor) ACECount() uint16                      { return 0 }
func (sd *SecurityDescriptor) DACLOffset() uint32                    { return 0 }
func (sd *SecurityDescriptor) HasACEForSID(_ []byte) bool            { return false }
func (sd *SecurityDescriptor) AddAllowedACE(_ []byte, _ uint32, _ byte) error { return nil }
func (sd *SecurityDescriptor) RemoveACEsForSID(_ []byte) int         { return 0 }

func Grant(_ *GrantConfig) (*GrantResult, error)                     { return nil, nil }
func Revoke(_, _, _ string) (int, error)                             { return 0, nil }
func TriggerSDProp(_ string) (*SDPropResult, error)                  { return nil, nil }
func SetSDPropInterval(_, _ string, _ uint32) error                  { return nil }
func ListProtectedObjects(_, _ string) ([]string, error)             { return nil, nil }
func AuditAdminSDHolder(_, _ string) ([]string, error)               { return nil, nil }
func FullAttack(_, _, _ string) error                                { return nil }
func ParseSIDString(_ string) ([]byte, error)                        { return nil, nil }
func SIDToString(_ []byte) string                                    { return "" }
func AppendRID(_ []byte, _ uint32) ([]byte, error)                   { return nil, nil }

var SDPropProtectedGroups = []struct {
	Name string
	RID  uint32
}{}
