//go:build !windows

package smm

// Non-Windows / non-amd64 stubs.

type KernelRW interface {
	ReadDword(addr uint64) (uint32, error)
	WriteQword(addr, value uint64) error
	ReadDword32(addr uint64) (uint32, error)
}

type SMRAMInfo struct {
	TSEGBase uint64
	TSEGSize uint64
	SMBase   uint64
	IsLocked bool
	BootGuard bool
	SMRAMC   byte
}

type SmmCommBuffer struct {
	Command byte
	Status  byte
	Pad     [6]byte
	SrcAddr uint64
	DstAddr uint64
	Length  uint32
	Pad2    [4]byte
	Data    [3968]byte
}

type SmmInstallConfig struct {
	KernelRW               KernelRW
	CommBufferPhysOverride uint64
}

type SmmInstallResult struct {
	SMBase         uint64
	TSEGBase       uint64
	TSEGSize       uint64
	HandlerAddr    uint64
	CommBufferPhys uint64
	CommBuffer     *SmmCommBuffer
	PingOK         bool
}

func Install(_ SmmInstallConfig) (*SmmInstallResult, error)         { return nil, nil }
func ReadPhysical(_ *SmmInstallResult, _ uint64, _ uint32) ([]byte, error) { return nil, nil }
func WritePhysical(_ *SmmInstallResult, _ uint64, _ []byte) error  { return nil }
func DisableHypervisor(_ *SmmInstallResult, _ uint64) error        { return nil }
func DetectSMRAM(_ KernelRW) (*SMRAMInfo, error)                   { return nil, nil }

func cli()      {}
func sti()      {}
func wbinvdSMM() {}
func triggerSMI(_ byte) {}
func outByte(_ uint16, _ byte) {}
func inByte(_ uint16) byte { return 0 }
