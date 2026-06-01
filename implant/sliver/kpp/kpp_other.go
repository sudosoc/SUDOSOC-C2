//go:build !windows

package kpp

// Non-Windows stubs.

type KernelRWer interface {
	ReadQword(addr uint64) (uint64, error)
	WriteQword(addr, value uint64) error
	ReadDword(addr uint64) (uint32, error)
}

type KPPBypassConfig struct {
	KernelRW              KernelRWer
	KernelBase            uint64
	HookKiTimerExpiration bool
	PrepareSSDTO          bool
}

type KPPBypassResult struct {
	ContextsNeutralized int
	DPCHookInstalled    bool
	SSDT                *SSDTState
	HookState           *HookState
}

type PGContext struct {
	PhysAddr    uint64
	KernelVA    uint64
	DPCOffset   uint64
	OrigDPCAddr uint64
	Neutralized bool
}

type SSDTState struct {
	SSDTBase  uint64
	SSDTLimit uint32
	Hooks     []*SSDTHook
}

type SSDTHook struct {
	SyscallIndex uint32
	OrigOffset   int32
	HookVA       uintptr
	HookPhys     uint64
	Active       bool
}

type HookState struct {
	TargetAddr     uint64
	OrigBytes      []byte
	TrampolineMem  uintptr
	TrampolinePhys uint64
	Active         bool
}

func Bypass(_ KPPBypassConfig) (*KPPBypassResult, error)              { return nil, nil }
func DSEBypass(_ KernelRWer) error                                      { return nil }
func DiscoverAndNeutralize(_ KernelRWer, _ uint64) ([]*PGContext, error) { return nil, nil }
func LocateSSDTO(_ KernelRWer, _ uint64) (*SSDTState, error)            { return nil, nil }
