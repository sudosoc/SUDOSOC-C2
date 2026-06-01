//go:build !windows

package dse

// Non-Windows stubs.

type KernelRWer interface {
	ReadQword(addr uint64) (uint64, error)
	WriteQword(addr, value uint64) error
	ReadDword(addr uint64) (uint32, error)
}

type DSEBypassResult struct {
	GCiOptionsCleared     bool
	SeCiCallbacksNulled   bool
	SeILSigningPolicyZero bool
	GCiOptionsAddr        uint64
	SeCiCallbacksAddr     uint64
	SeILSigningPolicyAddr uint64
}

type MappedDriver struct {
	KernelBase uint64
	KernelSize uint64
	EntryPoint uint64
	PhysPages  []uint64
	AllocVA    uintptr
	AllocSize  uintptr
}

type LoadMode int
const (
	LoadModeMap       LoadMode = iota
	LoadModeTestSign
	LoadModePermanent
)

type LoadConfig struct {
	Mode        LoadMode
	DriverBytes []byte
	DriverPath  string
	ServiceName string
	KernelRW    KernelRWer
	KernelBase  uint64
	CIBase      uint64
}

type LoadResult struct {
	Mode        LoadMode
	Mapped      *MappedDriver
	ServicePath string
	DSEResult   *DSEBypassResult
}

func BypassAll(_ KernelRWer, _, _ uint64) (*DSEBypassResult, error) { return nil, nil }
func Restore(_ KernelRWer, _ *DSEBypassResult)                       {}
func MapDriver(_ KernelRWer, _ []byte) (*MappedDriver, error)        { return nil, nil }
func LoadUnsignedDriver(_ LoadConfig) (*LoadResult, error)           { return nil, nil }
func FindGCiOptions(_ KernelRWer, _ uint64) (uint64, error)          { return 0, nil }
func FindSeCiCallbacks(_ KernelRWer, _ uint64) (uint64, error)       { return 0, nil }
func FindSeILSigningPolicy(_ KernelRWer, _ uint64) (uint64, error)   { return 0, nil }

func (m *MappedDriver) Unload() {}
