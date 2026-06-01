//go:build !windows

package hypervisor

// Stubs for non-Windows / non-amd64 builds.

func IsActive() bool       { return false }
func Launch() error        { return nil }
func Shutdown()            {}

type EptTables struct{}
type VcpuState struct{}
type HypervisorState struct{}
type GuestRegisters struct{}
