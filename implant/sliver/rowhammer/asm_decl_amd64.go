//go:build amd64

package rowhammer

// Assembly function declarations for amd64 (implemented in hammer_amd64.s).

func rdtscpFence() uint64
func clflushLine(addr uintptr)
func hammer2sidedASM(addr1, addr2 uintptr, iterations, rounds int)
func hammerManyASM(addrs []uintptr, iterations, rounds int)
