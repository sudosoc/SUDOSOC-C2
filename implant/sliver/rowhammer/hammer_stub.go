//go:build !amd64

package rowhammer

import "unsafe"

// Non-x64 stubs — on ARM64 we would use DC CIVAC for cache flushing.
// For now these are software-fallback stubs.

func hammer2sidedASM(addr1, addr2 uintptr, iterations, rounds int) {
	for r := 0; r < rounds; r++ {
		for i := 0; i < iterations; i++ {
			_ = *(*byte)(unsafe.Pointer(addr1))
			_ = *(*byte)(unsafe.Pointer(addr2))
		}
	}
}

func hammerManyASM(addrs []uintptr, iterations, rounds int) {
	for r := 0; r < rounds; r++ {
		for i := 0; i < iterations; i++ {
			for _, a := range addrs {
				_ = *(*byte)(unsafe.Pointer(a))
			}
		}
	}
}

func clflushLine(addr uintptr) {
	_ = *(*byte)(unsafe.Pointer(addr))
}

func rdtscpFence() uint64 {
	return 0
}
