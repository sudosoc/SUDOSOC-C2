package rowhammer

import (
	"fmt"
	"runtime"
	"sort"
	"unsafe"
)

// PhysPage represents a physical memory page and its mapping.
type PhysPage struct {
	VirtAddr uintptr
	PhysAddr uint64
	PFN      uint64 // Page Frame Number
}

// PhysContiguousRegion is a group of virtually-contiguous pages that are
// also physically contiguous — these are the best candidates for hammering.
type PhysContiguousRegion struct {
	Pages     []PhysPage
	StartPhys uint64
	EndPhys   uint64
	Size      uint64
}

// DRAMRow identifies a DRAM row by bank/row address.
type DRAMRow struct {
	Bank    int
	Row     int
	PhysEnd uint64
}

// MemoryMapper finds physically contiguous memory regions
// and maps virtual addresses to physical addresses.
type MemoryMapper struct {
	pageSize  uintptr
	pageMask  uintptr
	pagefile  uintptr // fd for /proc/self/pagemap (Linux) or handle (Windows)
}

// NewMemoryMapper creates a memory mapper.
func NewMemoryMapper() (*MemoryMapper, error) {
	ps := uintptr(getPageSize())
	m := &MemoryMapper{
		pageSize: ps,
		pageMask: ^(ps - 1),
	}
	if err := m.openPagemap(); err != nil {
		return nil, err
	}
	return m, nil
}

// Close releases the pagemap handle.
func (m *MemoryMapper) Close() {
	m.closePagemap()
}

// VirtToPhys translates a virtual address to physical address.
// Uses pagemap on Linux, QueryWorkingSetEx on Windows.
func (m *MemoryMapper) VirtToPhys(va uintptr) (uint64, error) {
	return m.virtToPhys(va)
}

// FindContiguousRegions scans the given buffer for physically contiguous runs.
// Returns regions sorted by size (largest first), as these are most useful
// for finding adjacent DRAM rows.
func (m *MemoryMapper) FindContiguousRegions(buf []byte, minPages int) ([]*PhysContiguousRegion, error) {
	if len(buf) == 0 {
		return nil, nil
	}

	base := uintptr(unsafe.Pointer(&buf[0]))
	numPages := len(buf) / int(m.pageSize)

	pages := make([]PhysPage, 0, numPages)
	for i := 0; i < numPages; i++ {
		va := base + uintptr(i)*m.pageSize
		pa, err := m.VirtToPhys(va)
		if err != nil {
			continue
		}
		if pa == 0 {
			continue
		}
		pages = append(pages, PhysPage{
			VirtAddr: va,
			PhysAddr: pa,
			PFN:      pa / uint64(m.pageSize),
		})
	}

	if len(pages) == 0 {
		return nil, fmt.Errorf("no physical addresses resolved (may need root/pagemap access)")
	}

	// Sort by physical address to find contiguous runs.
	sort.Slice(pages, func(i, j int) bool {
		return pages[i].PhysAddr < pages[j].PhysAddr
	})

	var regions []*PhysContiguousRegion
	start := 0
	for i := 1; i <= len(pages); i++ {
		isLast := i == len(pages)
		isContiguous := !isLast && pages[i].PFN == pages[i-1].PFN+1

		if !isContiguous {
			runLen := i - start
			if runLen >= minPages {
				region := &PhysContiguousRegion{
					Pages:     pages[start:i],
					StartPhys: pages[start].PhysAddr,
					EndPhys:   pages[i-1].PhysAddr + uint64(m.pageSize),
					Size:      uint64(runLen) * uint64(m.pageSize),
				}
				regions = append(regions, region)
			}
			start = i
		}
	}

	// Sort by size descending.
	sort.Slice(regions, func(i, j int) bool {
		return regions[i].Size > regions[j].Size
	})

	return regions, nil
}

// FindDRAMRows identifies which DRAM bank/row each physical address belongs to.
// The address mapping depends on the DRAM geometry configured by the memory controller.
// This uses the common XOR-based dual-channel address mapping for Intel systems.
func FindDRAMRows(pages []PhysPage) []DRAMRow {
	rows := make([]DRAMRow, len(pages))
	for i, p := range pages {
		bank, row := physAddrToDRAMRow(p.PhysAddr)
		rows[i] = DRAMRow{Bank: bank, Row: row, PhysEnd: p.PhysAddr + 4096}
	}
	return rows
}

// physAddrToDRAMRow applies Intel's common XOR address mapping.
// This is the "Ivy Bridge / Haswell" dual-rank, dual-channel mapping
// from "DRAMA: Exploiting DRAM Addressing for Cross-CPU Attacks".
//
//   row  = PA[33:18]
//   bank = PA[17:15] XOR PA[14:12]
//   channel (ignored here) = PA[6]
func physAddrToDRAMRow(pa uint64) (bank, row int) {
	row = int((pa >> 18) & 0xFFFF)
	bankBits := (pa >> 15) & 0x7
	xorBits := (pa >> 12) & 0x7
	bank = int(bankBits ^ xorBits)
	return bank, row
}

// AreInSameBank returns true if two physical addresses map to the same DRAM bank.
// Only addresses in the same bank can trigger rowhammer on each other.
func AreInSameBank(pa1, pa2 uint64) bool {
	b1, _ := physAddrToDRAMRow(pa1)
	b2, _ := physAddrToDRAMRow(pa2)
	return b1 == b2
}

// AreAdjacentRows returns true if two physical addresses are in adjacent DRAM rows.
// Adjacent rows are required for 2-sided hammering.
func AreAdjacentRows(pa1, pa2 uint64) bool {
	b1, r1 := physAddrToDRAMRow(pa1)
	b2, r2 := physAddrToDRAMRow(pa2)
	if b1 != b2 {
		return false
	}
	diff := r1 - r2
	if diff < 0 {
		diff = -diff
	}
	return diff == 1
}

// MeasureAccessTime measures the average DRAM access time for an address.
// Cache misses (DRAM accesses) take ~100-200ns.
// Cache hits take ~4-10ns.
// Used to verify cache flushing is working correctly.
func MeasureAccessTime(addr uintptr, samples int) (avgNs float64) {
	var total uint64
	for i := 0; i < samples; i++ {
		t1 := rdtscpFence()
		clflushLine(addr)
		_ = *(*byte)(unsafe.Pointer(addr)) // force DRAM access
		t2 := rdtscpFence()
		total += t2 - t1
	}
	// Approximate: modern CPUs run at ~3-4 GHz.
	// 1 cycle ≈ 0.33ns. Rough conversion.
	cycles := float64(total) / float64(samples)
	avgNs = cycles / 3.2 // assume 3.2 GHz
	return avgNs
}

// GetRAMSize returns the total physical RAM size in bytes.
// Used to bound scanning operations.
func GetRAMSize() uint64 {
	return getPhysicalMemorySize()
}

// LockPages attempts to lock the buffer pages into physical memory (no swap).
// This ensures our page-to-physical mapping doesn't change during hammering.
func LockPages(buf []byte) error {
	if len(buf) == 0 {
		return nil
	}
	return lockMemory(unsafe.Pointer(&buf[0]), uintptr(len(buf)))
}

// UnlockPages releases previously locked pages.
func UnlockPages(buf []byte) {
	if len(buf) == 0 {
		return
	}
	unlockMemory(unsafe.Pointer(&buf[0]), uintptr(len(buf)))
}

// ─── Platform hooks (defined in memory_map_windows.go) ───────────────────

// getPageSize returns the OS page size.
func getPageSize() int { return 4096 }

// openPagemap opens the pagemap handle on this platform.
func (m *MemoryMapper) openPagemap() error { return openPagemapPlatform(m) }

// closePagemap closes the pagemap handle.
func (m *MemoryMapper) closePagemap() { closePagemapPlatform(m) }

// virtToPhys resolves VA → PA on this platform.
func (m *MemoryMapper) virtToPhys(va uintptr) (uint64, error) { return virtToPhysPlatform(m, va) }

// allocLargeBuffer allocates a large buffer suitable for hammering.
func allocLargeBuffer(size int) ([]byte, error) { return allocLargeBufferPlatform(size) }

// freeLargeBuffer releases a hammering buffer.
func freeLargeBuffer(buf []byte) { freeLargeBufferPlatform(buf) }

// lockMemory pins pages in RAM.
func lockMemory(p unsafe.Pointer, n uintptr) error { return lockMemoryPlatform(p, n) }

// unlockMemory unpins pages from RAM.
func unlockMemory(p unsafe.Pointer, n uintptr) { unlockMemoryPlatform(p, n) }

// getPhysicalMemorySize returns total physical RAM.
func getPhysicalMemorySize() uint64 { return getPhysicalMemorySizePlatform() }

var _ = runtime.GOOS // suppress unused import
