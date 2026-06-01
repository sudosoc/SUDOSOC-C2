//go:build windows

package rowhammer

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	modKernel32           = syscall.NewLazyDLL("kernel32.dll")
	procVirtualAlloc      = modKernel32.NewProc("VirtualAlloc")
	procVirtualFree       = modKernel32.NewProc("VirtualFree")
	procVirtualLock       = modKernel32.NewProc("VirtualLock")
	procVirtualUnlock     = modKernel32.NewProc("VirtualUnlock")
	procQueryWorkingSetEx = syscall.NewLazyDLL("psapi.dll").NewProc("QueryWorkingSetEx")

	modNTDLL             = syscall.NewLazyDLL("ntdll.dll")
	procNtQuerySystemInfo = modNTDLL.NewProc("NtQuerySystemInformation")
)

const (
	MEM_COMMIT             = 0x1000
	MEM_RESERVE            = 0x2000
	MEM_RELEASE            = 0x8000
	PAGE_READWRITE         = 0x04
	SystemBasicInformation = 0x00
)

// PSAPI_WORKING_SET_EX_INFORMATION — used to resolve VA→PA on Windows.
type psapiWorkingSetExInformation struct {
	VirtualAddress uintptr
	VirtualAttributes uint64
}

// openPagemapPlatform — Windows uses QueryWorkingSetEx, no file to open.
func openPagemapPlatform(m *MemoryMapper) error {
	return nil
}

func closePagemapPlatform(m *MemoryMapper) {}

// virtToPhysPlatform uses QueryWorkingSetEx to get the physical page frame.
func virtToPhysPlatform(m *MemoryMapper, va uintptr) (uint64, error) {
	info := psapiWorkingSetExInformation{VirtualAddress: va & m.pageMask}
	r1, _, err := procQueryWorkingSetEx.Call(
		^uintptr(0), // current process
		uintptr(unsafe.Pointer(&info)),
		unsafe.Sizeof(info),
	)
	if r1 == 0 {
		return 0, fmt.Errorf("QueryWorkingSetEx: %w", err)
	}

	// VirtualAttributes bits:
	//   [0]    Valid
	//   [5:1]  Win32Protection
	//   [12:6] Shared / ShareCount
	//   [58:13] Page Frame Number (PFN)
	valid := info.VirtualAttributes & 1
	if valid == 0 {
		return 0, nil // page not in working set
	}
	pfn := (info.VirtualAttributes >> 1) & 0x000FFFFFFFFFFFFF
	pa := pfn*uint64(m.pageSize) | uint64(va&^m.pageMask)
	return pa, nil
}

// allocLargeBufferPlatform allocates a large buffer with VirtualAlloc.
// Using VirtualAlloc (not Go's allocator) gives us better page alignment
// and control over memory placement.
func allocLargeBufferPlatform(size int) ([]byte, error) {
	p, _, err := procVirtualAlloc.Call(
		0,
		uintptr(size),
		MEM_COMMIT|MEM_RESERVE,
		PAGE_READWRITE,
	)
	if p == 0 {
		return nil, fmt.Errorf("VirtualAlloc: %w", err)
	}
	// Build a Go slice header over the raw allocation.
	buf := unsafe.Slice((*byte)(unsafe.Pointer(p)), size)
	return buf, nil
}

func freeLargeBufferPlatform(buf []byte) {
	if len(buf) == 0 {
		return
	}
	procVirtualFree.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		0,
		MEM_RELEASE,
	)
}

func lockMemoryPlatform(p unsafe.Pointer, n uintptr) error {
	r1, _, err := procVirtualLock.Call(uintptr(p), n)
	if r1 == 0 {
		return fmt.Errorf("VirtualLock: %w", err)
	}
	return nil
}

func unlockMemoryPlatform(p unsafe.Pointer, n uintptr) {
	procVirtualUnlock.Call(uintptr(p), n)
}

// SYSTEM_BASIC_INFORMATION (NtQuerySystemInformation class 0).
type systemBasicInformation struct {
	Reserved                     uint32
	TimerResolution              uint32
	PageSize                     uint32
	NumberOfPhysicalPages        uint32
	LowestPhysicalPageNumber     uint32
	HighestPhysicalPageNumber    uint32
	AllocationGranularity        uint32
	MinimumUserModeAddress       uintptr
	MaximumUserModeAddress       uintptr
	ActiveProcessorsAffinityMask uintptr
	NumberOfProcessors           byte
}

func getPhysicalMemorySizePlatform() uint64 {
	var info systemBasicInformation
	procNtQuerySystemInfo.Call(
		SystemBasicInformation,
		uintptr(unsafe.Pointer(&info)),
		unsafe.Sizeof(info),
		0,
	)
	return uint64(info.NumberOfPhysicalPages) * uint64(info.PageSize)
}
