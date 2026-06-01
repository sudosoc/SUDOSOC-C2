// Copyright (C) 2026 Seif
// VMX assembly stubs — Intel VT-x instruction wrappers.
// Plan 9 / Go assembler syntax for amd64.

#include "textflag.h"

// ─── CPUID wrapper ────────────────────────────────────────────────────────
// func cpuid(leaf, subleaf uint32) (eax, ebx, ecx, edx uint32)
TEXT ·cpuid(SB),NOSPLIT,$0-24
    MOVL    leaf+0(FP), AX
    MOVL    subleaf+4(FP), CX
    CPUID
    MOVL    AX, eax+8(FP)
    MOVL    BX, ebx+12(FP)
    MOVL    CX, ecx+16(FP)
    MOVL    DX, edx+20(FP)
    RET

// ─── MSR read/write ───────────────────────────────────────────────────────
// func rdmsr(msr uint32) uint64
TEXT ·rdmsr(SB),NOSPLIT,$0-16
    MOVL    msr+0(FP), CX
    RDMSR
    SHLQ    $32, DX
    ORQ     DX, AX
    MOVQ    AX, ret+8(FP)
    RET

// func wrmsr(msr uint32, val uint64)
TEXT ·wrmsr(SB),NOSPLIT,$0-16
    MOVL    msr+0(FP), CX
    MOVQ    val+8(FP), AX
    MOVQ    AX, DX
    SHRQ    $32, DX
    WRMSR
    RET

// ─── CR register access ───────────────────────────────────────────────────
// func getCR0() uint64
TEXT ·getCR0(SB),NOSPLIT,$0-8
    MOVQ    CR0, AX
    MOVQ    AX, ret+0(FP)
    RET

// func getCR3() uint64
TEXT ·getCR3(SB),NOSPLIT,$0-8
    MOVQ    CR3, AX
    MOVQ    AX, ret+0(FP)
    RET

// func getCR4() uint64
TEXT ·getCR4(SB),NOSPLIT,$0-8
    MOVQ    CR4, AX
    MOVQ    AX, ret+0(FP)
    RET

// func setCR0(val uint64)
TEXT ·setCR0(SB),NOSPLIT,$0-8
    MOVQ    val+0(FP), AX
    MOVQ    AX, CR0
    RET

// func setCR4(val uint64)
TEXT ·setCR4(SB),NOSPLIT,$0-8
    MOVQ    val+0(FP), AX
    MOVQ    AX, CR4
    RET

// ─── Descriptor table registers ───────────────────────────────────────────
// func getGDTR() (base uint64, limit uint16)
TEXT ·getGDTR(SB),NOSPLIT,$16-10
    LEAQ    -16(SP), AX
    SGDT    (AX)
    MOVWQZX 0(AX), BX        // zero-extend 16-bit limit
    MOVQ    2(AX), CX        // 64-bit base
    MOVQ    CX, base+0(FP)
    MOVW    BX, limit+8(FP)
    RET

// func getIDTR() (base uint64, limit uint16)
TEXT ·getIDTR(SB),NOSPLIT,$16-10
    LEAQ    -16(SP), AX
    SIDT    (AX)
    MOVWQZX 0(AX), BX
    MOVQ    2(AX), CX
    MOVQ    CX, base+0(FP)
    MOVW    BX, limit+8(FP)
    RET

// func getCS() uint16
TEXT ·getCS(SB),NOSPLIT,$0-2
    MOVW    CS, AX
    MOVW    AX, ret+0(FP)
    RET

// func getSS() uint16
TEXT ·getSS(SB),NOSPLIT,$0-2
    MOVW    SS, AX
    MOVW    AX, ret+0(FP)
    RET

// func getDS() uint16
TEXT ·getDS(SB),NOSPLIT,$0-2
    MOVW    DS, AX
    MOVW    AX, ret+0(FP)
    RET

// func getES() uint16
TEXT ·getES(SB),NOSPLIT,$0-2
    MOVW    ES, AX
    MOVW    AX, ret+0(FP)
    RET

// func getFS() uint16
TEXT ·getFS(SB),NOSPLIT,$0-2
    MOVW    FS, AX
    MOVW    AX, ret+0(FP)
    RET

// func getGS() uint16
TEXT ·getGS(SB),NOSPLIT,$0-2
    MOVW    GS, AX
    MOVW    AX, ret+0(FP)
    RET

// func getTR() uint16
// STR r16 encodes as: 0F 00 /1, ModRM(AX) = C8
TEXT ·getTR(SB),NOSPLIT,$0-2
    BYTE    $0x0F; BYTE $0x00; BYTE $0xC8   // STR AX
    MOVW    AX, ret+0(FP)
    RET

// func getLDTR() uint16
// SLDT r16 encodes as: 0F 00 /0, ModRM(AX) = C0
TEXT ·getLDTR(SB),NOSPLIT,$0-2
    BYTE    $0x0F; BYTE $0x00; BYTE $0xC0   // SLDT AX
    MOVW    AX, ret+0(FP)
    RET

// func getRFLAGS() uint64
TEXT ·getRFLAGS(SB),NOSPLIT,$0-8
    PUSHFQ
    POPQ    AX
    MOVQ    AX, ret+0(FP)
    RET

// ─── VMX instructions ─────────────────────────────────────────────────────
// func vmxon(phys uint64) uint8
// Returns 0 on success (CF=0), non-zero on failure.
TEXT ·vmxon(SB),NOSPLIT,$8-9
    MOVQ    physAddr+0(FP), AX
    MOVQ    AX, -8(SP)
    BYTE    $0xF3; BYTE $0x0F; BYTE $0xC7; BYTE $0x74; BYTE $0x24; BYTE $0xF8
    // VMXON -8(SP)
    SETCS   AL              // CF=1 → AL=1 (failure)
    MOVB    AL, ret+8(FP)
    RET

// func vmxoff()
TEXT ·vmxoff(SB),NOSPLIT,$0-0
    BYTE    $0x0F; BYTE $0x01; BYTE $0xC4   // VMXOFF
    RET

// func vmclear(phys uint64) uint8
TEXT ·vmclear(SB),NOSPLIT,$8-9
    MOVQ    physAddr+0(FP), AX
    MOVQ    AX, -8(SP)
    BYTE    $0x66; BYTE $0x0F; BYTE $0xC7; BYTE $0x74; BYTE $0x24; BYTE $0xF8
    // VMCLEAR -8(SP)
    SETCS   AL
    MOVB    AL, ret+8(FP)
    RET

// func vmptrld(phys uint64) uint8
TEXT ·vmptrld(SB),NOSPLIT,$8-9
    MOVQ    physAddr+0(FP), AX
    MOVQ    AX, -8(SP)
    BYTE    $0x0F; BYTE $0xC7; BYTE $0x74; BYTE $0x24; BYTE $0xF8
    // VMPTRLD -8(SP)
    SETCS   AL
    MOVB    AL, ret+8(FP)
    RET

// func vmwrite(field, value uint64) uint8
TEXT ·vmwrite(SB),NOSPLIT,$0-17
    MOVQ    field+0(FP), CX
    MOVQ    value+8(FP), DX
    BYTE    $0x0F; BYTE $0x79; BYTE $0xD1   // VMWRITE RCX, RDX
    SETCS   AL
    MOVB    AL, ret+16(FP)
    RET

// func vmread(field uint64) (uint64, uint8)
TEXT ·vmread(SB),NOSPLIT,$0-17
    MOVQ    field+0(FP), CX
    BYTE    $0x0F; BYTE $0x78; BYTE $0xC8   // VMREAD RAX, RCX
    MOVQ    AX, ret+8(FP)
    SETCS   BL
    MOVB    BL, ret1+16(FP)
    RET

// func vmlaunch() uint8
TEXT ·vmlaunch(SB),NOSPLIT,$0-1
    BYTE    $0x0F; BYTE $0x01; BYTE $0xC2   // VMLAUNCH
    // If we reach here, VMLAUNCH failed.
    MOVB    $1, ret+0(FP)
    RET

// func vmresume() uint8
TEXT ·vmresume(SB),NOSPLIT,$0-1
    BYTE    $0x0F; BYTE $0x01; BYTE $0xC3   // VMRESUME
    MOVB    $1, ret+0(FP)
    RET

// func invept(invType uint64, eptp uint64)
TEXT ·invept(SB),NOSPLIT,$16-16
    MOVQ    invType+0(FP), AX
    MOVQ    eptp+8(FP), BX
    MOVQ    BX, -16(SP)
    MOVQ    $0, -8(SP)
    BYTE    $0x66; BYTE $0x0F; BYTE $0x38; BYTE $0x80; BYTE $0x44; BYTE $0x24; BYTE $0xF0
    // INVEPT RAX, -16(SP)
    RET

// func invvpid(invType uint64, vpid uint16, gva uint64)
TEXT ·invvpid(SB),NOSPLIT,$16-24
    MOVQ    invType+0(FP), AX
    MOVWQZX vpid+8(FP), BX
    MOVQ    gva+16(FP), CX
    MOVQ    BX, -16(SP)
    MOVQ    $0, -12(SP)
    MOVQ    CX, -8(SP)
    BYTE    $0x66; BYTE $0x0F; BYTE $0x38; BYTE $0x81; BYTE $0x44; BYTE $0x24; BYTE $0xF0
    // INVVPID RAX, -16(SP)
    RET

// ─── VM-Exit handler trampoline ───────────────────────────────────────────
// func vmExitTrampoline()
// Called by the CPU on every VM exit. Saves all GPRs and dispatches.
TEXT ·vmExitTrampoline(SB),NOSPLIT,$0-0
    // Save all GPRs on the host stack.
    PUSHQ   AX
    PUSHQ   BX
    PUSHQ   CX
    PUSHQ   DX
    PUSHQ   SI
    PUSHQ   DI
    PUSHQ   BP
    PUSHQ   R8
    PUSHQ   R9
    PUSHQ   R10
    PUSHQ   R11
    PUSHQ   R12
    PUSHQ   R13
    PUSHQ   R14
    PUSHQ   R15

    // Pass SP (pointing to saved register frame) as the argument.
    MOVQ    SP, DI          // arg0 = *GuestRegisters
    CALL    ·handleVmExit(SB)

    // Restore GPRs.
    POPQ    R15
    POPQ    R14
    POPQ    R13
    POPQ    R12
    POPQ    R11
    POPQ    R10
    POPQ    R9
    POPQ    R8
    POPQ    BP
    POPQ    DI
    POPQ    SI
    POPQ    DX
    POPQ    CX
    POPQ    BX
    POPQ    AX

    // Return to guest via VMRESUME.
    BYTE    $0x0F; BYTE $0x01; BYTE $0xC3   // VMRESUME
    // If VMRESUME fails, loop.
    JMP     ·vmExitTrampoline(SB)
