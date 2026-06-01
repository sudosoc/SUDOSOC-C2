// Copyright (C) 2026 Seif — see LICENSE

#include "textflag.h"

// func IndirectSyscall(ssn uint32, gadget uintptr, args ...uintptr) uintptr
//
// Sets EAX = ssn, then JMPs to the ntdll syscall;ret gadget.
// The CPU sees the syscall originating from inside ntdll — kernel stack
// walkers find a legitimate ntdll return address.
//
// Calling convention (Go internal ABI on amd64):
//   AX  = ssn   (first integer arg)
//   BX  = gadget
//   CX  = args.ptr
//   DI  = args.len
//
// Windows syscall ABI (inside the gadget):
//   EAX = SSN
//   R10 = first argument (RCX)
//   RDX = second argument
//   R8  = third argument
//   R9  = fourth argument
//   stack = fifth+ arguments
//
// We translate the Go variadic slice into the Windows register convention
// before jumping to the gadget.

TEXT ·IndirectSyscall(SB),NOSPLIT,$0-48
    // Load ssn, gadget, slice pointer and length from Go ABI stack frame.
    MOVL    ssn+0(FP),  R11          // R11 = SSN (uint32)
    MOVQ    gadget+8(FP), R10        // R10 = gadget address (temporary)
    MOVQ    args_base+16(FP), SI     // SI  = &args[0]
    MOVQ    args_len+24(FP), DI      // DI  = len(args)

    // Move SSN into EAX (Windows syscall convention).
    MOVL    R11, AX

    // Distribute arguments into Windows registers.
    // arg[0] → R10 (mirrors RCX for syscall path), arg[0] → RCX
    // arg[1] → RDX
    // arg[2] → R8
    // arg[3] → R9
    // arg[4..] → stack (pushed in reverse)

    XORQ    CX, CX
    XORQ    DX, DX
    XORQ    R8, R8
    XORQ    R9, R9

    CMPQ    DI, $0
    JE      do_call

    MOVQ    0(SI), CX               // arg[0] → RCX
    MOVQ    0(SI), R10              // arg[0] → R10 (syscall ABI requires both)
    CMPQ    DI, $1
    JE      do_call

    MOVQ    8(SI), DX               // arg[1] → RDX
    CMPQ    DI, $2
    JE      do_call

    MOVQ    16(SI), R8              // arg[2] → R8
    CMPQ    DI, $3
    JE      do_call

    MOVQ    24(SI), R9              // arg[3] → R9
    CMPQ    DI, $4
    JLE     do_call

    // Push remaining args[4..] onto the stack in reverse order.
    // Windows x64 ABI: first 4 in registers, rest on stack.
    // We need 32-byte shadow space + 8*extra bytes.
    MOVQ    DI, BX
    SUBQ    $4, BX                  // extra_count = len - 4
    SHLQ    $3, BX                  // extra_bytes = extra_count * 8
    SUBQ    BX, SP                  // grow stack
    MOVQ    DI, BX
    SUBQ    $4, BX
push_loop:
    CMPQ    BX, $0
    JLE     do_call
    MOVQ    (SI)(BX*8), R11
    MOVQ    R11, (SP)(BX*8)
    SUBQ    $1, BX
    JMP     push_loop

do_call:
    // Shadow space (32 bytes) required by Windows x64 ABI.
    SUBQ    $32, SP

    // gadget is now in R10 (we clobbered it for arg[0] above — reload).
    MOVQ    gadget+8(FP), R11
    // JMP to the gadget (syscall; ret inside ntdll).
    JMP     R11
