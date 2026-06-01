// Copyright (C) 2026 Seif — see LICENSE

#include "textflag.h"

// func getCurrentRSP() uintptr
//
// Returns the value of RSP at the point of call so overwriteStackFrames
// can locate the return-address slots on the OS stack.
// NOSPLIT is required: we must not trigger a stack growth check, which
// would move the stack and invalidate any RSP we captured.
TEXT ·getCurrentRSP(SB),NOSPLIT,$0-8
    MOVQ SP, AX
    MOVQ AX, ret+0(FP)
    RET
