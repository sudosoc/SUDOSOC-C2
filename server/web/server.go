package web

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

import (
	"fmt"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/gorilla/mux"
)

// buildRouter wires up all HTTP and WebSocket routes.
// Called by the WebUIManager on every Start().
func buildRouter() *mux.Router {
	r := mux.NewRouter()

	// ── REST API ──────────────────────────────────────────────────────────
	api := r.PathPrefix("/api").Subrouter()
	api.Use(recoveryMiddleware)
	api.Use(corsMiddleware)
	api.Use(jsonMiddleware)
	api.Use(requestTimeoutMiddleware)

	// ── Read-only data endpoints ──────────────────────────────────────
	api.HandleFunc("/stats",     handleStats).Methods(http.MethodGet)
	api.HandleFunc("/sessions",  handleSessions).Methods(http.MethodGet)
	api.HandleFunc("/beacons",   handleBeacons).Methods(http.MethodGet)
	api.HandleFunc("/loot",      handleLoot).Methods(http.MethodGet)
	api.HandleFunc("/operators", handleOperators).Methods(http.MethodGet)

	// ── Listener control (start / stop — includes WireGuard) ─────────
	api.HandleFunc("/listeners",      handleListeners).Methods(http.MethodGet)
	api.HandleFunc("/listeners",      handleListenerStart).Methods(http.MethodPost)
	api.HandleFunc("/listeners/{id}", handleListenerStop).Methods(http.MethodDelete)

	// ── Session control ────────────────────────────────────────────────
	api.HandleFunc("/sessions/{id}/kill",       handleSessionKill).Methods(http.MethodDelete)
	api.HandleFunc("/sessions/{id}/execute",    handleSessionExecute).Methods(http.MethodPost)
	api.HandleFunc("/sessions/{id}/screenshot", handleScreenshot).Methods(http.MethodGet)
	api.HandleFunc("/sessions/{id}/ps",         handlePS).Methods(http.MethodGet)
	api.HandleFunc("/sessions/{id}/ls",         handleLS).Methods(http.MethodGet)
	api.HandleFunc("/sessions/{id}/download",   handleDownload).Methods(http.MethodGet)
	api.HandleFunc("/sessions/{id}/upload",     handleUpload).Methods(http.MethodPost)
	api.HandleFunc("/sessions/{id}/ps/{pid}",   handleTerminateProcess).Methods(http.MethodDelete)

	// ── Beacon control ────────────────────────────────────────────────
	api.HandleFunc("/beacons/{id}/tasks",            handleBeaconTasks).Methods(http.MethodGet)
	api.HandleFunc("/beacons/{id}/tasks/{taskID}",   handleBeaconTaskContent).Methods(http.MethodGet)
	api.HandleFunc("/beacons/{id}/execute",          handleBeaconExecute).Methods(http.MethodPost)

	// ── Operator management ───────────────────────────────────────────
	api.HandleFunc("/operators/new", handleOperatorNew).Methods(http.MethodPost)

	// ── Generate ──────────────────────────────────────────────────────
	api.HandleFunc("/generate/options", handleGenerateOptions).Methods(http.MethodGet)
	api.HandleFunc("/generate",         handleGenerate).Methods(http.MethodPost)

	// ── WebSocket ─────────────────────────────────────────────────────────
	r.HandleFunc("/ws/events", handleWSEvents)
	r.HandleFunc("/ws/terminal/{sessionID}", handleWSTerminal)

	// ── Static SPA (React) ────────────────────────────────────────────────
	// The embedded FS is served from static.go; unknown routes fall back to
	// index.html so the React router handles deep links.
	r.PathPrefix("/").Handler(recoveryMiddleware(http.HandlerFunc(serveSPA)))

	return r
}

// corsMiddleware adds permissive CORS headers for the local UI during dev.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// jsonMiddleware sets Content-Type: application/json for all API responses.
func jsonMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		next.ServeHTTP(w, r)
	})
}

// recoveryMiddleware catches panics in HTTP handlers and returns a 500 instead
// of resetting the connection (which shows as "Connection reset by peer" in curl).
func recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				fmt.Printf("[web] panic in handler %s: %v\n%s\n", r.URL.Path, rec, debug.Stack())
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = fmt.Fprintf(w, `{"error":"internal server error","detail":"%v"}`, rec)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// requestTimeoutMiddleware wraps API handlers with a 30-second server-side timeout.
func requestTimeoutMiddleware(next http.Handler) http.Handler {
	return http.TimeoutHandler(next, 30*time.Second, `{"error":"request timeout"}`)
}

// jsonError writes a standard JSON error response.
func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write([]byte(`{"error":"` + msg + `"}`))
}
