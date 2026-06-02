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
	"context"
	"fmt"
	"net/http"
	"sync"
)

// WebUIManager manages the lifecycle of the Web UI HTTP server.
// It is safe for concurrent use — Start/Stop/Status can be called
// from the terminal, TUI, or a signal handler simultaneously.
type WebUIManager struct {
	mu     sync.Mutex
	server *http.Server
	port   uint16
	active bool
}

// Manager is the process-wide singleton.
var Manager = &WebUIManager{}

// Start launches the Web UI on the given port.
// Returns an error if the UI is already running or the port is unavailable.
func (m *WebUIManager) Start(port uint16) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.active {
		return fmt.Errorf("web UI already running on port %d", m.port)
	}

	router := buildRouter()
	m.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: router,
	}
	m.port = port
	m.active = true

	go func() {
		if err := m.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			m.mu.Lock()
			m.active = false
			m.mu.Unlock()
		}
	}()

	return nil
}

// Stop shuts down the Web UI gracefully.
func (m *WebUIManager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.active {
		return fmt.Errorf("web UI is not running")
	}

	err := m.server.Shutdown(context.Background())
	m.active = false
	m.server = nil
	return err
}

// Toggle starts the UI if stopped, stops it if running.
// Used by the SIGUSR1 signal handler.
func (m *WebUIManager) Toggle(port uint16) {
	m.mu.Lock()
	running := m.active
	currentPort := m.port
	m.mu.Unlock()

	if running {
		_ = m.Stop()
		fmt.Printf("\n[sudosoc] Web UI stopped (was on :%d)\n", currentPort)
	} else {
		if err := m.Start(port); err != nil {
			fmt.Printf("\n[sudosoc] Failed to start web UI: %v\n", err)
		} else {
			fmt.Printf("\n[sudosoc] Web UI started → http://localhost:%d\n", port)
		}
	}
}

// Status returns whether the web UI is active and on which port.
func (m *WebUIManager) Status() (active bool, port uint16) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.active, m.port
}
