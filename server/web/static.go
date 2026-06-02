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
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

// ui holds the compiled React/Vite output from webui/ (built into server/web/ui/).
//
// The placeholder server/web/ui/index.html is committed to the repository so
// that `go:embed` always compiles even on a fresh clone without running `make ui`.
// Running `make ui` (cd webui && npm run build) overwrites ui/ with the full
// React application; rebuild the server binary afterwards to embed it.
//
// Build sequence:
//   make ui          → compile React into server/web/ui/
//   make server-only → embed ui/ into the server binary
//
//go:embed all:ui
var uiFS embed.FS

// spaFS is the sub-filesystem rooted at the embedded ui/ directory.
var spaFS fs.FS

func init() {
	var err error
	spaFS, err = fs.Sub(uiFS, "ui")
	if err != nil {
		panic("web: failed to open embedded ui/: " + err.Error())
	}
}

// isStaticAsset returns true for extensions that should be served verbatim.
func isStaticAsset(path string) bool {
	static := []string{
		".js", ".css", ".png", ".jpg", ".jpeg", ".gif",
		".svg", ".ico", ".woff", ".woff2", ".ttf", ".map",
		".webmanifest", ".json",
	}
	for _, ext := range static {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

// serveSPA serves the React single-page application from the embedded ui/ FS.
//
//   - Static assets (*.js, *.css, images …) → served directly.
//   - Everything else → ui/index.html so the React Router handles client-side routing.
func serveSPA(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	if path == "" {
		path = "index.html"
	}

	if isStaticAsset(path) {
		if _, err := spaFS.Open(path); err != nil {
			http.NotFound(w, r)
			return
		}
		http.FileServer(http.FS(spaFS)).ServeHTTP(w, r)
		return
	}

	// SPA fallback — serve index.html for all navigable routes.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data, err := fs.ReadFile(spaFS, "index.html")
	if err != nil {
		http.Error(w, "UI not built — run: make ui && make server-only", http.StatusServiceUnavailable)
		return
	}
	_, _ = w.Write(data)
}
