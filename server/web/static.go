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

// dist holds the compiled React/Vite output from webui/dist/.
// Build it with:  cd webui && npm run build
// The Makefile target `make ui` handles this automatically.
//
//go:embed all:dist
var dist embed.FS

// distFS is the sub-filesystem rooted at the embedded dist/ directory.
var distFS fs.FS

func init() {
	var err error
	distFS, err = fs.Sub(dist, "dist")
	if err != nil {
		panic("web: failed to open embedded dist/: " + err.Error())
	}
}

// isStaticAsset returns true for file extensions that should be served
// verbatim without falling back to index.html.
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

// serveSPA serves the React single-page application.
//
//   - Static assets (*.js, *.css, images …) → served directly from dist/.
//   - Everything else → dist/index.html, so the React Router handles the route.
func serveSPA(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	if path == "" {
		path = "index.html"
	}

	if isStaticAsset(path) {
		// Try to open the exact file; 404 if missing.
		if _, err := distFS.Open(path); err != nil {
			http.NotFound(w, r)
			return
		}
		http.FileServer(http.FS(distFS)).ServeHTTP(w, r)
		return
	}

	// SPA fallback — serve index.html for all navigable routes.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data, err := fs.ReadFile(distFS, "index.html")
	if err != nil {
		http.Error(w, "UI not built — run: cd webui && npm run build", http.StatusServiceUnavailable)
		return
	}
	_, _ = w.Write(data)
}
