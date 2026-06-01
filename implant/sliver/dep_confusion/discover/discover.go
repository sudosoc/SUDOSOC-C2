package discover

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	Dependency Confusion — Phase 1: Internal Package Discovery.

	To execute a dependency confusion attack we first need to know the names
	of the target's internal (private) packages. These names leak in many ways:

	  1. Public GitHub repositories:
	     - requirements.txt / Pipfile / pyproject.toml → Python
	     - package.json / package-lock.json / yarn.lock → npm
	     - *.csproj / packages.config / NuGet.Config → NuGet
	     - go.mod (private module paths like github.com/company/internal-pkg)
	     - Gemfile / Gemfile.lock → Ruby
	     - Cargo.toml → Rust
	     - pom.xml / build.gradle → Java/Maven

	  2. Job postings (LinkedIn, GitHub Jobs):
	     "experience with our internal tool company-data-pipeline"

	  3. Leaked .npmrc / pip.conf / NuGet.config files in public repos:
	     These explicitly name private registries and package prefixes.

	  4. npm audit output in CI logs.

	  5. Error messages in public issue trackers.

	This module automates discovery by:
	  - Cloning/searching GitHub repos of the target org
	  - Parsing all dependency manifests
	  - Identifying packages that:
	    a. Are NOT available on public registries (PyPI/npm/NuGet/etc.)
	    b. Match naming patterns common for internal packages
	       (company-prefix, @company/scope, Company.Internal.*)
*/

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// DiscoveredPackage represents an internal package name found in the target org.
type DiscoveredPackage struct {
	Name       string
	Ecosystem  string // "pypi", "npm", "nuget", "rubygems", "go"
	FoundIn    string // URL of the manifest file where it was found
	Version    string // version referenced internally (we'll publish higher)
	IsPublic   bool   // false = not on public registry = vuln to confusion
	Confidence string // "high", "medium", "low"
}

// DiscoveryConfig holds parameters for the discovery phase.
type DiscoveryConfig struct {
	// OrgName is the GitHub organization to scan (e.g. "company-name").
	OrgName string
	// GitHubToken is a GitHub PAT for API access (public repos only = no token needed).
	GitHubToken string
	// Ecosystems lists which package managers to check.
	Ecosystems []string // ["pypi", "npm", "nuget", "rubygems", "go"]
	// OrgPrefixes are known internal package prefixes to look for.
	OrgPrefixes []string // e.g. ["mycompany-", "@mycompany/", "MyCompany."]
	// MaxRepos limits how many repos to scan (0 = no limit).
	MaxRepos int
}

// Discover scans the target GitHub org and returns all internal package names.
func Discover(ctx context.Context, cfg *DiscoveryConfig) ([]*DiscoveredPackage, error) {
	if len(cfg.Ecosystems) == 0 {
		cfg.Ecosystems = []string{"pypi", "npm", "nuget", "go"}
	}

	// Step 1: List all public repos in the org.
	repos, err := listOrgRepos(ctx, cfg.OrgName, cfg.GitHubToken, cfg.MaxRepos)
	if err != nil {
		return nil, fmt.Errorf("list repos for %s: %w", cfg.OrgName, err)
	}

	// Step 2: For each repo, find and parse dependency manifests.
	var allPkgs []*DiscoveredPackage
	for _, repo := range repos {
		pkgs := scanRepo(ctx, cfg, repo)
		allPkgs = append(allPkgs, pkgs...)
	}

	// Step 3: Deduplicate.
	allPkgs = deduplicate(allPkgs)

	// Step 4: Check which packages exist on public registries.
	for _, pkg := range allPkgs {
		pkg.IsPublic = checkPublicRegistry(ctx, pkg.Ecosystem, pkg.Name)
	}

	// Step 5: Filter to only non-public packages (the vulnerable ones).
	var vulnerable []*DiscoveredPackage
	for _, pkg := range allPkgs {
		if !pkg.IsPublic {
			pkg.Confidence = assessConfidence(pkg, cfg.OrgPrefixes)
			vulnerable = append(vulnerable, pkg)
		}
	}
	return vulnerable, nil
}

// ─── GitHub API ───────────────────────────────────────────────────────────

type ghRepo struct {
	Name          string `json:"name"`
	FullName      string `json:"full_name"`
	DefaultBranch string `json:"default_branch"`
}

func listOrgRepos(ctx context.Context, org, token string, maxRepos int) ([]ghRepo, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	var repos []ghRepo
	page := 1
	for {
		url := fmt.Sprintf("https://api.github.com/orgs/%s/repos?type=public&per_page=100&page=%d", org, page)
		req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
		if token != "" {
			req.Header.Set("Authorization", "token "+token)
		}
		req.Header.Set("Accept", "application/vnd.github.v3+json")
		req.Header.Set("User-Agent", "Mozilla/5.0") // blend in

		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode == 404 {
			return nil, fmt.Errorf("org %s not found", org)
		}
		var batch []ghRepo
		json.NewDecoder(resp.Body).Decode(&batch)
		repos = append(repos, batch...)

		if len(batch) < 100 || (maxRepos > 0 && len(repos) >= maxRepos) {
			break
		}
		page++
	}
	if maxRepos > 0 && len(repos) > maxRepos {
		repos = repos[:maxRepos]
	}
	return repos, nil
}

// scanRepo fetches known manifest files from a repo and parses dependencies.
func scanRepo(ctx context.Context, cfg *DiscoveryConfig, repo ghRepo) []*DiscoveredPackage {
	var pkgs []*DiscoveredPackage

	// Manifest files to look for, by ecosystem.
	manifests := map[string][]string{
		"pypi":     {"requirements.txt", "Pipfile", "pyproject.toml", "setup.py"},
		"npm":      {"package.json", "package-lock.json"},
		"nuget":    {"packages.config", "*.csproj", "NuGet.Config"},
		"go":       {"go.mod"},
		"rubygems": {"Gemfile"},
	}

	for _, eco := range cfg.Ecosystems {
		files := manifests[eco]
		for _, fname := range files {
			// Try to fetch via GitHub raw content API.
			url := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s",
				repo.FullName, repo.DefaultBranch, fname)
			content := fetchRaw(ctx, url, cfg.GitHubToken)
			if content == "" {
				continue
			}
			parsed := parseManifest(eco, content, url)
			pkgs = append(pkgs, parsed...)
		}
	}
	return pkgs
}

func fetchRaw(ctx context.Context, url, token string) string {
	client := &http.Client{Timeout: 10 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	if token != "" {
		req.Header.Set("Authorization", "token "+token)
	}
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	return string(b)
}

// ─── Manifest parsers ─────────────────────────────────────────────────────

func parseManifest(ecosystem, content, sourceURL string) []*DiscoveredPackage {
	switch ecosystem {
	case "pypi":
		return parsePythonManifest(content, sourceURL)
	case "npm":
		return parseNPMManifest(content, sourceURL)
	case "nuget":
		return parseNuGetManifest(content, sourceURL)
	case "go":
		return parseGoMod(content, sourceURL)
	case "rubygems":
		return parseGemfile(content, sourceURL)
	}
	return nil
}

func parsePythonManifest(content, src string) []*DiscoveredPackage {
	var pkgs []*DiscoveredPackage
	// requirements.txt / Pipfile: one package per line.
	re := regexp.MustCompile(`(?m)^([a-zA-Z0-9_\-\.]+)\s*[>=<!~^]?=?\s*([\d\.\*]+)?`)
	for _, m := range re.FindAllStringSubmatch(content, -1) {
		name := strings.TrimSpace(m[1])
		if name == "" || strings.HasPrefix(name, "#") {
			continue
		}
		ver := ""
		if len(m) > 2 {
			ver = m[2]
		}
		pkgs = append(pkgs, &DiscoveredPackage{
			Name: name, Ecosystem: "pypi", FoundIn: src, Version: ver,
		})
	}
	return pkgs
}

func parseNPMManifest(content, src string) []*DiscoveredPackage {
	var pkgs []*DiscoveredPackage
	var manifest struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal([]byte(content), &manifest); err != nil {
		return nil
	}
	for name, ver := range manifest.Dependencies {
		pkgs = append(pkgs, &DiscoveredPackage{
			Name: name, Ecosystem: "npm", FoundIn: src, Version: ver,
		})
	}
	for name, ver := range manifest.DevDependencies {
		pkgs = append(pkgs, &DiscoveredPackage{
			Name: name, Ecosystem: "npm", FoundIn: src, Version: ver,
		})
	}
	return pkgs
}

func parseNuGetManifest(content, src string) []*DiscoveredPackage {
	var pkgs []*DiscoveredPackage
	// Match <PackageReference Include="Name" Version="X.Y.Z" />
	re := regexp.MustCompile(`(?i)Include="([^"]+)"(?:\s+Version="([^"]+)")?`)
	for _, m := range re.FindAllStringSubmatch(content, -1) {
		ver := ""
		if len(m) > 2 {
			ver = m[2]
		}
		pkgs = append(pkgs, &DiscoveredPackage{
			Name: m[1], Ecosystem: "nuget", FoundIn: src, Version: ver,
		})
	}
	return pkgs
}

func parseGoMod(content, src string) []*DiscoveredPackage {
	var pkgs []*DiscoveredPackage
	// Match: require ( ... ) or require module/path vX.Y.Z
	re := regexp.MustCompile(`(?m)^\s+([\w\.\-/]+)\s+(v[\d\.\-a-z]+)`)
	for _, m := range re.FindAllStringSubmatch(content, -1) {
		pkgs = append(pkgs, &DiscoveredPackage{
			Name: m[1], Ecosystem: "go", FoundIn: src, Version: m[2],
		})
	}
	return pkgs
}

func parseGemfile(content, src string) []*DiscoveredPackage {
	var pkgs []*DiscoveredPackage
	re := regexp.MustCompile(`gem\s+'([^']+)'(?:,\s*'([^']+)')?`)
	for _, m := range re.FindAllStringSubmatch(content, -1) {
		ver := ""
		if len(m) > 2 {
			ver = m[2]
		}
		pkgs = append(pkgs, &DiscoveredPackage{
			Name: m[1], Ecosystem: "rubygems", FoundIn: src, Version: ver,
		})
	}
	return pkgs
}

// ─── Public registry checks ───────────────────────────────────────────────

// checkPublicRegistry returns true if the package exists on the public registry.
func checkPublicRegistry(ctx context.Context, ecosystem, name string) bool {
	client := &http.Client{Timeout: 5 * time.Second}
	var url string
	switch ecosystem {
	case "pypi":
		url = "https://pypi.org/pypi/" + name + "/json"
	case "npm":
		url = "https://registry.npmjs.org/" + name
	case "nuget":
		url = "https://api.nuget.org/v3/registration5-gz-semver2/" + strings.ToLower(name) + "/index.json"
	case "rubygems":
		url = "https://rubygems.org/api/v1/gems/" + name + ".json"
	case "go":
		url = "https://proxy.golang.org/" + name + "/@latest"
	default:
		return false
	}
	req, _ := http.NewRequestWithContext(ctx, "HEAD", url, nil)
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

// assessConfidence rates how likely a package name is internal vs. just obscure.
func assessConfidence(pkg *DiscoveredPackage, orgPrefixes []string) string {
	name := strings.ToLower(pkg.Name)
	for _, prefix := range orgPrefixes {
		if strings.HasPrefix(name, strings.ToLower(prefix)) {
			return "high"
		}
	}
	// Heuristics for internal-looking names.
	internalHints := []string{"internal", "private", "core", "common", "shared", "lib", "util", "sdk"}
	for _, hint := range internalHints {
		if strings.Contains(name, hint) {
			return "medium"
		}
	}
	return "low"
}

func deduplicate(pkgs []*DiscoveredPackage) []*DiscoveredPackage {
	seen := map[string]bool{}
	var result []*DiscoveredPackage
	for _, p := range pkgs {
		key := p.Ecosystem + ":" + p.Name
		if !seen[key] {
			seen[key] = true
			result = append(result, p)
		}
	}
	return result
}
