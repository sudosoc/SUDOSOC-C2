package scanner

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	Registry Availability Scanner.

	For each generated typo variant we must check whether the name is
	already registered on the public registry. Registering a name that
	already exists will fail (most registries reject duplicate names).

	We also check:
	  - Whether a name is on any BLOCKLIST (e.g., PyPI's typosquatting
	    protection blocks known typos of top-100 packages since 2022).
	  - Whether the name is SIMILAR to the operator's own packages
	    (to avoid accidentally squatting your own packages).
	  - RATE LIMITING: scan at ≤ 10 req/s to avoid blocking.

	Registry APIs:
	  PyPI:     GET https://pypi.org/pypi/<name>/json → 200 = exists, 404 = free
	  npm:      GET https://registry.npmjs.org/<name> → same
	  NuGet:    GET https://api.nuget.org/v3/registration5-gz-semver2/<name>/index.json
	  RubyGems: GET https://rubygems.org/api/v1/gems/<name>.json

	Stealth scanning:
	  - Use rotating User-Agent strings to blend with organic traffic.
	  - Add random delays (50-200ms) between requests.
	  - Use HTTP/2 with proper headers (same as a real package manager).
	  - Distribute scans across multiple source IPs if available.
*/

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sudosoc/SUDOSOC-C2/implant/sliver/typosquatting/generator"
)

// ScanResult contains the availability result for one typo variant.
type ScanResult struct {
	Variant     generator.TypoVariant
	Available   bool   // true = not yet registered on the public registry
	Blocked     bool   // true = blocked by registry typosquatting protection
	Error       error
	CheckedAt   time.Time
	StatusCode  int
}

// ScanConfig configures the scanner.
type ScanConfig struct {
	// Ecosystem is the target registry: "pypi", "npm", "nuget", "rubygems".
	Ecosystem string
	// Concurrency is the number of parallel HTTP checks (default: 5).
	Concurrency int
	// DelayMin and DelayMax set the per-request jitter delay (ms).
	DelayMin, DelayMax int
	// RotateUserAgents: use a pool of user-agent strings.
	RotateUserAgents bool
	// OnResult is called for each scan result as it arrives.
	OnResult func(ScanResult)
}

// Scanner checks typo variants against a package registry.
type Scanner struct {
	cfg    *ScanConfig
	client *http.Client
	uas    []string // user-agent pool
	rng    *rand.Rand
}

// NewScanner creates a new registry scanner.
func NewScanner(cfg *ScanConfig) *Scanner {
	if cfg.Concurrency == 0 {
		cfg.Concurrency = 5
	}
	if cfg.DelayMin == 0 {
		cfg.DelayMin = 50
	}
	if cfg.DelayMax == 0 {
		cfg.DelayMax = 200
	}
	return &Scanner{
		cfg:    cfg,
		client: &http.Client{Timeout: 10 * time.Second},
		uas:    buildUserAgentPool(cfg.Ecosystem),
		rng:    rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// ScanAll checks all variants and returns available (unregistered) ones.
func (s *Scanner) ScanAll(ctx context.Context, variants []generator.TypoVariant) []ScanResult {
	if len(variants) == 0 {
		return nil
	}

	sem := make(chan struct{}, s.cfg.Concurrency)
	results := make([]ScanResult, len(variants))
	var wg sync.WaitGroup

	for i, v := range variants {
		wg.Add(1)
		go func(idx int, variant generator.TypoVariant) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Jitter delay to avoid rate limiting.
			delay := s.cfg.DelayMin +
				s.rng.Intn(s.cfg.DelayMax-s.cfg.DelayMin+1)
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Duration(delay) * time.Millisecond):
			}

			res := s.checkOne(ctx, variant)
			results[idx] = res

			if s.cfg.OnResult != nil {
				s.cfg.OnResult(res)
			}
		}(i, v)
	}
	wg.Wait()

	// Filter to available only.
	var available []ScanResult
	for _, r := range results {
		if r.Available && !r.Blocked && r.Error == nil {
			available = append(available, r)
		}
	}
	return available
}

// ScanTargets generates typos for a list of package names and scans them all.
// Returns only the variants that are available for registration.
func (s *Scanner) ScanTargets(ctx context.Context, targets []string) []ScanResult {
	var allVariants []generator.TypoVariant
	for _, t := range targets {
		vars := generator.GenerateAll(t)
		// Only take high-confidence variants to reduce noise.
		for _, v := range vars {
			if v.Confidence >= 0.50 {
				allVariants = append(allVariants, v)
			}
		}
	}
	return s.ScanAll(ctx, allVariants)
}

func (s *Scanner) checkOne(ctx context.Context, variant generator.TypoVariant) ScanResult {
	res := ScanResult{
		Variant:   variant,
		CheckedAt: time.Now(),
	}

	url := s.registryURL(variant.Typo)
	if url == "" {
		res.Error = fmt.Errorf("unknown ecosystem %s", s.cfg.Ecosystem)
		return res
	}

	req, err := http.NewRequestWithContext(ctx, "HEAD", url, nil)
	if err != nil {
		res.Error = err
		return res
	}

	// Set User-Agent to mimic the real package manager client.
	ua := s.pickUserAgent()
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err := s.client.Do(req)
	if err != nil {
		res.Error = err
		return res
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	res.StatusCode = resp.StatusCode

	switch resp.StatusCode {
	case 404:
		// Package does NOT exist → available.
		res.Available = true
		// Check blocklist header (PyPI sends X-PyPI-Typosquatting: 1 for blocked names).
		if resp.Header.Get("X-PyPI-Typosquatting") == "1" ||
			resp.Header.Get("X-Blocked") != "" {
			res.Blocked = true
			res.Available = false
		}
	case 200:
		// Package exists → NOT available.
		res.Available = false
	case 429:
		// Rate limited.
		res.Error = fmt.Errorf("rate limited by %s", s.cfg.Ecosystem)
	default:
		res.Error = fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return res
}

func (s *Scanner) registryURL(name string) string {
	switch s.cfg.Ecosystem {
	case "pypi":
		return "https://pypi.org/pypi/" + name + "/json"
	case "npm":
		return "https://registry.npmjs.org/" + name
	case "nuget":
		return "https://api.nuget.org/v3/registration5-gz-semver2/" +
			strings.ToLower(name) + "/index.json"
	case "rubygems":
		return "https://rubygems.org/api/v1/gems/" + name + ".json"
	}
	return ""
}

func (s *Scanner) pickUserAgent() string {
	if len(s.uas) == 0 || !s.cfg.RotateUserAgents {
		return s.uas[0]
	}
	return s.uas[s.rng.Intn(len(s.uas))]
}

// buildUserAgentPool creates UA strings that look like real package managers.
func buildUserAgentPool(ecosystem string) []string {
	switch ecosystem {
	case "pypi":
		return []string{
			"pip/23.3.1 CPython/3.11.6 Windows/10",
			"pip/23.2.1 CPython/3.10.12 Linux/5.15.0",
			"pip/22.3.1 CPython/3.9.18 macOS/13.5",
			"pip/24.0 CPython/3.12.0 Linux/6.1.0",
			"poetry/1.7.0 CPython/3.11.5 Linux/5.15.0",
			"pipenv/2023.10.24 CPython/3.11.0",
		}
	case "npm":
		return []string{
			"npm/10.2.4 node/v20.10.0 linux x64",
			"npm/9.8.1 node/v18.18.2 win32 x64",
			"npm/10.1.0 node/v20.8.1 darwin x64",
			"yarn/1.22.21 npm/? node/v18.18.0 linux x64",
			"pnpm/8.10.2 npm/? node/v20.9.0 linux x64",
		}
	case "nuget":
		return []string{
			"NuGet Command Line/6.8.0 (Microsoft Windows NT 10.0.22621.0)",
			"NuGet/6.7.0 MSBuild/17.8.3",
			"dotnet-sdk/8.0.100",
		}
	case "rubygems":
		return []string{
			"Ruby, RubyGems/3.4.22 x86_64-linux Ruby/3.2.2",
			"Ruby, RubyGems/3.5.1 arm64-darwin23 Ruby/3.3.0",
		}
	default:
		return []string{"Mozilla/5.0"}
	}
}

// FilterByConfidence returns only scan results with confidence above threshold.
func FilterByConfidence(results []ScanResult, minConfidence float64) []ScanResult {
	var filtered []ScanResult
	for _, r := range results {
		if r.Variant.Confidence >= minConfidence {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

// FilterByCategory returns scan results matching specific typo categories.
func FilterByCategory(results []ScanResult, categories ...string) []ScanResult {
	catSet := make(map[string]bool)
	for _, c := range categories {
		catSet[c] = true
	}
	var filtered []ScanResult
	for _, r := range results {
		if catSet[r.Variant.Category] {
			filtered = append(filtered, r)
		}
	}
	return filtered
}
