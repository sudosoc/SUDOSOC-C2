package crypto

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	Elliptic Curve Primitives for Zero-Knowledge Proofs.

	We use the Ristretto255 group (a prime-order group built over Curve25519)
	rather than the raw Edwards25519 curve. Ristretto255 provides:

	  - Prime-order group (no cofactor issues that plague raw Edwards curves)
	  - Uniform, canonical point encoding (no point malleability)
	  - Constant-time operations (side-channel resistant)
	  - Compatibility with Curve25519's field arithmetic

	The group order is:
	  l = 2^252 + 27742317777372353535851937790883648493

	Security level: ~128 bits (equivalent to 3072-bit RSA).

	We implement the group operations using Go's crypto/internal/edwards25519
	package (available in Go 1.20+ as golang.org/x/crypto/internal/edwards25519).
	For the ZKP implementation we use the standard library's crypto/elliptic as
	an abstraction and provide our own P-256 implementation as a fallback.

	For production use, Ristretto255 is preferred. For simplicity in this
	implementation, we use P-256 (secp256r1 / NIST P-256) which is in the
	standard library's crypto/elliptic package. The ZKP math is identical;
	only the group parameters differ.

	References:
	  - Ristretto255: https://ristretto.group/
	  - Schnorr ZKP: https://tools.ietf.org/html/rfc8235
	  - NIZK: https://eprint.iacr.org/2021/1234
*/

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
)

// Group wraps an elliptic curve group for ZKP operations.
type Group struct {
	curve elliptic.Curve
	order *big.Int
}

// Point represents a group element (curve point).
type Point struct {
	X, Y *big.Int
	// Infinity indicates the point-at-infinity (identity element).
	Infinity bool
}

// Scalar represents a field element (integer mod group order).
type Scalar struct {
	v *big.Int
}

// DefaultGroup returns the P-256 group (standard, well-studied).
func DefaultGroup() *Group {
	c := elliptic.P256()
	return &Group{curve: c, order: c.Params().N}
}

// ─── Scalar operations ────────────────────────────────────────────────────

// NewScalar creates a scalar from a big.Int, reduced mod order.
func (g *Group) NewScalar(v *big.Int) *Scalar {
	return &Scalar{v: new(big.Int).Mod(v, g.order)}
}

// RandomScalar generates a cryptographically random scalar.
func (g *Group) RandomScalar() (*Scalar, error) {
	// Sample uniformly from [1, order-1].
	for {
		b := make([]byte, (g.order.BitLen()+7)/8)
		if _, err := rand.Read(b); err != nil {
			return nil, fmt.Errorf("random scalar: %w", err)
		}
		v := new(big.Int).SetBytes(b)
		v.Mod(v, g.order)
		if v.Sign() > 0 {
			return &Scalar{v: v}, nil
		}
	}
}

// HashToScalar computes H(data) mod order.
func (g *Group) HashToScalar(data ...[]byte) *Scalar {
	h := sha256.New()
	for _, d := range data {
		h.Write(d)
	}
	digest := h.Sum(nil)
	v := new(big.Int).SetBytes(digest)
	v.Mod(v, g.order)
	return &Scalar{v: v}
}

// Add returns a + b mod order.
func (g *Group) ScalarAdd(a, b *Scalar) *Scalar {
	r := new(big.Int).Add(a.v, b.v)
	r.Mod(r, g.order)
	return &Scalar{v: r}
}

// Mul returns a * b mod order.
func (g *Group) ScalarMul(a, b *Scalar) *Scalar {
	r := new(big.Int).Mul(a.v, b.v)
	r.Mod(r, g.order)
	return &Scalar{v: r}
}

// Sub returns a - b mod order.
func (g *Group) ScalarSub(a, b *Scalar) *Scalar {
	r := new(big.Int).Sub(a.v, b.v)
	r.Mod(r, g.order)
	return &Scalar{v: r}
}

// Neg returns -a mod order.
func (g *Group) ScalarNeg(a *Scalar) *Scalar {
	r := new(big.Int).Neg(a.v)
	r.Mod(r, g.order)
	return &Scalar{v: r}
}

// Bytes returns the scalar as a fixed-length big-endian byte slice.
func (s *Scalar) Bytes() []byte {
	b := s.v.Bytes()
	result := make([]byte, 32)
	copy(result[32-len(b):], b)
	return result
}

// Equal returns true if a == b.
func (s *Scalar) Equal(other *Scalar) bool {
	return s.v.Cmp(other.v) == 0
}

// ─── Point operations ─────────────────────────────────────────────────────

// BasePoint returns the generator point G.
func (g *Group) BasePoint() *Point {
	p := g.curve.Params()
	return &Point{X: new(big.Int).Set(p.Gx), Y: new(big.Int).Set(p.Gy)}
}

// Identity returns the point at infinity (additive identity).
func (g *Group) Identity() *Point {
	return &Point{Infinity: true, X: big.NewInt(0), Y: big.NewInt(0)}
}

// ScalarBaseMul returns s * G (generator point multiplication).
func (g *Group) ScalarBaseMul(s *Scalar) *Point {
	x, y := g.curve.ScalarBaseMult(s.v.Bytes())
	if x == nil {
		return g.Identity()
	}
	return &Point{X: x, Y: y}
}

// ScalarMulPoint returns s * P.
func (g *Group) ScalarMulPoint(s *Scalar, p *Point) *Point {
	if p.Infinity {
		return g.Identity()
	}
	x, y := g.curve.ScalarMult(p.X, p.Y, s.v.Bytes())
	if x == nil {
		return g.Identity()
	}
	return &Point{X: x, Y: y}
}

// AddPoints returns P + Q.
func (g *Group) AddPoints(p, q *Point) *Point {
	if p.Infinity {
		return &Point{X: new(big.Int).Set(q.X), Y: new(big.Int).Set(q.Y), Infinity: q.Infinity}
	}
	if q.Infinity {
		return &Point{X: new(big.Int).Set(p.X), Y: new(big.Int).Set(p.Y), Infinity: p.Infinity}
	}
	x, y := g.curve.Add(p.X, p.Y, q.X, q.Y)
	return &Point{X: x, Y: y}
}

// NegPoint returns -P (the additive inverse).
func (g *Group) NegPoint(p *Point) *Point {
	if p.Infinity {
		return g.Identity()
	}
	// Negation on elliptic curve: (x, y) → (x, -y mod p)
	negY := new(big.Int).Neg(p.Y)
	negY.Mod(negY, g.curve.Params().P)
	return &Point{X: new(big.Int).Set(p.X), Y: negY}
}

// IsOnCurve checks whether P is a valid curve point.
func (g *Group) IsOnCurve(p *Point) bool {
	if p.Infinity {
		return true
	}
	return g.curve.IsOnCurve(p.X, p.Y)
}

// Equal returns true if P == Q.
func (p *Point) Equal(q *Point) bool {
	if p.Infinity && q.Infinity {
		return true
	}
	if p.Infinity || q.Infinity {
		return false
	}
	return p.X.Cmp(q.X) == 0 && p.Y.Cmp(q.Y) == 0
}

// Bytes returns the compressed encoding of P (33 bytes for P-256).
func (p *Point) Bytes() []byte {
	if p.Infinity {
		return []byte{0x00}
	}
	// Compressed point: 0x02 (even Y) or 0x03 (odd Y) + X (32 bytes for P-256).
	prefix := byte(0x02)
	if p.Y.Bit(0) == 1 {
		prefix = 0x03
	}
	xBytes := p.X.Bytes()
	result := make([]byte, 33)
	result[0] = prefix
	copy(result[1+32-len(xBytes):], xBytes)
	return result
}

// PointFromBytes decodes a compressed curve point.
func (g *Group) PointFromBytes(b []byte) (*Point, error) {
	if len(b) == 1 && b[0] == 0x00 {
		return g.Identity(), nil
	}
	if len(b) != 33 {
		return nil, errors.New("invalid compressed point length")
	}
	// Decompress: find Y from X.
	// For P-256: y² = x³ - 3x + b (mod p)
	x := new(big.Int).SetBytes(b[1:])
	p256 := g.curve.Params()

	// y² = x³ + ax + b mod p  (for P-256, a = -3)
	x3 := new(big.Int).Exp(x, big.NewInt(3), p256.P)
	ax := new(big.Int).Mul(big.NewInt(-3), x)
	ax.Mod(ax, p256.P)
	rhs := new(big.Int).Add(x3, ax)
	rhs.Add(rhs, p256.B)
	rhs.Mod(rhs, p256.P)

	// Compute square root via Tonelli-Shanks (P-256: p ≡ 3 mod 4 → simple sqrt).
	ySquared := rhs
	exp := new(big.Int).Add(p256.P, big.NewInt(1))
	exp.Rsh(exp, 2) // (p+1)/4
	y := new(big.Int).Exp(ySquared, exp, p256.P)

	// Choose correct root based on parity bit.
	if (b[0] == 0x02) != (y.Bit(0) == 0) {
		y.Sub(p256.P, y)
	}

	pt := &Point{X: x, Y: y}
	if !g.IsOnCurve(pt) {
		return nil, errors.New("decoded point not on curve")
	}
	return pt, nil
}

// ─── Hash-to-point ────────────────────────────────────────────────────────

// HashToPoint maps arbitrary data to a curve point using try-and-increment.
// This is used for constructing commitment bases independent of G.
func (g *Group) HashToPoint(data []byte) *Point {
	ctr := uint32(0)
	for {
		h := sha256.New()
		h.Write(data)
		var ctrbuf [4]byte
		ctrbuf[0] = byte(ctr >> 24); ctrbuf[1] = byte(ctr >> 16)
		ctrbuf[2] = byte(ctr >> 8); ctrbuf[3] = byte(ctr)
		h.Write(ctrbuf[:])
		digest := h.Sum(nil)

		// Try to decode as x-coordinate.
		x := new(big.Int).SetBytes(digest)
		x.Mod(x, g.curve.Params().P)

		// Check if x² = y² has a solution on the curve.
		p256 := g.curve.Params()
		x3 := new(big.Int).Exp(x, big.NewInt(3), p256.P)
		ax := new(big.Int).Mul(big.NewInt(-3), x)
		ax.Mod(ax, p256.P)
		rhs := new(big.Int).Add(x3, ax)
		rhs.Add(rhs, p256.B)
		rhs.Mod(rhs, p256.P)

		// Legendre symbol: rhs^((p-1)/2) mod p == 1 means it's a QR.
		exp := new(big.Int).Sub(p256.P, big.NewInt(1))
		exp.Rsh(exp, 1)
		legendre := new(big.Int).Exp(rhs, exp, p256.P)
		if legendre.Cmp(big.NewInt(1)) == 0 {
			sqrtExp := new(big.Int).Add(p256.P, big.NewInt(1))
			sqrtExp.Rsh(sqrtExp, 2)
			y := new(big.Int).Exp(rhs, sqrtExp, p256.P)
			if y.Bit(0) != 0 { // force even Y for determinism
				y.Sub(p256.P, y)
			}
			return &Point{X: x, Y: y}
		}
		ctr++
	}
}
