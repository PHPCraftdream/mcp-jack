package jack

import (
	"bytes"
	"crypto/ed25519"
	"math/big"
)

// Constant time is NOT required here: public data, admission-time only
// (spec 01 section 2, spec 03 section 2).

var (
	curveP     *big.Int // p = 2^255 - 19
	groupL     *big.Int // L = 2^252 + 27742317777372353535851937790883648493
	curveD     *big.Int // d = -121665 * inv(121666) mod p
	sqrtM1     *big.Int // 2^((p-1)/4) mod p
	pPlus3Div8 *big.Int // (p+3)/8, exponent for the square-root candidate
)

func init() {
	two255 := new(big.Int).Lsh(big.NewInt(1), 255)
	curveP = new(big.Int).Sub(two255, big.NewInt(19))

	groupL = new(big.Int).Lsh(big.NewInt(1), 252)
	low, ok := new(big.Int).SetString("27742317777372353535851937790883648493", 10)
	if !ok {
		panic("jack: invalid group order constant")
	}
	groupL.Add(groupL, low)

	// d = -121665/121666 mod p (RFC 8032 section 5.1).
	num := new(big.Int).Mod(big.NewInt(-121665), curveP)
	den := modP(big.NewInt(121666))
	denInv := new(big.Int).ModInverse(den, curveP)
	curveD = modP(num.Mul(num, denInv))

	// sqrtM1 = 2^((p-1)/4) mod p (RFC 8032 section 5.1).
	exp := new(big.Int).Sub(curveP, big.NewInt(1))
	exp.Rsh(exp, 2)
	sqrtM1 = new(big.Int).Exp(big.NewInt(2), exp, curveP)

	pPlus3Div8 = new(big.Int).Add(curveP, big.NewInt(3))
	pPlus3Div8.Rsh(pPlus3Div8, 3)
}

// modP reduces a mod p into [0, p).
func modP(x *big.Int) *big.Int {
	return new(big.Int).Mod(x, curveP)
}

// point is an extended-coordinate point (X, Y, Z, T) with x = X/Z, y = Y/Z, x*y = T/Z (RFC 8032).
type point struct {
	X, Y, Z, T *big.Int
}

func identityPoint() *point {
	return &point{
		X: big.NewInt(0), Y: big.NewInt(1),
		Z: big.NewInt(1), T: big.NewInt(0),
	}
}

// isIdentityPoint reports whether p is the neutral element (x = 0, y = 1).
func isIdentityPoint(q *point) bool {
	return q.X.Sign() == 0 && modP(new(big.Int).Sub(q.Y, q.Z)).Sign() == 0
}

// addPoints returns p + q using the standard extended-coordinate addition
// formulas (RFC 8032 section 5.1.4, same as the reference addPoints).
func addPoints(p, q *point) *point {
	a := modP(new(big.Int).Mul(
		new(big.Int).Sub(p.Y, p.X),
		new(big.Int).Sub(q.Y, q.X),
	))
	b := modP(new(big.Int).Mul(
		new(big.Int).Add(p.Y, p.X),
		new(big.Int).Add(q.Y, q.X),
	))
	c := new(big.Int).Mul(p.T, q.T)
	c.Mul(c, curveD)
	c.Mul(c, big.NewInt(2))
	c = modP(c)
	dd := new(big.Int).Mul(p.Z, q.Z)
	dd.Mul(dd, big.NewInt(2))
	dd = modP(dd)
	e := modP(new(big.Int).Sub(b, a))
	f := modP(new(big.Int).Sub(dd, c))
	g := modP(new(big.Int).Add(dd, c))
	h := modP(new(big.Int).Add(b, a))
	r := &point{}
	r.X = modP(new(big.Int).Mul(e, f))
	r.Y = modP(new(big.Int).Mul(g, h))
	r.T = modP(new(big.Int).Mul(e, h))
	r.Z = modP(new(big.Int).Mul(f, g))
	return r
}

// mulPoint returns k*p by double-and-add over the bits of k (least significant first).
func mulPoint(p *point, k *big.Int) *point {
	r := identityPoint()
	q := p
	for i := 0; i < k.BitLen(); i++ {
		if k.Bit(i) == 1 {
			r = addPoints(r, q)
		}
		q = addPoints(q, q)
	}
	return r
}

// decodePoint decodes the 32-byte Ed25519 encoding, rejecting non-canonical
// encodings and points not on the curve (RFC 8032 section 5.1.3, spec 03 section 2).
// Returns nil for any rejection.
func decodePoint(b []byte) *point {
	if len(b) != 32 {
		return nil
	}
	sign := b[31] >> 7
	y := new(big.Int).SetBytes(reversed(b))
	// The 32-byte Ed25519 encoding is little-endian (RFC 8032 section 5.1.2):
	// after reversing, b[31] is the most significant byte, so this mask
	// clears exactly the sign bit, which is not part of y.
	mask := new(big.Int).Lsh(big.NewInt(1), 255)
	mask.Sub(mask, big.NewInt(1))
	y.And(y, mask)
	if y.Cmp(curveP) >= 0 {
		return nil // non-canonical: y must be below 2^255 - 19
	}
	y2 := modP(new(big.Int).Mul(y, y))
	u := modP(new(big.Int).Sub(y2, big.NewInt(1)))
	v := new(big.Int).Mul(curveD, y2)
	v = modP(v.Add(v, big.NewInt(1)))
	if v.Sign() == 0 {
		return nil // provably unreachable, kept as a guard
	}
	x2 := new(big.Int).ModInverse(v, curveP)
	if x2 == nil {
		return nil
	}
	x2.Mul(x2, u)
	x2 = modP(x2)
	// x = x2^((p+3)/8) mod p; if that is not a square root, multiply by sqrtM1.
	x := new(big.Int).Exp(x2, pPlus3Div8, curveP)
	if !squareRootOK(x, x2) {
		x.Mul(x, sqrtM1)
		x = modP(x)
	}
	if !squareRootOK(x, x2) {
		return nil // not on the curve
	}
	if x.Sign() == 0 && sign == 1 {
		return nil // non-canonical sign for a point with x = 0
	}
	// Make x's parity match the sign bit.
	if byte(x.Bit(0)) != sign&1 {
		x.Sub(curveP, x)
		x = modP(x)
	}
	return &point{
		X: x, Y: y, Z: big.NewInt(1),
		T: modP(new(big.Int).Mul(x, y)),
	}
}

// squareRootOK reports whether x^2 ≡ x2 (mod p).
func squareRootOK(x, x2 *big.Int) bool {
	xx := modP(new(big.Int).Mul(x, x))
	return xx.Cmp(x2) == 0
}

// Verify reports whether sig is a valid Ed25519 signature of message under
// publicKey, with the strict rules of spec 01 section 2: the scalar S
// (little-endian sig[32:64]) is below the group order L, and R (sig[:32]) is
// not a small-order point. A signature violating either is invalid even if
// the verification equation holds. Returns false for wrong lengths; it must
// not panic.
func Verify(publicKey, message, sig []byte) bool {
	if len(publicKey) != 32 || len(sig) != 64 {
		return false
	}
	// Strict R check (spec 01 section 2): a signature whose R encodes a
	// small-order point is invalid even if the verification equation holds.
	if isSmallOrderR(sig[:32]) {
		return false
	}
	// Strict S check: crypto/ed25519 historically does not enforce S < L.
	s := new(big.Int).SetBytes(reversed(sig[32:64]))
	if s.Cmp(groupL) >= 0 {
		return false
	}
	return ed25519.Verify(publicKey, message, sig)
}

// reversed returns a copy of b in little-endian byte order for big.Int set-then-parse.
func reversed(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[len(b)-1-i] = b[i]
	}
	return out
}

// smallOrderR holds the canonical 32-byte encodings of the eight points of
// order dividing 8 (the 8-torsion subgroup): the identity, the two y = 0
// order-4 points, the order-2 point, and the four order-8 points. A signature
// whose R is one of these is invalid even if the verification equation holds
// (spec 01 section 2); Rust rejects the same signatures via dalek's
// verify_strict (is_small_order). Non-canonical encodings of these points
// need no entry: crypto/ed25519 compares the raw signature bytes against the
// recomputed R, so only a canonical R encoding can satisfy the equation.
var smallOrderR = [8][32]byte{
	// identity, order 1: y = 1, x = 0.
	{
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	},
	// y = 0, sign bit clear, order 4.
	{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	},
	// y = 0, sign bit set, order 4.
	{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
	},
	// order 2: y = p - 1, x = 0.
	{
		0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
	},
	// order 8.
	{
		0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0,
		0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
		0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39,
		0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05,
	},
	// order 8, sign bit set.
	{
		0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0,
		0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
		0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39,
		0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x85,
	},
	// order 8.
	{
		0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f,
		0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f,
		0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6,
		0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a,
	},
	// order 8, sign bit set.
	{
		0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f,
		0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f,
		0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6,
		0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0xfa,
	},
}

// isSmallOrderR reports whether r (the first 32 bytes of a signature) is the
// canonical encoding of a small-order point.
func isSmallOrderR(r []byte) bool {
	for i := range smallOrderR {
		if bytes.Equal(r, smallOrderR[i][:]) {
			return true
		}
	}
	return false
}

// ValidatePublicKey reports whether pub satisfies spec 03 section 2: exactly
// 32 bytes, canonical (y below 2^255-19), a point on the curve, not the
// identity, and in the prime-order subgroup ([L]P is the identity).
// nil means acceptable.
func ValidatePublicKey(pub []byte) error {
	if len(pub) != 32 {
		return newError(400, CodeKeyRejected, "public key must be 32 bytes")
	}
	p := decodePoint(pub)
	if p == nil {
		return newError(400, CodeKeyRejected, "non-canonical or off-curve public key")
	}
	if isIdentityPoint(p) {
		return newError(400, CodeKeyRejected, "identity point")
	}
	if !isIdentityPoint(mulPoint(p, groupL)) {
		return newError(400, CodeKeyRejected, "not in the prime-order subgroup")
	}
	return nil
}
