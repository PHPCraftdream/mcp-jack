package userkey

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"github.com/PHPCraftdream/mcp-jack"
)

// Sizes of the raw Ed25519 material this package works with.
const (
	// SeedSize is the exact length of an Ed25519 seed: 32 bytes.
	SeedSize = ed25519.SeedSize
	// PublicKeySize is the exact length of a raw Ed25519 public key: 32 bytes.
	PublicKeySize = ed25519.PublicKeySize
	// SignatureSize is the exact length of an Ed25519 signature: 64 bytes.
	SignatureSize = ed25519.SignatureSize
)

// Signer is the client-role signing surface: the 64-byte Ed25519 signature of
// the exact message bytes, the 32-byte raw public key, and jack.KeyID of that
// public key. It mirrors the client SDK's signer interface shape so
// *ClientKey plugs in structurally and server-side code can accept signers
// without importing the client package. ServerKey and IssuedKey deliberately
// do not satisfy it: public records cannot sign and the issuance handle
// never acts as the user.
type Signer interface {
	// Sign returns the 64-byte Ed25519 signature of message.
	Sign(message []byte) ([]byte, error)
	// PublicKey returns the 32-byte raw Ed25519 public key.
	PublicKey() []byte
	// KID returns jack.KeyID(PublicKey()).
	KID() string
}

// ClientKey is the client-role user key. It holds private material for
// signing but exports only public data: Sign, PublicKey, and KID. There is
// deliberately no private accessor on this type; explicit private handoff
// exists only on the server-local IssuedKey handle. The private key lives
// only inside the unexported priv closure: fmt renders func values as
// addresses under every verb — including nested unexported-field walks that
// skip formatting methods, unsupported-verb fallbacks that restart rendering
// at depth zero, and container traversal — and reflection cannot enumerate
// closure captures, so no standard-format traversal can recover the bytes.
// encoding/json serializes ClientKey as an empty object.
type ClientKey struct {
	priv func() ed25519.PrivateKey
	pub  []byte
	kid  string
}

// IssuedKey is the server-local result of IssueLocalPair and the only type
// that can export private material, through Secret. It cannot sign: the
// server side of a pair never acts as the user. The seed lives only inside
// the unexported seed closure, with the same fmt opacity as ClientKey's priv
// closure. The fields differ in name and in closure signature, so the two
// underlying struct types are not identical and ordinary Go conversions
// between the roles — directly, through pointers, or through slices — are
// compile-time errors.
type IssuedKey struct {
	seed func() []byte
	pub  []byte
	kid  string
}

// ServerKey is the same user key as the server role holds it: the 32-byte
// public key and its KID, with no private material present. It cannot sign
// and has no private export; a private key cannot be recovered from it.
type ServerKey struct {
	pub []byte
	kid string
}

// GenerateClientKey creates a client key from a crypto/rand seed.
func GenerateClientKey() (*ClientKey, error) {
	seed := make([]byte, SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("userkey: reading random seed: %w", err)
	}
	return newClientKey(seed), nil
}

// ImportClientKey builds a client key from exactly 32 seed bytes. The input
// is copied by the Ed25519 derivation, so mutating the caller's slice
// afterwards cannot change the stored key. The returned error text never
// contains any seed material.
func ImportClientKey(seed []byte) (*ClientKey, error) {
	if len(seed) != SeedSize {
		return nil, fmt.Errorf("userkey: seed must be exactly %d bytes, got %d", SeedSize, len(seed))
	}
	return newClientKey(seed), nil
}

// IssueLocalPair generates a new key pair locally with crypto/rand for local
// issuance. The returned *IssuedKey is the server-local handle whose Secret
// method hands the seed to the client out of band; the returned *ServerKey
// is the public identity retained by the server. It performs no network I/O
// and nothing here decides where the seed is stored; server consumers must
// persist only the ServerKey half, since registries, profiles, and RPC
// payloads carry public material only.
func IssueLocalPair() (*IssuedKey, *ServerKey, error) {
	seed := make([]byte, SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, nil, fmt.Errorf("userkey: reading random seed: %w", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := make([]byte, PublicKeySize)
	copy(pub, priv.Public().(ed25519.PublicKey))
	kid := jack.KeyID(pub)
	seedFn := func() []byte { return seed }
	return &IssuedKey{seed: seedFn, pub: pub, kid: kid}, &ServerKey{pub: copyPub(pub), kid: kid}, nil
}

// Sign returns the 64-byte Ed25519 signature of the exact message bytes
// (crypto/ed25519, spec 01 section 2). A nil or zero-value key fails with an
// error instead of panicking.
func (k *ClientKey) Sign(message []byte) ([]byte, error) {
	if k == nil || k.priv == nil {
		return nil, fmt.Errorf("userkey: client key is not initialized")
	}
	return ed25519.Sign(k.priv(), message), nil
}

// PublicKey returns a fresh copy of the 32-byte raw public key, so mutating
// the returned slice cannot change the stored key. A nil or zero-value key
// yields an empty slice.
func (k *ClientKey) PublicKey() []byte {
	if k == nil {
		return nil
	}
	return copyPub(k.pub)
}

// KID returns base64url(SHA-256(public key)) via jack.KeyID (spec 01
// section 2). The KID is public data and is safe to log. A nil or zero-value
// key yields an empty string.
func (k *ClientKey) KID() string {
	if k == nil {
		return ""
	}
	return k.kid
}

// Secret returns a fresh copy of the 32-byte seed. This is the only private
// export in the package, available exclusively on the server-local issuance
// handle: ClientKey has no private accessor and ServerKey holds no private
// material. The copy is plaintext: the closure keeps the seed in plaintext
// memory for the lifetime of the handle, and Go cannot guarantee zeroization
// of either, so callers must not treat Secret copies as the only exposure.
// Zero the returned copy after use if your threat model requires it. A nil
// or zero-value handle yields nil.
func (k *IssuedKey) Secret() []byte {
	if k == nil || k.seed == nil {
		return nil
	}
	return append([]byte(nil), k.seed()...)
}

// PublicKey returns a fresh copy of the 32-byte raw public key of the issued
// pair. A nil or zero-value handle yields an empty slice.
func (k *IssuedKey) PublicKey() []byte {
	if k == nil {
		return nil
	}
	return copyPub(k.pub)
}

// KID returns base64url(SHA-256(public key)) via jack.KeyID, identical to the
// KID of the ServerKey half and of the ClientKey imported from Secret (spec
// 01 section 2). A nil or zero-value handle yields an empty string.
func (k *IssuedKey) KID() string {
	if k == nil {
		return ""
	}
	return k.kid
}

// redacted renders the client key for any fmt verb: the KID is public data
// (it appears in protocol headers and registries), everything else is
// withheld.
func (k ClientKey) redacted() string {
	return fmt.Sprintf("userkey.ClientKey{kid:%s}", k.kid)
}

// String implements fmt.Stringer on a value receiver so both ClientKey
// values and *ClientKey, including dereferenced copies, print redacted
// instead of leaking the private fields through %v, %+v, or %s.
func (k ClientKey) String() string { return k.redacted() }

// GoString implements fmt.GoStringer so %#v is redacted too.
func (k ClientKey) GoString() string { return k.redacted() }

// Format implements fmt.Formatter so every direct verb, including %x and %d,
// prints the redacted form. Nested values under unexported fields skip these
// methods; the priv closure only ever renders as a func address, under
// supported verbs and after unsupported-verb depth resets alike, so no walk
// reaches seed bytes.
func (k ClientKey) Format(f fmt.State, verb rune) {
	fmt.Fprint(f, k.redacted())
}

// redacted renders the issuance handle for any fmt verb: the KID is public
// data, everything else is withheld.
func (k IssuedKey) redacted() string {
	return fmt.Sprintf("userkey.IssuedKey{kid:%s}", k.kid)
}

// String implements fmt.Stringer on a value receiver so both IssuedKey
// values and *IssuedKey print redacted.
func (k IssuedKey) String() string { return k.redacted() }

// GoString implements fmt.GoStringer so %#v is redacted too.
func (k IssuedKey) GoString() string { return k.redacted() }

// Format implements fmt.Formatter so every direct verb prints the redacted
// form; the seed closure only ever renders as a func address, under supported
// verbs and after unsupported-verb depth resets alike, so no walk reaches
// seed bytes.
func (k IssuedKey) Format(f fmt.State, verb rune) {
	fmt.Fprint(f, k.redacted())
}

// ImportServerKey builds a server key from exactly 32 raw public-key bytes.
// The bytes are copied to an owned snapshot first and that copy is validated
// with jack.ValidatePublicKey, so the server role itself rejects
// non-canonical, off-curve, identity, and wrong-subgroup keys before they
// are stored. Only public material is accepted and kept; there is no way to
// obtain private material from the result. The error never contains key
// material.
func ImportServerKey(publicKey []byte) (*ServerKey, error) {
	pub, err := importPublic(publicKey)
	if err != nil {
		return nil, err
	}
	if err := jack.ValidatePublicKey(pub); err != nil {
		return nil, fmt.Errorf("userkey: public key rejected: %w", err)
	}
	return &ServerKey{pub: pub, kid: jack.KeyID(pub)}, nil
}

// PublicKey returns a fresh copy of the 32-byte raw public key. A nil or
// zero-value key yields an empty slice.
func (k *ServerKey) PublicKey() []byte {
	if k == nil {
		return nil
	}
	return copyPub(k.pub)
}

// KID returns base64url(SHA-256(public key)) via jack.KeyID, identical to
// the KID of the IssuedKey and of the ClientKey imported from its Secret
// (spec 01 section 2). A nil or zero-value key yields an empty string.
func (k *ServerKey) KID() string {
	if k == nil {
		return ""
	}
	return k.kid
}

// Verify reports whether signature is a valid Ed25519 signature of message
// under the imported public key, via jack.Verify with its strict scalar
// rule. It is the server role's only cryptographic operation on user keys:
// public material verifies, it never signs. A nil or zero-value key returns
// false.
func (k *ServerKey) Verify(message, signature []byte) bool {
	if k == nil {
		return false
	}
	return jack.Verify(k.pub, message, signature)
}

// newClientKey builds the client-role wrapper from a 32-byte seed. The
// derived private key is captured by a closure: func values render only as
// addresses in every fmt path, and reflection cannot enumerate closure
// captures, so the seed bytes are unreachable from the struct fields.
func newClientKey(seed []byte) *ClientKey {
	priv := ed25519.NewKeyFromSeed(seed)
	pub := make([]byte, PublicKeySize)
	copy(pub, priv.Public().(ed25519.PublicKey))
	privFn := func() ed25519.PrivateKey { return priv }
	return &ClientKey{priv: privFn, pub: pub, kid: jack.KeyID(pub)}
}

// importPublic checks the length of raw public-key bytes and returns an
// owned copy for validation and storage.
func importPublic(publicKey []byte) ([]byte, error) {
	if len(publicKey) != PublicKeySize {
		return nil, fmt.Errorf("userkey: public key must be exactly %d bytes, got %d", PublicKeySize, len(publicKey))
	}
	pub := make([]byte, PublicKeySize)
	copy(pub, publicKey)
	return pub, nil
}

// copyPub returns a copy of a raw public-key slice.
func copyPub(pub []byte) []byte {
	out := make([]byte, len(pub))
	copy(out, pub)
	return out
}
