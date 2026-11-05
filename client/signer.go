package client

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"github.com/PHPCraftdream/mcp-jack"
)

// Signer produces Ed25519 signatures over the exact message bytes.
// InMemorySigner is the built-in implementation; OS key stores or ssh-agent
// signers plug in by implementing this interface. KID must equal
// jack.KeyID(PublicKey()) over the 32-byte raw Ed25519 public key
// (spec 01 section 2).
//
// Private keys must never live in config files; profiles carry only public
// data (spec 01 section 6, README principle 5).
type Signer interface {
	// Sign returns the 64-byte Ed25519 signature of message.
	Sign(message []byte) ([]byte, error)
	// PublicKey returns the 32-byte raw Ed25519 public key.
	PublicKey() []byte
	// KID returns jack.KeyID(PublicKey()).
	KID() string
}

// InMemorySigner signs with an in-process Ed25519 private key.
type InMemorySigner struct {
	priv ed25519.PrivateKey
	pub  []byte
	kid  string
}

// NewInMemorySigner builds a signer from a 32-byte Ed25519 seed.
func NewInMemorySigner(seed []byte) (*InMemorySigner, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("jack client: signer seed must be exactly %d bytes", ed25519.SeedSize)
	}
	return newInMemorySigner(ed25519.NewKeyFromSeed(seed)), nil
}

// GenerateSigner creates a signer from a crypto/rand seed.
func GenerateSigner() (*InMemorySigner, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	return newInMemorySigner(ed25519.NewKeyFromSeed(seed)), nil
}

func newInMemorySigner(priv ed25519.PrivateKey) *InMemorySigner {
	pub := make([]byte, ed25519.PublicKeySize)
	copy(pub, priv.Public().(ed25519.PublicKey))
	return &InMemorySigner{priv: priv, pub: pub, kid: jack.KeyID(pub)}
}

// Sign returns the Ed25519 signature of message.
func (s *InMemorySigner) Sign(message []byte) ([]byte, error) {
	return ed25519.Sign(s.priv, message), nil
}

// PublicKey returns a copy of the 32-byte public key.
func (s *InMemorySigner) PublicKey() []byte {
	pub := make([]byte, len(s.pub))
	copy(pub, s.pub)
	return pub
}

// KID returns the key identifier of the public key.
func (s *InMemorySigner) KID() string { return s.kid }
