package server

import (
	"crypto/ed25519"
	"errors"

	jack "github.com/PHPCraftdream/mcp-jack"
)

// ResponseSigner holds the server signing capability without private-key export.
// PublicKey returns the fixed identity of this handle, not a key-selection policy.
// The provider must bound method duration: the SDK waits synchronously
// and cannot forcibly interrupt a stuck callback.
type ResponseSigner interface {
	PublicKey() []byte
	Sign([]byte) ([]byte, error)
}

var errResponseSigner = errors.New("server: response signer unavailable")

func responsePublicKey(signer ResponseSigner) (public []byte, result error) {
	complete := false
	defer func() {
		if !complete {
			_ = recover()
			public, result = nil, errResponseSigner
		}
	}()
	provided := signer.PublicKey()
	if len(provided) != ed25519.PublicKeySize {
		complete = true
		return nil, errResponseSigner
	}
	public = append([]byte(nil), provided...)
	if jack.ValidatePublicKey(public) != nil {
		complete = true
		return nil, errResponseSigner
	}
	complete = true
	return public, nil
}

func responseSignature(signer ResponseSigner, public []byte, message string) (signature []byte, result error) {
	complete := false
	defer func() {
		if !complete {
			_ = recover()
			signature, result = nil, errResponseSigner
		}
	}()
	provided, err := signer.Sign([]byte(message))
	if err != nil || len(provided) != ed25519.SignatureSize {
		complete = true
		return nil, errResponseSigner
	}
	signature = append([]byte(nil), provided...)
	// The provider cannot alter the expected message or attest a different identity.
	if !jack.Verify(public, []byte(message), signature) {
		complete = true
		return nil, errResponseSigner
	}
	complete = true
	return signature, nil
}
