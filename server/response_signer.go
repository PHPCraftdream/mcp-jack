package server

import (
	"crypto/ed25519"
	"errors"

	jack "github.com/PHPCraftdream/mcp-jack"
)

// ResponseSigner удерживает server signing capability без private export.
// PublicKey возвращает фиксированную identity этого handle, не key-selection policy.
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
	// Provider не может изменить expected message или подтвердить другую identity.
	if !jack.Verify(public, []byte(message), signature) {
		complete = true
		return nil, errResponseSigner
	}
	complete = true
	return signature, nil
}
