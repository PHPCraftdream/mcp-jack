package transport

import (
	"crypto/ed25519"
	"errors"
	"net/http"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/server/internal/verify"
)

// ResponseSigner holds the server signing capability without private-key export.
// PublicKey returns the fixed identity of this handle, not a key-selection policy.
// The provider must bound method duration: the SDK waits synchronously
// and cannot forcibly interrupt a stuck callback.
type ResponseSigner interface {
	PublicKey() []byte
	Sign([]byte) ([]byte, error)
}

// ResponseKeyRequest is an owned copy; the payload is not the source of key authority.
type ResponseKeyRequest struct {
	Status           int
	Tool             string
	RequestSignature string
	Body             []byte
}

// ResponseKeyAuthorization pins identity/time and the lease until the write completes.
// The provider must bound its callbacks and must not lose the lease on panic/error.
type ResponseKeyAuthorization struct {
	Signer    ResponseSigner
	Timestamp int64
	Final     func() error
	Release   func()
}

// ResponseKeyProvider is selected explicitly; persistence/clock/ring invariants belong to the provider.
type ResponseKeyProvider interface {
	AuthorizeResponse(ResponseKeyRequest) (ResponseKeyAuthorization, error)
}

var errResponseSigner = errors.New("server: response signer unavailable")

var errResponseAuthorization = errors.New("server: response authorization unavailable")

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

func authorizeResponse(provider ResponseKeyProvider, input ResponseKeyRequest) (authorization ResponseKeyAuthorization, err error) {
	complete := false
	defer func() {
		if !complete {
			_ = recover()
			err = errResponseAuthorization
		}
	}()
	authorization, err = provider.AuthorizeResponse(input)
	complete = true
	if err != nil {
		return authorization, errResponseAuthorization
	}
	if authorization.Signer == nil || authorization.Final == nil || authorization.Release == nil || authorization.Timestamp < 0 || authorization.Timestamp > verify.MaxDurableTimestamp {
		return authorization, errResponseAuthorization
	}
	return authorization, nil
}

func finalResponseAuthorization(check func() error) (err error) {
	complete := false
	defer func() {
		if !complete {
			_ = recover()
			err = errResponseAuthorization
		}
	}()
	err = check()
	complete = true
	if err != nil {
		return errResponseAuthorization
	}
	return nil
}

func releaseResponseAuthorization(release func()) {
	if release == nil {
		return
	}
	defer func() { _ = recover() }()
	release()
}

func (h *handler) writeAuthorized(w http.ResponseWriter, status int, header http.Header, body []byte, requestSignature, tool string) {
	payload := append([]byte(nil), body...)
	input := ResponseKeyRequest{Status: status, Tool: tool, RequestSignature: requestSignature, Body: append([]byte(nil), payload...)}
	authorization, err := authorizeResponse(h.keys, input)
	defer releaseResponseAuthorization(authorization.Release)
	refuse := func() {
		writeError(w, http.StatusServiceUnavailable, "rotation_state_unavailable", "response authorization unavailable")
	}
	if err != nil {
		refuse()
		return
	}
	public, err := responsePublicKey(authorization.Signer)
	if err != nil {
		refuse()
		return
	}
	kid := jack.KeyID(public)
	message := jack.ResponseSigningString(status, requestSignature, kid, authorization.Timestamp, payload)
	signature, err := responseSignature(authorization.Signer, public, message)
	if err != nil {
		refuse()
		return
	}
	if err := finalResponseAuthorization(authorization.Final); err != nil {
		refuse()
		return
	}
	header.Set("Jack-Auth", jack.FormatResponseAuth(jack.ResponseAuth{Kid: kid, TS: authorization.Timestamp, Sig: jack.EncodeBase64URL(signature)}))
	writeRaw(w, status, header, payload)
}
