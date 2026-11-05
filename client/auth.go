package client

import (
	"crypto/rand"
	"fmt"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
)

// DefaultWindow is the timestamp acceptance window the server applies by
// default (spec 01 section 4 step 6); the client uses it unless overridden.
const DefaultWindow = 30 * time.Second

// nonceSize is the required nonce length of spec 01 section 2.
const nonceSize = 16

// NonceSource returns the 16 random nonce bytes for one request.
type NonceSource func() ([]byte, error)

// RandomNonce returns 16 bytes from crypto/rand.
func RandomNonce() ([]byte, error) {
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

// hasControl reports whether s contains an ASCII control character; the
// signing target must not embed line breaks (spec 01 section 3.1).
func hasControl(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}

// SignRequest builds the signed Jack-Auth header value for one request
// (spec 01 sections 3 and 3.1).
func SignRequest(s Signer, aud, method, target string, body []byte, nonce []byte, now time.Time) (string, error) {
	if s == nil {
		return "", fmt.Errorf("jack client: nil signer")
	}
	if len(nonce) != nonceSize {
		return "", fmt.Errorf("jack client: nonce must be exactly %d bytes, got %d", nonceSize, len(nonce))
	}
	if method == "" || hasControl(method) {
		return "", fmt.Errorf("jack client: empty or control-character HTTP method")
	}
	if target == "" || hasControl(target) {
		return "", fmt.Errorf("jack client: empty or control-character target")
	}
	kid := s.KID()
	ts := now.Unix()
	nonceB64 := jack.EncodeBase64URL(nonce)
	sig, err := s.Sign([]byte(jack.RequestSigningString(method, target, aud, kid, ts, nonceB64, body)))
	if err != nil {
		return "", err
	}
	return jack.FormatRequestAuth(jack.RequestAuth{
		Kid:   kid,
		TS:    ts,
		Nonce: nonceB64,
		Sig:   jack.EncodeBase64URL(sig),
	}), nil
}

// VerifyResponse is the client-side mirror of spec 01 section 5: it checks
// that the response was signed by the pinned server key, over the request
// signature, within the window. Each failure is a *jack.Error.
func VerifyResponse(serverKey []byte, status int, headerValues []string, requestSig string, body []byte, now time.Time, window time.Duration) error {
	if len(serverKey) != 32 {
		// Configuration misuse, not a protocol rejection.
		return fmt.Errorf("jack client: pinned server key must be exactly 32 bytes, got %d", len(serverKey))
	}
	if window <= 0 {
		window = DefaultWindow
	}
	windowSeconds := int64(window / time.Second)

	auth, err := jack.ParseResponseAuth(headerValues)
	if err != nil {
		return err
	}
	if auth.Kid != jack.KeyID(serverKey) {
		return &jack.Error{HTTPStatus: 0, Code: jack.CodeUnknownServerKey, Message: "response signed by an unpinned key"}
	}
	if ts := now.Unix(); ts < auth.TS {
		if auth.TS-ts > windowSeconds {
			return &jack.Error{HTTPStatus: 0, Code: jack.CodeTimestampOutOfWindow, Message: "response timestamp outside the acceptance window"}
		}
	} else if ts-auth.TS > windowSeconds {
		return &jack.Error{HTTPStatus: 0, Code: jack.CodeTimestampOutOfWindow, Message: "response timestamp outside the acceptance window"}
	}
	sig, err := jack.DecodeBase64URLFixed(auth.Sig, 64)
	if err != nil {
		// The parser already enforces a canonical 64-byte sig, so any error
		// here can only be a signature mismatch, not a malformed header.
		return &jack.Error{HTTPStatus: 0, Code: jack.CodeBadSignature, Message: "malformed response signature"}
	}
	msg := []byte(jack.ResponseSigningString(status, requestSig, auth.Kid, auth.TS, body))
	if !jack.Verify(serverKey, msg, sig) {
		return &jack.Error{HTTPStatus: 0, Code: jack.CodeBadSignature, Message: "response signature does not verify"}
	}
	return nil
}
