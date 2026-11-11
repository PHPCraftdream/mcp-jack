package server

import (
	"errors"
	"net/http"

	jack "github.com/PHPCraftdream/mcp-jack"
)

// ResponseKeyRequest — owned copy; payload не является источником key authority.
type ResponseKeyRequest struct {
	Status           int
	Tool             string
	RequestSignature string
	Body             []byte
}

// ResponseKeyAuthorization закрепляет identity/time и lease до завершения write.
// Provider обязан ограничивать callbacks и не терять lease при panic/error.
type ResponseKeyAuthorization struct {
	Signer    ResponseSigner
	Timestamp int64
	Final     func() error
	Release   func()
}

// ResponseKeyProvider выбирается явно; persistence/clock/ring invariants принадлежат provider.
type ResponseKeyProvider interface {
	AuthorizeResponse(ResponseKeyRequest) (ResponseKeyAuthorization, error)
}

var errResponseAuthorization = errors.New("server: response authorization unavailable")

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
	if authorization.Signer == nil || authorization.Final == nil || authorization.Release == nil || authorization.Timestamp < 0 || authorization.Timestamp > maxDurableTimestamp {
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
