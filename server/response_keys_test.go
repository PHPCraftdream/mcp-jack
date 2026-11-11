package server

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/client"
)

type responseKeyProviderFunc func(ResponseKeyRequest) (ResponseKeyAuthorization, error)
func (provider responseKeyProviderFunc) AuthorizeResponse(input ResponseKeyRequest) (ResponseKeyAuthorization, error) { return provider(input) }

type leaseWireRecorder struct {
	*httptest.ResponseRecorder
	held *bool
	t *testing.T
}
func (writer leaseWireRecorder) WriteHeader(status int) { if !*writer.held { writer.t.Error("lease released before headers") }; writer.ResponseRecorder.WriteHeader(status) }
func (writer leaseWireRecorder) Write(body []byte) (int, error) { if !*writer.held { writer.t.Error("lease released before body") }; return writer.ResponseRecorder.Write(body) }

func responseKeyFixture(t *testing.T, provider ResponseKeyProvider) (http.Handler, func(byte) *http.Request, *NonceStore) {
	t.Helper()
	user := responseFixtureKey("leased-user")
	public := user.Public().(ed25519.PublicKey)
	kid := jack.KeyID(public)
	state := NewMemoryState()
	if err := state.Update(func(edit *StateEdit) error { edit.PutKey(RegistryEntry{Kid: kid, PublicKey: jack.EncodeBase64URL(public), Name: "caller"}); return nil }); err != nil { t.Fatal(err) }
	nonces := NewNonceStore()
	verifier, err := NewVerifier(Config{Aud: "public", State: state, Nonces: nonces, Now: func() int64 { return 100 }})
	if err != nil { t.Fatal(err) }
	handler, err := NewHandler(HandlerConfig{Verifier: verifier, ResponseKeys: provider}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-App-Private", "not-on-refusal")
		_, _ = w.Write([]byte("application payload"))
	}))
	if err != nil { t.Fatal(err) }
	request := func(value byte) *http.Request {
		body := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
		auth := jack.RequestAuth{Kid: kid, TS: 100, Nonce: jack.EncodeBase64URL(bytes.Repeat([]byte{value}, 16))}
		message := jack.RequestSigningString("POST", "/mcp", "public", kid, auth.TS, auth.Nonce, body)
		auth.Sig = jack.EncodeBase64URL(ed25519.Sign(user, []byte(message)))
		r := httptest.NewRequest("POST", "/mcp", bytes.NewReader(body))
		r.Header.Set("Jack-Auth", jack.FormatRequestAuth(auth))
		r.Header.Set("Content-Type", "application/json")
		return r
	}
	return handler, request, nonces
}

func TestResponseKeyAuthorizationCapturesIdentityAndHoldsLeaseThroughWrite(t *testing.T) {
	var recorder *httptest.ResponseRecorder
	held := false
	calls, signs, finals, releases := 0, 0, 0, 0
	keys := []ed25519.PrivateKey{responseFixtureKey("leased-old"), responseFixtureKey("leased-next")}
	provider := responseKeyProviderFunc(func(input ResponseKeyRequest) (ResponseKeyAuthorization, error) {
		index := calls
		calls++
		held = true
		if input.Status != 200 || string(input.Body) != "application payload" { t.Error("provider saw wrong owned payload") }
		input.Body[0] ^= 1
		key := keys[index]
		signer := &testResponseSigner{public: key.Public().(ed25519.PublicKey), sign: func(message []byte) ([]byte, error) { signs++; return ed25519.Sign(key, message), nil }}
		return ResponseKeyAuthorization{Signer: signer, Timestamp: int64(100+index), Final: func() error {
			finals++
			if recorder.Body.Len() != 0 || recorder.Header().Get("Jack-Auth") != "" { t.Error("wire bytes exposed before final gate") }
			return nil
		}, Release: func() { releases++; held = false }}, nil
	})
	handler, request, nonces := responseKeyFixture(t, provider)
	if calls != 0 { t.Fatal("constructor authorized a response") }
	bad := request(1)
	bad.URL.RawQuery = "tampered=1"
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, bad)
	if recorder.Code != 401 || calls != 0 || nonces.Len() != 0 { t.Fatal("pre-auth request acquired response authorization") }
	for index := 0; index < 2; index++ {
		recorder = httptest.NewRecorder()
		r := request(byte(index+2))
		auth, err := jack.ParseRequestAuth(r.Header.Values("Jack-Auth"))
		if err != nil { t.Fatal(err) }
		handler.ServeHTTP(leaseWireRecorder{ResponseRecorder: recorder, held: &held, t: t}, r)
		if recorder.Code != 200 || string(recorder.Body.Bytes()) != "application payload" || held { t.Fatal("authorized payload/lease ownership changed") }
		if err := client.VerifyResponse(keys[index].Public().(ed25519.PublicKey), 200, recorder.Header().Values("Jack-Auth"), auth.Sig, recorder.Body.Bytes(), time.Unix(100, 0), 30*time.Second); err != nil { t.Fatal("selected lease identity failed exact signature") }
	}
	if calls != 2 || signs != 2 || finals != 2 || releases != 2 || nonces.Len() != 2 { t.Fatal("response authorization/sign/final/release repeated") }
}

func TestResponseKeyAuthorizationFinalRefusalNeverExposesPayloadOrRetries(t *testing.T) {
	for _, failure := range []string{"acquire-error", "acquire-panic", "bad-public", "bad-signature", "sign-panic", "missing-final", "missing-release", "negative-time", "final-error", "final-panic"} {
		t.Run(failure, func(t *testing.T) {
			calls, signs, finals, releases := 0, 0, 0, 0
			key := responseFixtureKey("leased-fault")
			provider := responseKeyProviderFunc(func(ResponseKeyRequest) (ResponseKeyAuthorization, error) {
				calls++
				if failure == "acquire-panic" { panic("private provider detail") }
				signer := &testResponseSigner{public: key.Public().(ed25519.PublicKey), sign: func(message []byte) ([]byte, error) {
					signs++
					if failure == "sign-panic" { panic("private provider detail") }
					if failure == "bad-signature" { return make([]byte, 64), nil }
					return ed25519.Sign(key, message), nil
				}}
				if failure == "bad-public" { signer.public = make([]byte, 31) }
				authorization := ResponseKeyAuthorization{Signer: signer, Timestamp: 100, Final: func() error {
					finals++
					if failure == "final-panic" { panic("private provider detail") }
					return errors.New("private provider detail")
				}, Release: func() { releases++ }}
				if failure == "missing-final" { authorization.Final = nil }
				if failure == "missing-release" { authorization.Release = nil }
				if failure == "negative-time" { authorization.Timestamp = -1 }
				if failure == "acquire-error" { return authorization, errors.New("private provider detail") }
				return authorization, nil
			})
			handler, request, nonces := responseKeyFixture(t, provider)
			r := request(1)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, r)
			if recorder.Code != 503 || recorder.Header().Get("Jack-Auth") != "" || recorder.Header().Get("X-App-Private") != "" || bytes.Contains(recorder.Body.Bytes(), []byte("application payload")) || bytes.Contains(recorder.Body.Bytes(), []byte("private provider detail")) || nonces.Len() != 1 || calls != 1 || signs > 1 || finals > 1 {
				t.Fatal("provider fault exposed signed/payload/detail response or retried")
			}
			wantSigns, wantFinals := 0, 0
			switch failure {
			case "bad-signature", "sign-panic": wantSigns = 1
			case "final-error", "final-panic": wantSigns, wantFinals = 1, 1
			}
			if signs != wantSigns || finals != wantFinals { t.Fatal("invalid authorization reached a later phase") }
			wantRelease := 1
			if failure == "acquire-panic" || failure == "missing-release" { wantRelease = 0 }
			if releases != wantRelease { t.Fatal("authorization lease release lost or repeated") }
			replay := httptest.NewRecorder()
			handler.ServeHTTP(replay, request(1))
			if replay.Code != 401 || calls != 1 { t.Fatal("consumed nonce allowed handler or signer redelivery") }
		})
	}
}

func TestResponseKeyProfilesAreExplicitlyExclusive(t *testing.T) {
	verifier, err := NewVerifier(Config{Aud: "public", State: NewMemoryState(), Nonces: NewNonceStore()})
	if err != nil { t.Fatal(err) }
	calls := 0
	provider := responseKeyProviderFunc(func(ResponseKeyRequest) (ResponseKeyAuthorization, error) { calls++; return ResponseKeyAuthorization{}, errors.New("unused") })
	key := responseFixtureKey("exclusive")
	for _, config := range []HandlerConfig{
		{Verifier: verifier, ServerKey: key, ResponseKeys: provider},
		{Verifier: verifier, ResponseSigner: &testResponseSigner{}, ResponseKeys: provider},
	} {
		if _, err := NewHandler(config, http.NotFoundHandler()); err == nil { t.Fatal("ambiguous signing profiles accepted") }
	}
	if calls != 0 { t.Fatal("constructor invoked provider while rejecting configuration") }
}
