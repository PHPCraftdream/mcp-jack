package transport

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
	nonceimpl "github.com/PHPCraftdream/mcp-jack/server/internal/nonce"
	stateimpl "github.com/PHPCraftdream/mcp-jack/server/internal/state"
	verify "github.com/PHPCraftdream/mcp-jack/server/internal/verify"
)

func TestOpaqueResponseSignerCapturesPublicIdentityWithoutPrivateExport(t *testing.T) {
	key := responseFixtureKey("server")
	public := key.Public().(ed25519.PublicKey)
	calls := 0
	provider := &testResponseSigner{public: public, sign: func(message []byte) ([]byte, error) {
		calls++
		return ed25519.Sign(key, message), nil
	}}
	verifier, err := verify.NewVerifier(verify.Config{Aud: "test", State: stateimpl.NewMemoryState(), Nonces: nonceimpl.NewNonceStore()})
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := NewHandler(HandlerConfig{Verifier: verifier, ResponseSigner: provider}, http.NotFoundHandler())
	if err != nil {
		t.Fatal(err)
	}
	handler := wrapped.(*handler)
	if len(handler.key) != 0 || handler.signer == nil || calls != 0 {
		t.Fatal("constructor requested private key or signed prematurely")
	}
	clear(public)
	if _, err := responseSignature(provider, handler.public, "exact public response message"); err != nil || calls != 1 {
		t.Fatalf("provider-owned public buffer changed captured identity: %v", err)
	}
	if _, err := NewHandler(HandlerConfig{Verifier: verifier, ServerKey: key, ResponseSigner: provider}, http.NotFoundHandler()); err == nil {
		t.Fatal("ambiguous signing profiles accepted")
	}
}

func TestOpaqueResponseSignerRejectsBadPublicIdentityAndProviderPanic(t *testing.T) {
	identity := make([]byte, ed25519.PublicKeySize)
	identity[0] = 1
	for _, provider := range []*testResponseSigner{
		nil, {public: nil}, {public: make([]byte, 31)}, {public: identity}, {panicPublic: true},
	} {
		if public, err := responsePublicKey(provider); !errors.Is(err, errResponseSigner) || public != nil {
			t.Fatalf("bad public identity accepted: %v", err)
		}
	}
}

func TestOpaqueResponseSignerValidatesExactMessageKeyAndProviderOutputWithoutRetry(t *testing.T) {
	key := responseFixtureKey("server")
	other := responseFixtureKey("other")
	public := key.Public().(ed25519.PublicKey)
	for name, sign := range map[string]func([]byte) ([]byte, error){
		"error":     func([]byte) ([]byte, error) { return nil, errors.New("private provider detail") },
		"panic":     func([]byte) ([]byte, error) { panic("private provider detail") },
		"nil-panic": func([]byte) ([]byte, error) { panic(nil) },
		"short":     func([]byte) ([]byte, error) { return make([]byte, 63), nil },
		"wrong-key": func(message []byte) ([]byte, error) { return ed25519.Sign(other, message), nil },
		"mutated-message": func(message []byte) ([]byte, error) {
			message[0] ^= 1
			return ed25519.Sign(key, message), nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			provider := &testResponseSigner{public: public, sign: func(message []byte) ([]byte, error) {
				calls++
				return sign(message)
			}}
			signature, err := responseSignature(provider, public, "exact immutable message")
			if !errors.Is(err, errResponseSigner) || signature != nil || calls != 1 || bytes.Contains([]byte(err.Error()), []byte("private provider detail")) {
				t.Fatalf("bad provider output accepted, leaked or retried: %v calls=%d", err, calls)
			}
		})
	}
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
		if input.Status != 200 || string(input.Body) != "application payload" {
			t.Error("provider saw wrong owned payload")
		}
		input.Body[0] ^= 1
		key := keys[index]
		signer := &testResponseSigner{public: key.Public().(ed25519.PublicKey), sign: func(message []byte) ([]byte, error) { signs++; return ed25519.Sign(key, message), nil }}
		return ResponseKeyAuthorization{Signer: signer, Timestamp: int64(100 + index), Final: func() error {
			finals++
			if recorder.Body.Len() != 0 || recorder.Header().Get("Jack-Auth") != "" {
				t.Error("wire bytes exposed before final gate")
			}
			return nil
		}, Release: func() { releases++; held = false }}, nil
	})
	handler, request, nonces := responseKeyFixture(t, provider)
	if calls != 0 {
		t.Fatal("constructor authorized a response")
	}
	bad := request(1)
	bad.URL.RawQuery = "tampered=1"
	bad.RequestURI = bad.URL.RequestURI()
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, bad)
	if recorder.Code != 401 || calls != 0 || nonces.Len() != 0 {
		t.Fatal("pre-auth request acquired response authorization")
	}
	for index := 0; index < 2; index++ {
		recorder = httptest.NewRecorder()
		r := request(byte(index + 2))
		auth, err := jack.ParseRequestAuth(r.Header.Values("Jack-Auth"))
		if err != nil {
			t.Fatal(err)
		}
		handler.ServeHTTP(leaseWireRecorder{ResponseRecorder: recorder, held: &held, t: t}, r)
		if recorder.Code != 200 || string(recorder.Body.Bytes()) != "application payload" || held {
			t.Fatal("authorized payload/lease ownership changed")
		}
		if err := client.VerifyResponse(keys[index].Public().(ed25519.PublicKey), 200, recorder.Header().Values("Jack-Auth"), auth.Sig, recorder.Body.Bytes(), time.Unix(100, 0), 30*time.Second); err != nil {
			t.Fatal("selected lease identity failed exact signature")
		}
	}
	if calls != 2 || signs != 2 || finals != 2 || releases != 2 || nonces.Len() != 2 {
		t.Fatal("response authorization/sign/final/release repeated")
	}
}

func TestResponseKeyAuthorizationFinalRefusalNeverExposesPayloadOrRetries(t *testing.T) {
	for _, failure := range []string{"acquire-error", "acquire-panic", "bad-public", "bad-signature", "sign-panic", "missing-final", "missing-release", "negative-time", "final-error", "final-panic"} {
		t.Run(failure, func(t *testing.T) {
			calls, signs, finals, releases := 0, 0, 0, 0
			key := responseFixtureKey("leased-fault")
			provider := responseKeyProviderFunc(func(ResponseKeyRequest) (ResponseKeyAuthorization, error) {
				calls++
				if failure == "acquire-panic" {
					panic("private provider detail")
				}
				signer := &testResponseSigner{public: key.Public().(ed25519.PublicKey), sign: func(message []byte) ([]byte, error) {
					signs++
					if failure == "sign-panic" {
						panic("private provider detail")
					}
					if failure == "bad-signature" {
						return make([]byte, 64), nil
					}
					return ed25519.Sign(key, message), nil
				}}
				if failure == "bad-public" {
					signer.public = make([]byte, 31)
				}
				authorization := ResponseKeyAuthorization{Signer: signer, Timestamp: 100, Final: func() error {
					finals++
					if failure == "final-panic" {
						panic("private provider detail")
					}
					return errors.New("private provider detail")
				}, Release: func() { releases++ }}
				if failure == "missing-final" {
					authorization.Final = nil
				}
				if failure == "missing-release" {
					authorization.Release = nil
				}
				if failure == "negative-time" {
					authorization.Timestamp = -1
				}
				if failure == "acquire-error" {
					return authorization, errors.New("private provider detail")
				}
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
			case "bad-signature", "sign-panic":
				wantSigns = 1
			case "final-error", "final-panic":
				wantSigns, wantFinals = 1, 1
			}
			if signs != wantSigns || finals != wantFinals {
				t.Fatal("invalid authorization reached a later phase")
			}
			wantRelease := 1
			if failure == "acquire-panic" || failure == "missing-release" {
				wantRelease = 0
			}
			if releases != wantRelease {
				t.Fatal("authorization lease release lost or repeated")
			}
			replay := httptest.NewRecorder()
			handler.ServeHTTP(replay, request(1))
			if replay.Code != 401 || calls != 1 {
				t.Fatal("consumed nonce allowed handler or signer redelivery")
			}
		})
	}
}

func TestResponseKeyProfilesAreExplicitlyExclusive(t *testing.T) {
	verifier, err := verify.NewVerifier(verify.Config{Aud: "public", State: stateimpl.NewMemoryState(), Nonces: nonceimpl.NewNonceStore()})
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	provider := responseKeyProviderFunc(func(ResponseKeyRequest) (ResponseKeyAuthorization, error) {
		calls++
		return ResponseKeyAuthorization{}, errors.New("unused")
	})
	key := responseFixtureKey("exclusive")
	for _, config := range []HandlerConfig{
		{Verifier: verifier, ServerKey: key, ResponseKeys: provider},
		{Verifier: verifier, ResponseSigner: &testResponseSigner{}, ResponseKeys: provider},
	} {
		if _, err := NewHandler(config, http.NotFoundHandler()); err == nil {
			t.Fatal("ambiguous signing profiles accepted")
		}
	}
	if calls != 0 {
		t.Fatal("constructor invoked provider while rejecting configuration")
	}
}
