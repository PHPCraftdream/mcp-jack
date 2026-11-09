package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
)

const cfgHTTPURL = "https://svc.example.test/mcp"
const cfgHTTPStaleAud = "https://stale.example.test"

func cfgHTTPOKBody() []byte {
	return rpcResultBody(json.RawMessage(`{"kid":"kid-1","name":"n","admin":false}`))
}

type cfgHTTPRec struct {
	headerCounts []int
	auths        []jack.RequestAuth
	bodies       [][]byte
	targets      []string
	methods      []string
}

type cfgHTTPReply struct {
	status     int
	ts         int64
	unsigned   bool
	body       []byte
	signedBody []byte
}

func cfgHTTPKeys(t *testing.T) ([]byte, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return pub, priv
}

func cfgHTTPCountNonce(n *int) NonceSource {
	return func() ([]byte, error) {
		*n++
		return bytes.Repeat([]byte{byte(*n)}, 16), nil
	}
}

func cfgHTTPSpy(priv ed25519.PrivateKey, pub []byte, rec *cfgHTTPRec, rep cfgHTTPReply) *spyBase {
	return &spyBase{fn: func(req *http.Request) (*http.Response, error) {
		var body []byte
		if req.Body != nil {
			body, _ = io.ReadAll(req.Body)
		}
		values := req.Header.Values("Jack-Auth")
		rec.headerCounts = append(rec.headerCounts, len(values))
		rec.bodies = append(rec.bodies, body)
		rec.targets = append(rec.targets, req.URL.RequestURI())
		rec.methods = append(rec.methods, req.Method)
		auth, err := jack.ParseRequestAuth(values)
		if err != nil {
			return nil, err
		}
		rec.auths = append(rec.auths, auth)
		status := rep.status
		if status == 0 {
			status = http.StatusOK
		}
		h := http.Header{}
		h.Set("Content-Type", "application/json")
		if !rep.unsigned {
			signed := rep.signedBody
			if signed == nil {
				signed = rep.body
			}
			kid := jack.KeyID(pub)
			msg := []byte(jack.ResponseSigningString(status, auth.Sig, kid, rep.ts, signed))
			sig := ed25519.Sign(priv, msg)
			h.Set("Jack-Auth", jack.FormatResponseAuth(jack.ResponseAuth{Kid: kid, TS: rep.ts, Sig: jack.EncodeBase64URL(sig)}))
		}
		return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(bytes.NewReader(rep.body)), Request: req}, nil
	}}
}

func cfgHTTPReqVerifies(rec *cfgHTTPRec, i int, signer Signer, aud string) bool {
	if i >= len(rec.auths) || i >= len(rec.bodies) {
		return false
	}
	auth := rec.auths[i]
	sig, err := jack.DecodeBase64URLFixed(auth.Sig, ed25519.SignatureSize)
	if err != nil {
		return false
	}
	msg := []byte(jack.RequestSigningString(rec.methods[i], rec.targets[i], aud, auth.Kid, auth.TS, auth.Nonce, rec.bodies[i]))
	return auth.Kid == signer.KID() && jack.Verify(signer.PublicKey(), msg, sig)
}

func cfgHTTPCfg(t *testing.T, hc *http.Client, pub []byte) Config {
	t.Helper()
	return Config{
		BaseURL:   cfgHTTPURL,
		Aud:       fixtureAud,
		Signer:    seedSignerByName(t, "alice"),
		ServerKey: pub,
		HTTP:      hc,
		Now:       fixedClock(fixtureNow),
		Window:    30 * time.Second,
	}
}

func cfgHTTPNew(t *testing.T, cfg Config) *Client {
	t.Helper()
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func cfgHTTPJackCode(t *testing.T, err error, want string) {
	t.Helper()
	var jErr *jack.Error
	if !errors.As(err, &jErr) {
		t.Fatalf("err = %T (%v), want *jack.Error", err, err)
	}
	if jErr.Code != want {
		t.Fatalf("code = %q, want %q", jErr.Code, want)
	}
}

func cfgHTTPNotAppError(t *testing.T, err error) {
	t.Helper()
	var he *HTTPError
	var re *RPCError
	var te *ToolError
	if errors.As(err, &he) || errors.As(err, &re) || errors.As(err, &te) {
		t.Fatalf("err = %T (%v), want a verification error, not a decoded application error", err, err)
	}
}

func TestConfigHTTPPlainBaseIsSignedAndVerified(t *testing.T) {
	pub, priv := cfgHTTPKeys(t)
	rec := &cfgHTTPRec{}
	spy := cfgHTTPSpy(priv, pub, rec, cfgHTTPReply{ts: fixtureNow, body: cfgHTTPOKBody()})
	cfg := cfgHTTPCfg(t, &http.Client{Timeout: 7 * time.Second, Transport: spy}, pub)
	c := cfgHTTPNew(t, cfg)

	res, err := c.WhoAmI(context.Background())
	if err != nil {
		t.Fatalf("WhoAmI: %v", err)
	}
	if res.KID != "kid-1" {
		t.Fatalf("KID = %q, want kid-1", res.KID)
	}
	if spy.calls != 1 {
		t.Fatalf("spy calls = %d, want 1", spy.calls)
	}
	if len(rec.headerCounts) != 1 || rec.headerCounts[0] != 1 {
		t.Fatalf("Jack-Auth header counts = %v, want [1]", rec.headerCounts)
	}
	if !cfgHTTPReqVerifies(rec, 0, cfg.Signer, fixtureAud) {
		t.Fatal("request signature did not verify")
	}
	if rec.auths[0].TS != fixtureNow {
		t.Fatalf("header ts = %d, want %d", rec.auths[0].TS, fixtureNow)
	}
}

func TestConfigHTTPPlainBaseRefusesUntrustedResponses(t *testing.T) {
	tampered := rpcResultBody(json.RawMessage(`{"kid":"other","name":"n","admin":false}`))
	cases := []struct {
		name string
		rep  cfgHTTPReply
		code string
	}{
		{"unsigned 200", cfgHTTPReply{unsigned: true, body: cfgHTTPOKBody()}, jack.CodeMissingAuth},
		{"signature over a different body", cfgHTTPReply{ts: fixtureNow, body: cfgHTTPOKBody(), signedBody: tampered}, jack.CodeBadSignature},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pub, priv := cfgHTTPKeys(t)
			spy := cfgHTTPSpy(priv, pub, &cfgHTTPRec{}, tc.rep)
			c := cfgHTTPNew(t, cfgHTTPCfg(t, &http.Client{Transport: spy}, pub))
			res, err := c.WhoAmI(context.Background())
			if err == nil {
				t.Fatalf("WhoAmI accepted an untrusted response: %+v", res)
			}
			cfgHTTPJackCode(t, err, tc.code)
			if res.KID != "" || res.Name != "" || res.Admin {
				t.Fatalf("structuredContent surfaced decoded fields: %+v", res)
			}
		})
	}
}

func TestConfigHTTPUnsigned401IsStatusOnly(t *testing.T) {
	pub, priv := cfgHTTPKeys(t)
	body := []byte(`{"error":{"code":"SECRETCODE","message":"SECRET MESSAGE"}}`)
	spy := cfgHTTPSpy(priv, pub, &cfgHTTPRec{}, cfgHTTPReply{status: http.StatusUnauthorized, unsigned: true, body: body})
	c := cfgHTTPNew(t, cfgHTTPCfg(t, &http.Client{Transport: spy}, pub))
	_, err := c.WhoAmI(context.Background())
	if err == nil {
		t.Fatal("WhoAmI accepted an unsigned 401")
	}
	var ue *UnauthenticatedResponseError
	if !errors.As(err, &ue) {
		t.Fatalf("err = %T (%v), want *UnauthenticatedResponseError", err, err)
	}
	if ue.Status != http.StatusUnauthorized {
		t.Fatalf("Status = %d, want 401", ue.Status)
	}
	var he *HTTPError
	if errors.As(err, &he) {
		t.Fatalf("err is *HTTPError: %v", err)
	}
	if strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("unsigned body text leaked into error: %v", err)
	}
}

func TestConfigHTTPOtherUnverifiedStatusesRefused(t *testing.T) {
	errBody := `{"error":{"code":"LEAKCODE","message":"LEAK"}}`
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{"500", http.StatusInternalServerError, errBody},
		{"403", http.StatusForbidden, errBody},
		{"404", http.StatusNotFound, errBody},
		{"200 rpc error", http.StatusOK, `{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"LEAK"}}`},
		{"200 tool error", http.StatusOK, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"LEAK"}],"isError":true}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pub, priv := cfgHTTPKeys(t)
			spy := cfgHTTPSpy(priv, pub, &cfgHTTPRec{}, cfgHTTPReply{status: tc.status, unsigned: true, body: []byte(tc.body)})
			c := cfgHTTPNew(t, cfgHTTPCfg(t, &http.Client{Transport: spy}, pub))
			_, err := c.WhoAmI(context.Background())
			if err == nil {
				t.Fatal("WhoAmI accepted an unsigned response")
			}
			cfgHTTPNotAppError(t, err)
			var ue *UnauthenticatedResponseError
			if errors.As(err, &ue) {
				t.Fatalf("err is *UnauthenticatedResponseError for status %d: %v", tc.status, err)
			}
			cfgHTTPJackCode(t, err, jack.CodeMissingAuth)
			if strings.Contains(err.Error(), "LEAK") {
				t.Fatalf("unsigned body text leaked into error: %v", err)
			}
		})
	}
}

func TestConfigHTTPDoesNotMutateCallerClient(t *testing.T) {
	pub, priv := cfgHTTPKeys(t)
	spy := cfgHTTPSpy(priv, pub, &cfgHTTPRec{}, cfgHTTPReply{ts: fixtureNow, body: cfgHTTPOKBody()})
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	redirectCalled := false
	caller := &http.Client{
		Timeout:   7 * time.Second,
		Jar:       jar,
		Transport: spy,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			redirectCalled = true
			return nil
		},
	}
	cfg := cfgHTTPCfg(t, caller, pub)
	c := cfgHTTPNew(t, cfg)
	if _, err := c.WhoAmI(context.Background()); err != nil {
		t.Fatalf("WhoAmI: %v", err)
	}

	if caller.Transport != http.RoundTripper(spy) {
		t.Fatal("caller Transport was replaced")
	}
	if caller.Timeout != 7*time.Second {
		t.Fatalf("caller Timeout = %v, want 7s", caller.Timeout)
	}
	if caller.Jar != http.CookieJar(jar) {
		t.Fatal("caller Jar was changed")
	}
	if caller.CheckRedirect == nil {
		t.Fatal("caller CheckRedirect was cleared")
	}
	if redirectCalled {
		t.Fatal("caller CheckRedirect was invoked")
	}
	if c.hc == caller {
		t.Fatal("client uses the caller's *http.Client")
	}
	if c.hc.Timeout != 7*time.Second {
		t.Fatalf("copy Timeout = %v, want 7s", c.hc.Timeout)
	}
	if c.hc.Jar != http.CookieJar(jar) {
		t.Fatal("copy lost the caller's Jar")
	}
	if c.hc.CheckRedirect == nil || c.hc.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
		t.Fatal("copy CheckRedirect is not no-follow")
	}
	if redirectCalled {
		t.Fatal("caller CheckRedirect was invoked through the copy")
	}
	tr, ok := c.hc.Transport.(*Transport)
	if !ok || tr == nil {
		t.Fatalf("copy Transport = %T, want *Transport", c.hc.Transport)
	}
	if tr.Base != http.RoundTripper(spy) {
		t.Fatalf("copy Transport.Base = %v, want the caller's spy", tr.Base)
	}
	if tr.Aud != cfg.Aud || tr.Signer != cfg.Signer || !bytes.Equal(tr.ServerKey, cfg.ServerKey) {
		t.Fatal("copy Transport Aud/Signer/ServerKey differ from Config")
	}
}

func TestConfigHTTPDoesNotMutateCallerTransport(t *testing.T) {
	pub, priv := cfgHTTPKeys(t)
	stalePub, _ := cfgHTTPKeys(t)
	staleSigner := seedSignerByName(t, "newbie")
	spy := cfgHTTPSpy(priv, pub, &cfgHTTPRec{}, cfgHTTPReply{ts: fixtureNow + 5, body: cfgHTTPOKBody()})
	nonces := 0
	orig := &Transport{
		Base:      spy,
		Aud:       cfgHTTPStaleAud,
		Signer:    staleSigner,
		ServerKey: stalePub,
		Now:       fixedClock(fixtureNow + 5),
		Nonce:     cfgHTTPCountNonce(&nonces),
		Window:    11 * time.Second,
	}
	callerHC := NewHTTPClient(orig)
	cfg := cfgHTTPCfg(t, callerHC, pub)
	cfg.Now = nil
	cfg.Window = 0

	assertUnchanged := func(stage string) {
		t.Helper()
		if callerHC.Transport != http.RoundTripper(orig) {
			t.Fatalf("%s: caller http.Client.Transport replaced", stage)
		}
		if orig.Base != http.RoundTripper(spy) || orig.Aud != cfgHTTPStaleAud || orig.Signer != Signer(staleSigner) || !bytes.Equal(orig.ServerKey, stalePub) {
			t.Fatalf("%s: caller Transport Base/Aud/Signer/ServerKey mutated", stage)
		}
		if orig.Now == nil || orig.Now().Unix() != fixtureNow+5 || orig.Nonce == nil || orig.Window != 11*time.Second {
			t.Fatalf("%s: caller Transport Now/Nonce/Window mutated", stage)
		}
	}

	c := cfgHTTPNew(t, cfg)
	assertUnchanged("after NewClient")
	if tr, ok := c.hc.Transport.(*Transport); !ok || tr == orig {
		t.Fatalf("client Transport = %T, want a new *Transport", c.hc.Transport)
	}
	if _, err := c.WhoAmI(context.Background()); err != nil {
		t.Fatalf("WhoAmI: %v", err)
	}
	assertUnchanged("after call")
}

func TestConfigHTTPPrewrappedChainCollapsesToConfig(t *testing.T) {
	for _, tc := range []struct {
		name  string
		depth int
	}{{"single", 1}, {"nested 2", 2}, {"nested 4", 4}} {
		t.Run(tc.name, func(t *testing.T) {
			pub, priv := cfgHTTPKeys(t)
			stalePub, _ := cfgHTTPKeys(t)
			staleSigner := seedSignerByName(t, "newbie")
			rec := &cfgHTTPRec{}
			spy := cfgHTTPSpy(priv, pub, rec, cfgHTTPReply{ts: fixtureNow, body: cfgHTTPOKBody()})
			innerNonces, outerNonces := 0, 0
			var next http.RoundTripper = spy
			for i := 1; i < tc.depth; i++ {
				next = &Transport{Base: next, Aud: cfgHTTPStaleAud, Signer: staleSigner, ServerKey: stalePub, Nonce: cfgHTTPCountNonce(&innerNonces)}
			}
			outer := &Transport{
				Base:      next,
				Aud:       cfgHTTPStaleAud,
				Signer:    staleSigner,
				ServerKey: stalePub,
				Now:       fixedClock(fixtureNow),
				Nonce:     cfgHTTPCountNonce(&outerNonces),
				Window:    30 * time.Second,
			}
			cfg := cfgHTTPCfg(t, NewHTTPClient(outer), pub)
			cfg.Now = nil
			cfg.Window = 0
			c := cfgHTTPNew(t, cfg)
			if _, err := c.WhoAmI(context.Background()); err != nil {
				t.Fatalf("WhoAmI: %v", err)
			}
			if spy.calls != 1 {
				t.Fatalf("spy calls = %d, want 1", spy.calls)
			}
			if len(rec.headerCounts) != 1 || rec.headerCounts[0] != 1 {
				t.Fatalf("Jack-Auth header counts = %v, want [1]", rec.headerCounts)
			}
			if !cfgHTTPReqVerifies(rec, 0, cfg.Signer, fixtureAud) {
				t.Fatal("request signature does not verify under Config Signer/Aud")
			}
			if outerNonces != 1 || innerNonces != 0 {
				t.Fatalf("nonce calls outer=%d inner=%d, want 1 and 0", outerNonces, innerNonces)
			}
		})
	}
}

func TestConfigHTTPPrecedenceNowAndNonce(t *testing.T) {
	const a = fixtureNow
	const b = fixtureNow + 100
	cases := []struct {
		name     string
		cfgNow   func() time.Time
		cfgNonce bool
		respTS   int64
		wantTS   int64
		wantErr  bool
		wantN1   int
		wantN2   int
	}{
		{"config Now and Nonce win", fixedClock(b), true, b, b, false, 0, 1},
		{"config Now verifies response", fixedClock(b), true, a, b, true, 0, 1},
		{"inherited Now and Nonce", nil, false, a, a, false, 1, 0},
		{"inherited Now verifies response", nil, false, b, a, true, 1, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pub, priv := cfgHTTPKeys(t)
			rec := &cfgHTTPRec{}
			spy := cfgHTTPSpy(priv, pub, rec, cfgHTTPReply{ts: tc.respTS, body: cfgHTTPOKBody()})
			n1, n2 := 0, 0
			tr := &Transport{Base: spy, Now: fixedClock(a), Window: 30 * time.Second, Nonce: cfgHTTPCountNonce(&n1)}
			cfg := cfgHTTPCfg(t, NewHTTPClient(tr), pub)
			cfg.Now = tc.cfgNow
			cfg.Window = 0
			if tc.cfgNonce {
				cfg.Nonce = cfgHTTPCountNonce(&n2)
			}
			c := cfgHTTPNew(t, cfg)
			if got := c.now().Unix(); got != tc.wantTS {
				t.Fatalf("Client.now = %d, want %d", got, tc.wantTS)
			}
			_, err := c.WhoAmI(context.Background())
			if tc.wantErr {
				if err == nil {
					t.Fatal("WhoAmI accepted a response outside the effective clock window")
				}
				cfgHTTPJackCode(t, err, jack.CodeTimestampOutOfWindow)
			} else if err != nil {
				t.Fatalf("WhoAmI: %v", err)
			}
			if len(rec.auths) != 1 || rec.auths[0].TS != tc.wantTS {
				t.Fatalf("request auths = %+v, want one with ts %d", rec.auths, tc.wantTS)
			}
			if n1 != tc.wantN1 || n2 != tc.wantN2 {
				t.Fatalf("nonce calls n1=%d n2=%d, want %d and %d", n1, n2, tc.wantN1, tc.wantN2)
			}
		})
	}
}

func TestConfigHTTPPrecedenceWindow(t *testing.T) {
	cases := []struct {
		name  string
		tnWin time.Duration
		cfWin time.Duration
		ok    bool
	}{
		{"config window wider wins", 5 * time.Second, 60 * time.Second, true},
		{"config window narrower wins", 60 * time.Second, 5 * time.Second, false},
		{"inherited narrow window", 5 * time.Second, 0, false},
		{"inherited wide window", 60 * time.Second, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pub, priv := cfgHTTPKeys(t)
			spy := cfgHTTPSpy(priv, pub, &cfgHTTPRec{}, cfgHTTPReply{ts: fixtureNow + 30, body: cfgHTTPOKBody()})
			tr := &Transport{Base: spy, Window: tc.tnWin}
			cfg := cfgHTTPCfg(t, NewHTTPClient(tr), pub)
			cfg.Window = tc.cfWin
			c := cfgHTTPNew(t, cfg)
			_, err := c.WhoAmI(context.Background())
			if tc.ok {
				if err != nil {
					t.Fatalf("WhoAmI: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("WhoAmI accepted a response outside the effective window")
			}
			cfgHTTPJackCode(t, err, jack.CodeTimestampOutOfWindow)
		})
	}
}

func cfgHTTPProofOK(t *testing.T, body []byte, aud, signerKid string, newSigner Signer, ts int64) bool {
	t.Helper()
	var req jsonrpcRequest
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("request body does not decode: %v", err)
	}
	var args map[string]any
	if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
		t.Fatalf("arguments do not decode: %v", err)
	}
	proof, ok := args["proof"].(string)
	if !ok {
		t.Fatalf("arguments[proof] = %v, want a string", args["proof"])
	}
	proofBytes, err := jack.DecodeBase64URLFixed(proof, 64)
	if err != nil {
		t.Fatalf("DecodeBase64URLFixed(proof): %v", err)
	}
	msg := []byte(jack.RotateProofString(aud, signerKid, newSigner.KID(), ts))
	return jack.Verify(newSigner.PublicKey(), msg, proofBytes)
}

func TestConfigHTTPRotateKeyPinsTimestampAndFreshVerification(t *testing.T) {
	variants := []struct {
		name  string
		build func(spy *spyBase, now func() time.Time) (*http.Client, func() time.Time)
	}{
		{"config Now", func(spy *spyBase, now func() time.Time) (*http.Client, func() time.Time) {
			return &http.Client{Transport: spy}, now
		}},
		{"prewrapped Now", func(spy *spyBase, now func() time.Time) (*http.Client, func() time.Time) {
			return NewHTTPClient(&Transport{Base: spy, Now: now}), nil
		}},
	}
	replies := []struct {
		name   string
		respTS int64
		ok     bool
	}{
		{"fresh response", fixtureNow + 3600, true},
		{"stale response", fixtureNow, false},
	}
	for _, v := range variants {
		for _, r := range replies {
			t.Run(v.name+"/"+r.name, func(t *testing.T) {
				pub, priv := cfgHTTPKeys(t)
				rec := &cfgHTTPRec{}
				spy := cfgHTTPSpy(priv, pub, rec, cfgHTTPReply{ts: r.respTS, body: cfgHTTPOKBody()})
				hc, cfgNow := v.build(spy, delayedClock())
				cfg := cfgHTTPCfg(t, hc, pub)
				cfg.Now = cfgNow
				c := cfgHTTPNew(t, cfg)
				newbie := seedSignerByName(t, "newbie")

				res, err := c.RotateKey(context.Background(), newbie)
				if r.ok {
					if err != nil {
						t.Fatalf("RotateKey: %v", err)
					}
					if res.KID != "kid-1" {
						t.Fatalf("KID = %q, want kid-1", res.KID)
					}
				} else {
					if err == nil {
						t.Fatalf("RotateKey accepted a stale response: %+v", res)
					}
					cfgHTTPJackCode(t, err, jack.CodeTimestampOutOfWindow)
				}
				if len(rec.auths) != 1 {
					t.Fatalf("spy saw %d requests, want 1", len(rec.auths))
				}
				if rec.auths[0].Kid != cfg.Signer.KID() {
					t.Fatalf("header kid = %q, want current signer %q", rec.auths[0].Kid, cfg.Signer.KID())
				}
				if rec.auths[0].TS != fixtureNow {
					t.Fatalf("header ts = %d, want %d", rec.auths[0].TS, fixtureNow)
				}
				if !cfgHTTPReqVerifies(rec, 0, cfg.Signer, fixtureAud) {
					t.Fatal("request signature does not verify under the current signer")
				}
				if !cfgHTTPProofOK(t, rec.bodies[0], fixtureAud, cfg.Signer.KID(), newbie, fixtureNow) {
					t.Fatal("rotate proof ts differs from header ts")
				}
			})
		}
	}
}

func TestConfigHTTPEnrollSignedByNewSigner(t *testing.T) {
	pub, priv := cfgHTTPKeys(t)
	rec := &cfgHTTPRec{}
	spy := cfgHTTPSpy(priv, pub, rec, cfgHTTPReply{ts: fixtureNow, body: cfgHTTPOKBody()})
	cfg := cfgHTTPCfg(t, &http.Client{Transport: spy}, pub)
	c := cfgHTTPNew(t, cfg)
	newbie := seedSignerByName(t, "newbie")

	res, err := c.Enroll(context.Background(), "code", "name", newbie)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if res.KID != "kid-1" {
		t.Fatalf("KID = %q, want kid-1", res.KID)
	}
	if len(rec.auths) != 1 || rec.auths[0].Kid != newbie.KID() {
		t.Fatalf("request auths = %+v, want one with kid %q", rec.auths, newbie.KID())
	}
	if !cfgHTTPReqVerifies(rec, 0, newbie, fixtureAud) {
		t.Fatal("enroll request signature does not verify under the new signer")
	}
}

func TestConfigHTTPPermissiveCheckRedirectStillRefused(t *testing.T) {
	const location = "https://other.example.test/mcp"
	variants := []struct {
		name  string
		build func(rt http.RoundTripper, cr func(*http.Request, []*http.Request) error) *http.Client
	}{
		{"plain base", func(rt http.RoundTripper, cr func(*http.Request, []*http.Request) error) *http.Client {
			return &http.Client{Transport: rt, CheckRedirect: cr}
		}},
		{"prewrapped", func(rt http.RoundTripper, cr func(*http.Request, []*http.Request) error) *http.Client {
			return &http.Client{Transport: &Transport{Base: rt}, CheckRedirect: cr}
		}},
	}
	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			pub, _ := cfgHTTPKeys(t)
			hits := map[string]int{}
			spy := &spyBase{fn: func(req *http.Request) (*http.Response, error) {
				hits[req.URL.String()]++
				h := http.Header{}
				status := http.StatusOK
				if req.URL.String() == cfgHTTPURL {
					status = http.StatusFound
					h.Set("Location", location)
				}
				return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader("{}")), Request: req}, nil
			}}
			crCalled := false
			hc := v.build(spy, func(*http.Request, []*http.Request) error {
				crCalled = true
				return nil
			})
			c := cfgHTTPNew(t, cfgHTTPCfg(t, hc, pub))
			_, err := c.WhoAmI(context.Background())
			if !errors.Is(err, ErrRedirectRefused) {
				t.Fatalf("err = %v, want ErrRedirectRefused", err)
			}
			if hits[cfgHTTPURL] != 1 || hits[location] != 0 || spy.calls != 1 {
				t.Fatalf("hits = %v, spy calls = %d, want origin once and Location never", hits, spy.calls)
			}
			if crCalled {
				t.Fatal("caller's permissive CheckRedirect was invoked")
			}
		})
	}
}

func TestConfigHTTPLoopbackControls(t *testing.T) {
	srv := newTestServer(t)
	srv.Handle = func(w http.ResponseWriter, auth jack.RequestAuth, _ []byte) {
		srv.writeSignedJSON(w, auth, http.StatusOK, rpcResultBody(json.RawMessage(`{"kid":"`+auth.Kid+`","name":"n","admin":false}`)))
	}
	cases := []struct {
		name string
		hc   *http.Client
	}{
		{"nil HTTP", nil},
		{"empty http.Client", &http.Client{}},
		{"prewrapped nil Base", NewHTTPClient(&Transport{Base: nil})},
		{"prewrapped zero Transport", &http.Client{Transport: &Transport{}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := cfgHTTPCfg(t, tc.hc, srv.Pub)
			cfg.BaseURL = srv.URL + "/mcp"
			c := cfgHTTPNew(t, cfg)
			res, err := c.WhoAmI(context.Background())
			if err != nil {
				t.Fatalf("WhoAmI: %v", err)
			}
			if res.KID != cfg.Signer.KID() {
				t.Fatalf("KID = %q, want %q", res.KID, cfg.Signer.KID())
			}
		})
	}
}

func cfgHTTPNewClientErr(t *testing.T, cfg Config) error {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		_, err := NewClient(cfg)
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("NewClient did not return")
		return nil
	}
}

func cfgHTTPChain(n int, base http.RoundTripper) *Transport {
	next := base
	var top *Transport
	for i := 0; i < n; i++ {
		top = &Transport{Base: next}
		next = top
	}
	return top
}

func TestConfigHTTPChainShapeErrors(t *testing.T) {
	cases := []struct {
		name  string
		build func(spy *spyBase) *http.Client
	}{
		{"cycle of two", func(*spyBase) *http.Client {
			a, b := &Transport{}, &Transport{}
			a.Base = b
			b.Base = a
			return &http.Client{Transport: a}
		}},
		{"self cycle", func(*spyBase) *http.Client {
			a := &Transport{}
			a.Base = a
			return &http.Client{Transport: a}
		}},
		{"typed nil Transport", func(*spyBase) *http.Client {
			var tn *Transport
			return &http.Client{Transport: tn}
		}},
		{"typed nil inside chain", func(*spyBase) *http.Client {
			return &http.Client{Transport: &Transport{Base: (*Transport)(nil)}}
		}},
		{"chain of 17", func(spy *spyBase) *http.Client {
			return &http.Client{Transport: cfgHTTPChain(17, spy)}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pub, priv := cfgHTTPKeys(t)
			spy := cfgHTTPSpy(priv, pub, &cfgHTTPRec{}, cfgHTTPReply{ts: fixtureNow, body: cfgHTTPOKBody()})
			err := cfgHTTPNewClientErr(t, cfgHTTPCfg(t, tc.build(spy), pub))
			if err == nil {
				t.Fatal("NewClient accepted a malformed transport chain")
			}
			if !strings.Contains(err.Error(), "jack client") {
				t.Fatalf("err = %v, want it to mention \"jack client\"", err)
			}
			if spy.calls != 0 {
				t.Fatalf("spy calls = %d, want 0", spy.calls)
			}
		})
	}
}

func TestConfigHTTPChainOfFiveAccepted(t *testing.T) {
	pub, priv := cfgHTTPKeys(t)
	rec := &cfgHTTPRec{}
	spy := cfgHTTPSpy(priv, pub, rec, cfgHTTPReply{ts: fixtureNow, body: cfgHTTPOKBody()})
	cfg := cfgHTTPCfg(t, &http.Client{Transport: cfgHTTPChain(5, spy)}, pub)
	c := cfgHTTPNew(t, cfg)
	if _, err := c.WhoAmI(context.Background()); err != nil {
		t.Fatalf("WhoAmI: %v", err)
	}
	if spy.calls != 1 || len(rec.headerCounts) != 1 || rec.headerCounts[0] != 1 {
		t.Fatalf("spy calls = %d, header counts = %v, want one signed call", spy.calls, rec.headerCounts)
	}
}
