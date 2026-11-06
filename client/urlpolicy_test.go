package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	spec "github.com/PHPCraftdream/mcp-jack/spec"
)

// roundTripFunc adapts a function to http.RoundTripper.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// errSpyBase is the canned error returned by the spy base for allowed URLs,
// so no network is needed.
var errSpyBase = errors.New("spy base: canned error")

// spyBase counts calls and records the last request.
type spyBase struct {
	calls int
	last  *http.Request
	fn    func(*http.Request) (*http.Response, error)
}

func (s *spyBase) RoundTrip(r *http.Request) (*http.Response, error) {
	s.calls++
	s.last = r
	if s.fn != nil {
		return s.fn(r)
	}
	return nil, errSpyBase
}

// spySigner counts every use of the wrapped signer.
type spySigner struct {
	inner *InMemorySigner
	calls int
}

func (s *spySigner) Sign(m []byte) ([]byte, error) { s.calls++; return s.inner.Sign(m) }
func (s *spySigner) PublicKey() []byte             { s.calls++; return s.inner.PublicKey() }
func (s *spySigner) KID() string                   { s.calls++; return s.inner.KID() }

// closeSpyBody records Close.
type closeSpyBody struct {
	io.Reader
	closed bool
	reads  int
}

func (b *closeSpyBody) Read(p []byte) (int, error) { b.reads++; return b.Reader.Read(p) }
func (b *closeSpyBody) Close() error               { b.closed = true; return nil }

// Fixture-driven URL policy tests (spec/fixtures/client-url-policy.json).
//
// Entry paths exercised for every row (name, url, allow, optional
// parse_reject):
//
//   - policy fn: checkDestination(raw) must agree with allow.
//   - NewClient: allowed rows must be ACCEPTED (err == nil); refused rows must
//     fail with a policy error. There is no parser-dependent leniency.
//   - validateProfile, LoadProfile, NewClientFromProfile: same expectations as
//     NewClient (a profile with a valid key from newPolicyProfile is used).
//   - parse_reject (only the row listed for "go"): the policy ACCEPTS the
//     row but net/url rejects it, so the four constructors/loaders above must
//     fail with the generic "must be an absolute http/https URL" error and
//     NOT with a policy error; http.NewRequest cannot build it either.
//   - Transport.RoundTrip (TestTransportRoundTripURLPolicyFixture), one
//     explicit bucket per row, no skips:
//     A: http.NewRequest fails. checkDestination(raw) must refuse the raw
//     string, or the row must be allow=true with parse_reject for go.
//     B: NewRequest succeeds and checkRequestDestination(req) agrees with
//     allow. Refused rows give a policy error with zero signer and zero base
//     calls; allowed rows reach the spy base exactly once (errSpyBase).
//     C: NewRequest succeeds, the transport view ACCEPTS but the fixture
//     refuses (the Go parser percent-decoded or dropped/escaped bytes, so
//     RoundTrip cannot see the raw string). The raw string must be refused
//     by checkDestination (pre-parser rejection), the rebuilt transport-view
//     destination must itself pass the policy and, for http rows, the parsed
//     host must be a literal canonical loopback so normalisation can only
//     land on a loopback address. allow must be false.
//     The reverse (transport refuses, fixture allows) is a test failure.

type urlPolicyCase struct {
	Name        string   `json:"name"`
	URL         string   `json:"url"`
	Allow       bool     `json:"allow"`
	ParseReject []string `json:"parse_reject"`
}

// goParseRejects reports whether the fixture row is flagged as rejected by
// Go's net/url parser although the policy accepts it.
func goParseRejects(c urlPolicyCase) bool {
	for _, p := range c.ParseReject {
		if p == "go" {
			return true
		}
	}
	return false
}

// genericParseMsg is the non-policy error text of the public constructors.
const genericParseMsg = "must be an absolute http/https URL"

func loadURLPolicyCases(t *testing.T) []urlPolicyCase {
	t.Helper()
	data, err := spec.Fixture("client-url-policy.json")
	if err != nil {
		t.Fatalf("spec.Fixture: %v", err)
	}
	var doc struct {
		Cases []urlPolicyCase `json:"cases"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("decode client-url-policy.json: %v", err)
	}
	if len(doc.Cases) == 0 {
		t.Fatal("client-url-policy.json has no cases")
	}
	seen := make(map[string]bool, len(doc.Cases))
	for _, c := range doc.Cases {
		if c.Name == "" || strings.ContainsAny(c.Name, " /\\") || seen[c.Name] {
			t.Fatalf("fixture case name %q is empty, unsanitised or duplicate", c.Name)
		}
		seen[c.Name] = true
		if len(c.ParseReject) > 0 && !c.Allow {
			t.Fatalf("fixture case %q: parse_reject only makes sense for allowed rows", c.Name)
		}
	}
	return doc.Cases
}

func isPolicyError(err error) bool {
	return errors.Is(err, errMalformedDestination) || errors.Is(err, errInsecureDestination)
}

func newPolicyProfile(t *testing.T, rawURL string) (Profile, []byte) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return Profile{URL: rawURL, Aud: fixtureAud, ServerPublicKey: jack.EncodeBase64URL(pub)}, pub
}

func TestCheckDestinationFixture(t *testing.T) {
	for _, c := range loadURLPolicyCases(t) {
		t.Run(c.Name, func(t *testing.T) {
			err := checkDestination(c.URL)
			if c.Allow && err != nil {
				t.Fatalf("checkDestination(%q) = %v, want allow", c.URL, err)
			}
			if !c.Allow && err == nil {
				t.Fatalf("checkDestination(%q) = nil, want refusal", c.URL)
			}
		})
	}
}

// TestNewClientURLPolicyFixture runs NewClient, validateProfile, LoadProfile
// and NewClientFromProfile for every row.
func TestNewClientURLPolicyFixture(t *testing.T) {
	for _, c := range loadURLPolicyCases(t) {
		t.Run(c.Name, func(t *testing.T) {
			p, pub := newPolicyProfile(t, c.URL)
			doc, merr := json.Marshal(p)
			if merr != nil {
				t.Fatalf("marshal profile: %v", merr)
			}
			_, errNew := NewClient(Config{
				BaseURL:   c.URL,
				Aud:       fixtureAud,
				Signer:    seedSignerByName(t, "alice"),
				ServerKey: pub,
			})
			errValidate := validateProfile(p)
			_, errLoad := LoadProfile(bytes.NewReader(doc))
			_, errFromProfile := NewClientFromProfile(p, seedSignerByName(t, "alice"), nil)

			paths := []struct {
				name string
				err  error
			}{
				{"NewClient", errNew},
				{"validateProfile", errValidate},
				{"LoadProfile", errLoad},
				{"NewClientFromProfile", errFromProfile},
			}
			for _, e := range paths {
				switch {
				case !c.Allow:
					if e.err == nil || !isPolicyError(e.err) {
						t.Fatalf("%s(%q) = %v, want policy refusal", e.name, c.URL, e.err)
					}
				case goParseRejects(c):
					if e.err == nil || isPolicyError(e.err) || !strings.Contains(e.err.Error(), genericParseMsg) {
						t.Fatalf("%s(%q) = %v, want the generic %q error (parse_reject go), not a policy error", e.name, c.URL, e.err, genericParseMsg)
					}
				default:
					if e.err != nil {
						t.Fatalf("%s(%q) = %v, want success", e.name, c.URL, e.err)
					}
				}
			}
		})
	}
}

// transportViewDestination rebuilds the destination string the Transport
// checks (same construction as checkRequestDestination).
func transportViewDestination(u *url.URL) string {
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	raw := u.Scheme + "://" + u.Host + path
	if u.ForceQuery || u.RawQuery != "" {
		raw += "?" + u.RawQuery
	}
	return raw
}

func TestTransportRoundTripURLPolicyFixture(t *testing.T) {
	cases := loadURLPolicyCases(t)
	var bucketA, bucketB, bucketC int
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			req, nerr := http.NewRequest(http.MethodPost, c.URL, strings.NewReader(`{}`))
			if nerr != nil {
				// Bucket A.
				if checkDestination(c.URL) == nil && !(c.Allow && goParseRejects(c)) {
					t.Fatalf("http.NewRequest(%q) failed (%v) but the row is neither refused by checkDestination nor allow+parse_reject go", c.URL, nerr)
				}
				bucketA++
				return
			}
			if c.Allow && goParseRejects(c) {
				t.Fatalf("row %q is flagged parse_reject go but http.NewRequest accepted it", c.URL)
			}
			terr := checkRequestDestination(req)
			transportAllows := terr == nil
			switch {
			case transportAllows == c.Allow:
				// Bucket B.
				bucketB++
				signer := &spySigner{inner: seedSignerByName(t, "alice")}
				base := &spyBase{}
				tr := &Transport{Base: base, Aud: fixtureAud, Signer: signer, ServerKey: make([]byte, 32), Now: fixedClock(fixtureNow)}
				_, err := tr.RoundTrip(req)
				if c.Allow {
					if !errors.Is(err, errSpyBase) {
						t.Fatalf("RoundTrip(%q) = %v, want the spy base error", c.URL, err)
					}
					if base.calls != 1 {
						t.Fatalf("base calls = %d, want 1", base.calls)
					}
					return
				}
				if err == nil || !isPolicyError(err) {
					t.Fatalf("RoundTrip(%q) = %v, want policy refusal", c.URL, err)
				}
				if signer.calls != 0 || base.calls != 0 {
					t.Fatalf("refused request reached signer (%d) or base (%d)", signer.calls, base.calls)
				}
			case transportAllows && !c.Allow:
				// Bucket C: the parser normalised the offending bytes away.
				bucketC++
				if checkDestination(c.URL) == nil {
					t.Fatalf("row %q: raw string is not refused by checkDestination", c.URL)
				}
				view := transportViewDestination(req.URL)
				if err := checkDestination(view); err != nil {
					t.Fatalf("row %q: transport view %q = %v, want accepted", c.URL, view, err)
				}
				if req.URL.Scheme == "http" {
					host := req.URL.Hostname()
					if !isLoopbackIPv4(host) && host != "::1" {
						t.Fatalf("row %q: http transport view host %q is not a canonical loopback literal", c.URL, host)
					}
				}
			default:
				t.Fatalf("row %q: transport refuses (%v) but the fixture allows it", c.URL, terr)
			}
		})
	}
	t.Logf("RoundTrip buckets: A(NewRequest fails)=%d B(agree)=%d C(parser-normalised)=%d total=%d", bucketA, bucketB, bucketC, len(cases))
	if bucketA+bucketB+bucketC != len(cases) {
		t.Fatalf("buckets A+B+C = %d, want %d", bucketA+bucketB+bucketC, len(cases))
	}
	if bucketB*2 < len(cases) {
		t.Fatalf("bucket B = %d of %d rows, want at least half", bucketB, len(cases))
	}
}

func TestTransportRefusesBypassShapes(t *testing.T) {
	newTr := func(t *testing.T) (*Transport, *spySigner, *spyBase) {
		signer := &spySigner{inner: seedSignerByName(t, "alice")}
		base := &spyBase{}
		return &Transport{Base: base, Aud: fixtureAud, Signer: signer, ServerKey: make([]byte, 32), Now: fixedClock(fixtureNow)}, signer, base
	}
	mk := func(t *testing.T, raw string, body io.Reader) *http.Request {
		req, err := http.NewRequest(http.MethodPost, raw, body)
		if err != nil {
			t.Fatalf("http.NewRequest: %v", err)
		}
		return req
	}
	check := func(t *testing.T, tr *Transport, signer *spySigner, base *spyBase, req *http.Request, body *closeSpyBody) {
		t.Helper()
		resp, err := tr.RoundTrip(req)
		if err == nil || !isPolicyError(err) {
			t.Fatalf("RoundTrip err = %v, want policy refusal", err)
		}
		if resp != nil {
			t.Fatalf("resp = %+v, want nil", resp)
		}
		if signer.calls != 0 || base.calls != 0 {
			t.Fatalf("refused request reached signer (%d) or base (%d)", signer.calls, base.calls)
		}
		if body != nil && (!body.closed || body.reads != 0) {
			t.Fatalf("body closed=%v reads=%d, want closed and unread", body.closed, body.reads)
		}
	}

	t.Run("remote-http", func(t *testing.T) {
		tr, signer, base := newTr(t)
		body := &closeSpyBody{Reader: strings.NewReader("{}")}
		check(t, tr, signer, base, mk(t, "http://svc.example.test/mcp", body), body)
	})
	t.Run("userinfo", func(t *testing.T) {
		tr, signer, base := newTr(t)
		req := mk(t, "https://svc.example.test/mcp", nil)
		req.URL.User = url.UserPassword("u", "p")
		check(t, tr, signer, base, req, nil)
	})
	t.Run("opaque", func(t *testing.T) {
		tr, signer, base := newTr(t)
		req := mk(t, "https://svc.example.test/mcp", nil)
		req.URL.Opaque = "//svc.example.test/mcp"
		check(t, tr, signer, base, req, nil)
	})
	t.Run("nil-url", func(t *testing.T) {
		tr, signer, base := newTr(t)
		body := &closeSpyBody{Reader: strings.NewReader("{}")}
		req := &http.Request{Method: http.MethodPost, Header: http.Header{}, Body: body}
		check(t, tr, signer, base, req, body)
	})
	t.Run("nil-request", func(t *testing.T) {
		tr, signer, base := newTr(t)
		resp, err := tr.RoundTrip(nil)
		if err == nil || resp != nil {
			t.Fatalf("RoundTrip(nil) = %v, %v, want error", resp, err)
		}
		if signer.calls != 0 || base.calls != 0 {
			t.Fatal("nil request reached signer or base")
		}
	})
	t.Run("signer-override-in-context-still-refused", func(t *testing.T) {
		tr, signer, base := newTr(t)
		other := &spySigner{inner: seedSignerByName(t, "newbie")}
		req := mk(t, "http://svc.example.test/mcp", nil)
		req = req.WithContext(WithRequestSigner(context.Background(), other))
		check(t, tr, signer, base, req, nil)
		if other.calls != 0 {
			t.Fatalf("override signer used %d times", other.calls)
		}
	})
}

// signedResponder returns a spy fn that answers every request with a validly
// signed 200 response, after running inspect on the request.
func signedResponder(t *testing.T, priv ed25519.PrivateKey, pub []byte, inspect func(*http.Request, []byte)) func(*http.Request) (*http.Response, error) {
	return func(req *http.Request) (*http.Response, error) {
		auth, err := jack.ParseRequestAuth(req.Header.Values("Jack-Auth"))
		if err != nil {
			return nil, err
		}
		var body []byte
		if req.Body != nil {
			body, _ = io.ReadAll(req.Body)
		}
		if inspect != nil {
			inspect(req, body)
		}
		kid := jack.KeyID(pub)
		out := rpcResultBody(json.RawMessage(`{}`))
		msg := []byte(jack.ResponseSigningString(http.StatusOK, auth.Sig, kid, fixtureNow, out))
		sig := ed25519.Sign(priv, msg)
		h := http.Header{}
		h.Set("Content-Type", "application/json")
		h.Set("Jack-Auth", jack.FormatResponseAuth(jack.ResponseAuth{Kid: kid, TS: fixtureNow, Sig: jack.EncodeBase64URL(sig)}))
		return &http.Response{StatusCode: http.StatusOK, Header: h, Body: io.NopCloser(bytes.NewReader(out)), Request: req}, nil
	}
}

func TestRemoteHTTPSPositiveControl(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	alice := seedSignerByName(t, "alice")
	var gotScheme, gotHost, gotTarget string
	var sigOK bool
	base := &spyBase{fn: signedResponder(t, priv, pub, func(req *http.Request, body []byte) {
		gotScheme, gotHost, gotTarget = req.URL.Scheme, req.URL.Host, req.URL.RequestURI()
		auth, aerr := jack.ParseRequestAuth(req.Header.Values("Jack-Auth"))
		if aerr != nil {
			return
		}
		sig, derr := jack.DecodeBase64URLFixed(auth.Sig, ed25519.SignatureSize)
		msg := []byte(jack.RequestSigningString(req.Method, gotTarget, fixtureAud, auth.Kid, auth.TS, auth.Nonce, body))
		sigOK = derr == nil && jack.Verify(alice.PublicKey(), msg, sig)
	})}
	tr := &Transport{Base: base, Aud: fixtureAud, Signer: alice, ServerKey: pub, Now: fixedClock(fixtureNow), Window: 30 * time.Second}
	c, err := NewClient(Config{
		BaseURL:   "https://svc.example.test/mcp?x=1",
		Aud:       fixtureAud,
		Signer:    alice,
		ServerKey: pub,
		HTTP:      NewHTTPClient(tr),
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := c.call(context.Background(), nil, "jack.test", nil, nil); err != nil {
		t.Fatalf("call: %v", err)
	}
	if base.calls != 1 {
		t.Fatalf("base calls = %d, want 1", base.calls)
	}
	if gotScheme != "https" || gotHost != "svc.example.test" || gotTarget != "/mcp?x=1" {
		t.Fatalf("request reached base as %s://%s%s", gotScheme, gotHost, gotTarget)
	}
	if !sigOK {
		t.Fatal("request signature over the target did not verify")
	}
}

func TestLoopbackHTTPSignedRoundTrip(t *testing.T) {
	srv := newTestServer(t)
	if !strings.HasPrefix(srv.URL, "http://127.0.0.1:") {
		t.Fatalf("test server URL %q is not literal-loopback http", srv.URL)
	}
	srv.Handle = func(w http.ResponseWriter, auth jack.RequestAuth, _ []byte) {
		srv.writeSignedJSON(w, auth, http.StatusOK, rpcResultBody(json.RawMessage(`{}`)))
	}
	resp, err := postMCP(t, NewHTTPClient(newTransport(t, srv)), srv.URL, []byte(`{"ping":1}`))
	if err != nil {
		t.Fatalf("loopback round trip: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func redirectBase(status int, location string) *spyBase {
	return &spyBase{fn: func(req *http.Request) (*http.Response, error) {
		h := http.Header{}
		h.Set("Location", location)
		return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
	}}
}

func TestRedirectsAreRefused(t *testing.T) {
	statuses := []int{
		http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect,
	}
	for _, loc := range []string{"http://evil.example/", "https://other.example.test/mcp"} {
		for _, status := range statuses {
			base := redirectBase(status, loc)
			tr := &Transport{Base: base, Aud: fixtureAud, Signer: seedSignerByName(t, "alice"), ServerKey: make([]byte, 32), Now: fixedClock(fixtureNow)}

			req, err := http.NewRequest(http.MethodPost, "https://svc.example.test/mcp", strings.NewReader("{}"))
			if err != nil {
				t.Fatalf("http.NewRequest: %v", err)
			}
			resp, err := tr.RoundTrip(req)
			if !errors.Is(err, ErrRedirectRefused) {
				t.Fatalf("RoundTrip err = %v, want ErrRedirectRefused", err)
			}
			var re *RedirectRefusedError
			if !errors.As(err, &re) || re.Status != status {
				t.Fatalf("RoundTrip err = %v, want *RedirectRefusedError status %d", err, status)
			}
			if resp != nil || base.calls != 1 {
				t.Fatalf("resp = %v, base calls = %d, want nil and 1", resp, base.calls)
			}
			if strings.Contains(err.Error(), loc) {
				t.Fatalf("error surfaces Location: %v", err)
			}

			// Through the SDK http.Client: never followed.
			base2 := redirectBase(status, loc)
			tr.Base = base2
			req2, err := http.NewRequest(http.MethodPost, "https://svc.example.test/mcp", strings.NewReader("{}"))
			if err != nil {
				t.Fatalf("http.NewRequest: %v", err)
			}
			resp2, err := NewHTTPClient(tr).Do(req2)
			if !errors.Is(err, ErrRedirectRefused) {
				t.Fatalf("Do err = %v, want ErrRedirectRefused", err)
			}
			if resp2 != nil && resp2.Body != nil {
				_ = resp2.Body.Close()
			}
			if base2.calls != 1 {
				t.Fatalf("base calls through Do = %d, want exactly 1", base2.calls)
			}
		}
	}
}

func TestIsRedirectStatusExactSet(t *testing.T) {
	for status := 0; status < 700; status++ {
		want := status == 301 || status == 302 || status == 303 || status == 307 || status == 308
		if got := isRedirectStatus(status); got != want {
			t.Fatalf("isRedirectStatus(%d) = %v, want %v", status, got, want)
		}
	}
}

// statusBase answers every request with the given delivered status, an empty
// body and (when signAs != 0) a response signature computed over signAs with
// the key priv; badSig signs with an unrelated key instead.
func statusBase(priv ed25519.PrivateKey, pub []byte, deliver, signAs int, badSig bool) *spyBase {
	return &spyBase{fn: func(req *http.Request) (*http.Response, error) {
		h := http.Header{}
		if signAs != 0 {
			auth, err := jack.ParseRequestAuth(req.Header.Values("Jack-Auth"))
			if err != nil {
				return nil, err
			}
			kid := jack.KeyID(pub)
			signKey := priv
			if badSig {
				_, signKey, _ = ed25519.GenerateKey(nil)
			}
			msg := []byte(jack.ResponseSigningString(signAs, auth.Sig, kid, fixtureNow, []byte{}))
			sig := ed25519.Sign(signKey, msg)
			h.Set("Jack-Auth", jack.FormatResponseAuth(jack.ResponseAuth{Kid: kid, TS: fixtureNow, Sig: jack.EncodeBase64URL(sig)}))
		}
		return &http.Response{StatusCode: deliver, Header: h, Body: http.NoBody, Request: req}, nil
	}}
}

func newStatusTransport(t *testing.T, base http.RoundTripper, pub []byte) *Transport {
	t.Helper()
	return &Transport{Base: base, Aud: fixtureAud, Signer: seedSignerByName(t, "alice"), ServerKey: pub, Now: fixedClock(fixtureNow), Window: 30 * time.Second}
}

func newStatusRequest(t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "https://svc.example.test/mcp", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	return req
}

func TestSigned304IsNotARedirect(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}

	t.Run("RoundTrip", func(t *testing.T) {
		base := statusBase(priv, pub, http.StatusNotModified, http.StatusNotModified, false)
		resp, err := newStatusTransport(t, base, pub).RoundTrip(newStatusRequest(t))
		if err != nil {
			t.Fatalf("RoundTrip err = %v, want signed 304 returned", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusNotModified {
			t.Fatalf("status = %d, want 304", resp.StatusCode)
		}
		if base.calls != 1 {
			t.Fatalf("base calls = %d, want 1", base.calls)
		}
	})

	t.Run("NewHTTPClient.Do", func(t *testing.T) {
		base := statusBase(priv, pub, http.StatusNotModified, http.StatusNotModified, false)
		resp, err := NewHTTPClient(newStatusTransport(t, base, pub)).Do(newStatusRequest(t))
		if err != nil {
			t.Fatalf("Do err = %v, want signed 304 returned", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusNotModified {
			t.Fatalf("status = %d, want 304", resp.StatusCode)
		}
		if base.calls != 1 {
			t.Fatalf("base calls = %d, want 1", base.calls)
		}
	})
}

// TestNonRedirect3xxGoesThroughVerification documents the exact redirect set:
// 300 and 304 that are unsigned, tampered or badly signed fail verification
// (a *jack.Error), never with a redirect error.
func TestNonRedirect3xxGoesThroughVerification(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	cases := []struct {
		name    string
		deliver int
		signAs  int // 0 = unsigned
		badSig  bool
	}{
		{"304-unsigned", http.StatusNotModified, 0, false},
		{"304-signed-as-200", http.StatusNotModified, http.StatusOK, false},
		{"304-bad-signature", http.StatusNotModified, http.StatusNotModified, true},
		{"300-unsigned", http.StatusMultipleChoices, 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, viaDo := range []bool{false, true} {
				base := statusBase(priv, pub, c.deliver, c.signAs, c.badSig)
				tr := newStatusTransport(t, base, pub)
				var resp *http.Response
				var err error
				if viaDo {
					resp, err = NewHTTPClient(tr).Do(newStatusRequest(t))
				} else {
					resp, err = tr.RoundTrip(newStatusRequest(t))
				}
				if resp != nil && resp.Body != nil {
					_ = resp.Body.Close()
				}
				if err == nil {
					t.Fatalf("viaDo=%v: err = nil, want a verification error", viaDo)
				}
				if errors.Is(err, ErrRedirectRefused) {
					t.Fatalf("viaDo=%v: err = %v, must not be a redirect refusal", viaDo, err)
				}
				var re *RedirectRefusedError
				if errors.As(err, &re) {
					t.Fatalf("viaDo=%v: err = %v, must not be *RedirectRefusedError", viaDo, err)
				}
				var je *jack.Error
				if !errors.As(err, &je) {
					t.Fatalf("viaDo=%v: err = %v (%T), want a verification *jack.Error", viaDo, err, err)
				}
				if base.calls != 1 {
					t.Fatalf("viaDo=%v: base calls = %d, want 1", viaDo, base.calls)
				}
			}
		})
	}
}

func TestNewHTTPClientDoesNotFollowRedirects(t *testing.T) {
	hc := NewHTTPClient(&Transport{})
	if hc.CheckRedirect == nil {
		t.Fatal("CheckRedirect is nil")
	}
	if err := hc.CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("CheckRedirect = %v, want http.ErrUseLastResponse", err)
	}
}

func TestClientRefusesRedirectFromInjectedHTTP(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	base := redirectBase(http.StatusFound, "http://evil.example/")
	callerClient := &http.Client{Transport: base}
	c, err := NewClient(Config{
		BaseURL:   "https://svc.example.test/mcp",
		Aud:       fixtureAud,
		Signer:    seedSignerByName(t, "alice"),
		ServerKey: pub,
		HTTP:      callerClient,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if callerClient.CheckRedirect != nil {
		t.Fatal("caller's http.Client was mutated")
	}
	err = c.call(context.Background(), nil, "jack.test", nil, nil)
	if !errors.Is(err, ErrRedirectRefused) {
		t.Fatalf("call err = %v, want ErrRedirectRefused", err)
	}
	if base.calls != 1 {
		t.Fatalf("base calls = %d, want exactly 1 (no redirect followed)", base.calls)
	}
}
