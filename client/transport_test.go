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
	"github.com/PHPCraftdream/mcp-jack/client/internal/testfixture"
	"github.com/PHPCraftdream/mcp-jack/client/internal/urlpolicy"
	spec "github.com/PHPCraftdream/mcp-jack/spec"
)

// newTransport builds a Transport pinned to the test server key with fixed
// clock and alice as signer; Nonce is omitted (RandomNonce is used).
func newTransport(t *testing.T, srv *testServer) *Transport {
	t.Helper()
	return &Transport{
		Aud:       fixtureAud,
		Signer:    seedSignerByName(t, "alice"),
		ServerKey: srv.Pub,
		Now:       fixedClock(fixtureNow),
		Window:    30 * time.Second,
	}
}

type shortSignatureSigner struct{ inner *InMemorySigner }

func (s shortSignatureSigner) Sign([]byte) ([]byte, error) { return []byte{1, 2, 3}, nil }
func (s shortSignatureSigner) PublicKey() []byte           { return s.inner.PublicKey() }
func (s shortSignatureSigner) KID() string                 { return s.inner.KID() }

func TestTransportRejectsMalformedOwnAuthHeader(t *testing.T) {
	base := &spyBase{}
	body := &closeSpyBody{Reader: strings.NewReader(`{"ping":1}`)}
	tr := &Transport{
		Base:      base,
		Aud:       fixtureAud,
		Signer:    shortSignatureSigner{inner: seedSignerByName(t, "alice")},
		Now:       fixedClock(fixtureNow),
		Nonce:     func() ([]byte, error) { return make([]byte, 16), nil },
		ServerKey: make([]byte, ed25519.PublicKeySize),
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, fixtureAud+"/mcp", nil)
	if err != nil {
		t.Fatalf("http.NewRequestWithContext: %v", err)
	}
	req.Body = body

	resp, err := tr.RoundTrip(req)
	if err == nil {
		t.Fatal("RoundTrip err = nil, want malformed own auth header")
	}
	if resp != nil {
		t.Fatalf("resp = %+v, want nil", resp)
	}
	if !strings.Contains(err.Error(), "jack client: parsing signed request auth header:") {
		t.Fatalf("err = %q, want descriptive client wrapper", err)
	}
	var jErr *jack.Error
	if !errors.As(err, &jErr) {
		t.Fatalf("err = %T (%v), want wrapped *jack.Error", err, err)
	}
	if jErr.Code != jack.CodeMalformedAuth {
		t.Fatalf("Code = %q, want %q", jErr.Code, jack.CodeMalformedAuth)
	}
	if base.calls != 0 {
		t.Fatalf("base calls = %d, want 0", base.calls)
	}
	if !body.closed {
		t.Fatal("request body was not closed")
	}
}

// postMCP issues a signed POST to srv at path /mcp with the given body.
func postMCP(t *testing.T, httpc *http.Client, srvURL string, body []byte) (*http.Response, error) {
	t.Helper()
	u, err := url.Parse(srvURL)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	u.Path = "/mcp"
	req, err := http.NewRequestWithContext(context.Background(), "POST", u.String(), strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("http.NewRequestWithContext: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	return httpc.Do(req)
}

func TestTransportRoundTripHappyPath(t *testing.T) {
	srv := newTestServer(t)
	tr := newTransport(t, srv)

	wantBody := rpcResultBody(json.RawMessage(`{"ok":true}`))
	var gotKid string
	var gotTS int64
	alice := seedSignerByName(t, "alice")
	srv.Handle = func(w http.ResponseWriter, auth jack.RequestAuth, body []byte) {
		gotKid = auth.Kid
		gotTS = auth.TS
		srv.writeSignedJSON(w, auth, http.StatusOK, wantBody)
	}

	httpc := NewHTTPClient(tr)
	resp, err := postMCP(t, httpc, srv.URL, []byte(`{"ping":1}`))
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(got) != string(wantBody) {
		t.Fatalf("body = %q, want %q", got, wantBody)
	}
	if resp.ContentLength != int64(len(wantBody)) {
		t.Fatalf("ContentLength = %d, want %d", resp.ContentLength, len(wantBody))
	}
	if gotKid != alice.KID() {
		t.Fatalf("server saw kid %q, want alice kid %q", gotKid, alice.KID())
	}
	if gotTS != fixtureNow {
		t.Fatalf("server saw ts %d, want %d", gotTS, fixtureNow)
	}
}

func TestTransportUnsigned401SurfacesError(t *testing.T) {
	srv := newTestServer(t)
	tr := newTransport(t, srv)
	srv.Handle = func(w http.ResponseWriter, auth jack.RequestAuth, _ []byte) {
		srv.writeUnsignedJSON(w, http.StatusUnauthorized, []byte(`{"error":{"code":"unknown_key","message":"nope"}}`))
	}

	httpc := NewHTTPClient(tr)
	resp, err := postMCP(t, httpc, srv.URL, []byte(`{"ping":1}`))
	if err == nil {
		t.Fatalf("Do err = nil, want UnauthenticatedResponseError")
	}
	if resp != nil {
		t.Fatalf("resp = %+v, want nil", resp)
	}
	var ue *UnauthenticatedResponseError
	if !errors.As(err, &ue) {
		t.Fatalf("err = %T (%v), want *UnauthenticatedResponseError", err, err)
	}
	if ue.Status != http.StatusUnauthorized {
		t.Fatalf("Status = %d, want 401", ue.Status)
	}
}

func TestTransportSigned401PassesThrough(t *testing.T) {
	srv := newTestServer(t)
	tr := newTransport(t, srv)
	wantBody := []byte(`{"error":{"code":"unknown_key","message":"expired"}}`)
	srv.Handle = func(w http.ResponseWriter, auth jack.RequestAuth, _ []byte) {
		srv.writeSignedJSON(w, auth, http.StatusUnauthorized, wantBody)
	}

	httpc := NewHTTPClient(tr)
	resp, err := postMCP(t, httpc, srv.URL, []byte(`{"ping":1}`))
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(got) != string(wantBody) {
		t.Fatalf("body = %q, want %q", got, wantBody)
	}
}

func TestTransportRefusesStreamingResponse(t *testing.T) {
	// The media type is the part before the first ';', trimmed and
	// case-insensitive; a malformed parameter list must not defeat the refusal.
	for _, contentType := range []string{
		"text/event-stream",
		"Text/Event-Stream; charset=utf-8",
		"text/event-stream ;;; =bad",
		" text/event-stream;",
	} {
		t.Run(contentType, func(t *testing.T) {
			srv := newTestServer(t)
			tr := newTransport(t, srv)
			srv.Handle = func(w http.ResponseWriter, _ jack.RequestAuth, _ []byte) {
				// Streams cannot be body-hashed so they are refused per spec 01
				// section 5 / README Q1 — signed or not; an unsigned stream suffices
				// here because the streaming guard fires before verification.
				w.Header().Set("Content-Type", contentType)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("data: x\n\n"))
			}

			httpc := NewHTTPClient(tr)
			resp, err := postMCP(t, httpc, srv.URL, []byte(`{"ping":1}`))
			if !errors.Is(err, ErrStreamingUnsupported) {
				t.Fatalf("err = %v, want ErrStreamingUnsupported", err)
			}
			if resp != nil {
				t.Fatalf("resp = %+v, want nil", resp)
			}
		})
	}
}

func TestTransportDetectsTamperedBody(t *testing.T) {
	srv := newTestServer(t)
	tr := newTransport(t, srv)
	srv.Handle = func(w http.ResponseWriter, auth jack.RequestAuth, _ []byte) {
		bodyA := rpcResultBody(json.RawMessage(`{"ok":true}`))
		msg := []byte(jack.ResponseSigningString(http.StatusOK, auth.Sig, srv.Kid, srv.Now, bodyA))
		sig := ed25519.Sign(srv.Key, msg)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Jack-Auth", jack.FormatResponseAuth(jack.ResponseAuth{Kid: srv.Kid, TS: srv.Now, Sig: jack.EncodeBase64URL(sig)}))
		// Same length, different content: flip the last byte before '}'.
		bodyB := append([]byte{}, bodyA...)
		bodyB[len(bodyB)-2] = 'X'
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bodyB)
	}

	httpc := NewHTTPClient(tr)
	resp, err := postMCP(t, httpc, srv.URL, []byte(`{"ping":1}`))
	if err == nil {
		t.Fatalf("Do err = nil, want jack.Error bad signature")
	}
	if resp != nil {
		t.Fatalf("resp = %+v, want nil", resp)
	}
	var jErr *jack.Error
	if !errors.As(err, &jErr) {
		t.Fatalf("err = %T (%v), want *jack.Error", err, err)
	}
	if jErr.Code != jack.CodeBadSignature {
		t.Fatalf("Code = %q, want %q", jErr.Code, jack.CodeBadSignature)
	}
}

func TestTransportRejectsUnpinnedServerKey(t *testing.T) {
	srv := newTestServer(t)
	tr := newTransport(t, srv)
	wrongPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	tr.ServerKey = wrongPub
	srv.Handle = func(w http.ResponseWriter, auth jack.RequestAuth, _ []byte) {
		srv.writeSignedJSON(w, auth, http.StatusOK, rpcResultBody(json.RawMessage(`{"ok":true}`)))
	}

	httpc := NewHTTPClient(tr)
	resp, err := postMCP(t, httpc, srv.URL, []byte(`{"ping":1}`))
	if err == nil {
		t.Fatalf("Do err = nil, want jack.Error unknown server key")
	}
	if resp != nil {
		t.Fatalf("resp = %+v, want nil", resp)
	}
	var jErr *jack.Error
	if !errors.As(err, &jErr) {
		t.Fatalf("err = %T (%v), want *jack.Error", err, err)
	}
	if jErr.Code != jack.CodeUnknownServerKey {
		t.Fatalf("Code = %q, want %q", jErr.Code, jack.CodeUnknownServerKey)
	}
}

func TestTransportRejectsStaleTimestamp(t *testing.T) {
	srv := newTestServer(t)
	tr := newTransport(t, srv)
	tr.Now = fixedClock(fixtureNow + 3600) // response ts (fixtureNow) is out of window
	srv.Handle = func(w http.ResponseWriter, auth jack.RequestAuth, _ []byte) {
		srv.writeSignedJSON(w, auth, http.StatusOK, rpcResultBody(json.RawMessage(`{"ok":true}`)))
	}

	httpc := NewHTTPClient(tr)
	resp, err := postMCP(t, httpc, srv.URL, []byte(`{"ping":1}`))
	if err == nil {
		t.Fatalf("Do err = nil, want jack.Error timestamp out of window")
	}
	if resp != nil {
		t.Fatalf("resp = %+v, want nil", resp)
	}
	var jErr *jack.Error
	if !errors.As(err, &jErr) {
		t.Fatalf("err = %T (%v), want *jack.Error", err, err)
	}
	if jErr.Code != jack.CodeTimestampOutOfWindow {
		t.Fatalf("Code = %q, want %q", jErr.Code, jack.CodeTimestampOutOfWindow)
	}
}

// streamingRefusalCase is one row of spec/fixtures/client-streaming-refusal.json.
type streamingRefusalCase struct {
	Name        string   `json:"name"`
	ContentType []string `json:"content_type"`
	Refused     bool     `json:"refused"`
}

// TestTransportStreamingRefusalFixture runs the shared client streaming-
// refusal table through a spy base transport. All Content-Type field lines
// take part (joined with commas, any member decides). A refused row must surface
// ErrStreamingUnsupported with the response body closed and never read, and
// a non-refused row must reach verification: the pinned key is random and
// the answer unsigned, so the observable outcome is the missing-auth
// jack.Error, proving the stream guard did not fire.
func TestTransportStreamingRefusalFixture(t *testing.T) {
	data, err := spec.Fixture("client-streaming-refusal.json")
	if err != nil {
		t.Fatalf("spec.Fixture: %v", err)
	}
	var doc struct {
		Cases []streamingRefusalCase `json:"cases"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("decode client-streaming-refusal.json: %v", err)
	}
	if len(doc.Cases) == 0 {
		t.Fatal("client-streaming-refusal.json has no cases")
	}
	for _, c := range doc.Cases {
		t.Run(c.Name, func(t *testing.T) {
			body := &closeSpyBody{Reader: strings.NewReader("data: x\n\n")}
			base := &spyBase{fn: func(*http.Request) (*http.Response, error) {
				hdr := http.Header{}
				if len(c.ContentType) > 0 {
					hdr["Content-Type"] = c.ContentType
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     hdr,
					Body:       body,
				}, nil
			}}
			pub, _, err := ed25519.GenerateKey(nil)
			if err != nil {
				t.Fatalf("ed25519.GenerateKey: %v", err)
			}
			tr := &Transport{
				Aud:       fixtureAud,
				Signer:    seedSignerByName(t, "alice"),
				ServerKey: pub,
				Now:       fixedClock(fixtureNow),
				Window:    30 * time.Second,
				Base:      base,
			}
			req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://svc.example.test/mcp", strings.NewReader(`{"ping":1}`))
			if err != nil {
				t.Fatalf("http.NewRequestWithContext: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")
			_, err = tr.RoundTrip(req)
			if base.calls != 1 {
				t.Fatalf("base calls = %d, want 1", base.calls)
			}
			if c.Refused {
				if !errors.Is(err, ErrStreamingUnsupported) {
					t.Fatalf("err = %v, want ErrStreamingUnsupported", err)
				}
				if !body.closed || body.reads != 0 {
					t.Fatalf("body closed=%v reads=%d, want closed without any read", body.closed, body.reads)
				}
				return
			}
			var jErr *jack.Error
			if !errors.As(err, &jErr) || jErr.Code != jack.CodeMissingAuth {
				t.Fatalf("err = %v, want jack.Error missing_auth (verification ran, no stream refusal)", err)
			}
		})
	}
}

// Fixture-driven URL policy tests (spec/fixtures/client-url-policy.json).
//
// Entry paths exercised for every row (name, url, allow, optional
// parse_reject):
//
//   - policy fn: urlpolicy.CheckDestination(raw) must agree with allow.
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
//     A: http.NewRequest fails. urlpolicy.CheckDestination(raw) must refuse the raw
//     string, or the row must be allow=true with parse_reject for go.
//     B: NewRequest succeeds and urlpolicy.CheckRequestDestination(req) agrees with
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

// transportViewDestination rebuilds the destination string the Transport
// checks (same construction as urlpolicy.CheckRequestDestination).

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
	cases := testfixture.LoadURLPolicyCases(t)
	var bucketA, bucketB, bucketC int
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			req, nerr := http.NewRequest(http.MethodPost, c.URL, strings.NewReader(`{}`))
			if nerr != nil {
				// Bucket A.
				if urlpolicy.CheckDestination(c.URL) == nil && !(c.Allow && testfixture.GoParseRejects(c)) {
					t.Fatalf("http.NewRequest(%q) failed (%v) but the row is neither refused by checkDestination nor allow+parse_reject go", c.URL, nerr)
				}
				bucketA++
				return
			}
			if c.Allow && testfixture.GoParseRejects(c) {
				t.Fatalf("row %q is flagged parse_reject go but http.NewRequest accepted it", c.URL)
			}
			terr := urlpolicy.CheckRequestDestination(req)
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
				if urlpolicy.CheckDestination(c.URL) == nil {
					t.Fatalf("row %q: raw string is not refused by checkDestination", c.URL)
				}
				view := transportViewDestination(req.URL)
				if err := urlpolicy.CheckDestination(view); err != nil {
					t.Fatalf("row %q: transport view %q = %v, want accepted", c.URL, view, err)
				}
				if req.URL.Scheme == "http" {
					host := req.URL.Hostname()
					if !urlpolicy.IsLoopbackIPv4(host) && host != "::1" {
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
