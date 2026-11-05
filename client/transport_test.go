package client

import (
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
