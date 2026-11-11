//go:build linux

package rotationclient_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/client"
	rotationclient "github.com/PHPCraftdream/mcp-jack/client/rotation"
	"github.com/PHPCraftdream/mcp-jack/rotation"
)

type capturedRequest struct {
	body []byte
	nonce string
	target string
}

func TestHTTPExplicitRefreshAndExactSignedCalls(t *testing.T) {
	var mode atomic.Int32
	var calls atomic.Int32
	requests := make(chan capturedRequest, 8)
	user := fixtureSigner(61)
	var f fixture
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, err := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
		auth, parseErr := jack.ParseRequestAuth(r.Header.Values("Jack-Auth"))
		if err != nil || parseErr != nil || len(body) > 1<<20 || r.Method != "POST" || auth.Kid != jack.KeyID(user.PublicKey()) {
			t.Error("invalid signed HTTP request")
			w.WriteHeader(400)
			return
		}
		signing := jack.RequestSigningString(r.Method, r.URL.RequestURI(), "public-controller-test", auth.Kid, auth.TS, auth.Nonce, body)
		signature, err := jack.DecodeBase64URLFixed(auth.Sig, 64)
		if err != nil || !jack.Verify(user.PublicKey(), []byte(signing), signature) || r.Header.Get("MCP-Protocol-Version") != "2025-11-25" {
			t.Error("method/target/aud/body signature changed")
			w.WriteHeader(400)
			return
		}
		select {
		case requests <- capturedRequest{body: body, nonce: auth.Nonce, target: r.URL.RequestURI()}:
		default: t.Error("unexpected request overflow"); w.WriteHeader(503); return
		}
		key := f.anchor
		responseBody := []byte("public ordinary bytes")
		if mode.Load() == 1 || mode.Load() == 2 {
			responseBody = envelope(t, f.anchor, []rotation.Record{f.first, f.second}, rotation.ResultCursor{Ordinal: 2, Hash: f.second.Hash}, true)
		}
		if mode.Load() == 3 { key = f.next }
		kid := jack.KeyID(key.PublicKey())
		message := jack.ResponseSigningString(200, auth.Sig, kid, 1200, responseBody)
		w.Header().Set("Jack-Auth", jack.FormatResponseAuth(jack.ResponseAuth{Kid: kid, TS: 1200, Sig: jack.EncodeBase64URL(ed25519.Sign(key.key, []byte(message)))}))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(responseBody)
	}))
	defer remote.Close()
	endpoint := remote.URL + "/mcp?raw=%2f&x=1"
	f = setupEndpoint(t, func() int64 { return 1200 }, endpoint)
	sender, err := rotationclient.NewHTTP(f.store, user, 2*time.Second)
	if err != nil { t.Fatal(err) }
	body := []byte(` {"jsonrpc":"2.0", "id":7,"method":"ping"} `)
	reply, err := sender.Call(context.Background(), body)
	if err != nil || reply.Status != 200 || string(reply.Body) != "public ordinary bytes" { t.Fatalf("signed ordinary HTTP failed: %v", err) }
	first := <-requests
	if !bytes.Equal(first.body, body) || first.target != "/mcp?raw=%2f&x=1" || calls.Load() != 1 { t.Fatal("exact caller body/target changed or retried") }
	mode.Store(2)
	if _, err := sender.Call(context.Background(), body); err != nil { t.Fatal(err) }
	second := <-requests
	snapshot, _, err := f.store.Snapshot()
	if err != nil || snapshot.Head.Ordinal != 0 { t.Fatal("ordinary HTTP response automatically extended trust") }
	mode.Store(3)
	if _, err := sender.Call(context.Background(), body); err == nil { t.Fatal("unknown HTTP carrier accepted without refresh") } else { requireCode(t, err, jack.CodeUnknownServerKey) }
	third := <-requests
	mode.Store(1)
	refreshed, err := sender.Refresh(context.Background())
	if err != nil || !refreshed.Committed || refreshed.Terminal.Ordinal != 2 || !refreshed.Complete { t.Fatalf("explicit HTTP refresh failed: %+v %v", refreshed, err) }
	fourth := <-requests
	var request struct {
		JSONRPC string `json:"jsonrpc"`
		ID int `json:"id"`
		Method string `json:"method"`
		Params struct {
			Name string `json:"name"`
			Arguments map[string]json.RawMessage `json:"arguments"`
		} `json:"params"`
	}
	if json.Unmarshal(fourth.body, &request) != nil || request.Method != "tools/call" || request.Params.Name != "jack.server.key" || len(request.Params.Arguments) != 2 || string(request.Params.Arguments["after_ordinal"]) != "0" || string(request.Params.Arguments["after_hash"]) != `"-"` || calls.Load() != 4 {
		t.Fatal("refresh cursor schema changed or hidden requests/pagination occurred")
	}
	nonces := map[string]bool{}
	for _, capture := range []capturedRequest{first, second, third, fourth} {
		if nonces[capture.nonce] { t.Fatal("distinct explicit calls reused nonce") }
		nonces[capture.nonce] = true
	}
}

func TestHTTPRefreshRejectsConcurrentACKWithoutRepeatingRequest(t *testing.T) {
	var f fixture
	var calls atomic.Int32
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		auth, err := jack.ParseRequestAuth(r.Header.Values("Jack-Auth"))
		if err != nil { t.Error(err); w.WriteHeader(400); return }
		body := envelope(t, f.anchor, []rotation.Record{f.first}, rotation.ResultCursor{Ordinal: 1, Hash: f.first.Hash}, true)
		acked, err := f.controller.AcceptRefresh(response(t, f.anchor, 1200, body), json.RawMessage("1"), rotation.ResultCursor{Hash: "-"})
		if err != nil || !acked.Committed { t.Error("concurrent exact ACK fixture failed"); w.WriteHeader(500); return }
		kid := jack.KeyID(f.anchor.PublicKey())
		message := jack.ResponseSigningString(200, auth.Sig, kid, 1200, body)
		w.Header().Set("Jack-Auth", jack.FormatResponseAuth(jack.ResponseAuth{Kid: kid, TS: 1200, Sig: jack.EncodeBase64URL(ed25519.Sign(f.anchor.key, []byte(message)))}))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer remote.Close()
	f = setupEndpoint(t, func() int64 { return 1200 }, remote.URL+"/mcp")
	sender, err := rotationclient.NewHTTP(f.store, fixtureSigner(61), 2*time.Second)
	if err != nil { t.Fatal(err) }
	result, err := sender.Refresh(context.Background())
	requireCode(t, err, "rotation_state_changed")
	snapshot, _, readErr := f.store.Snapshot()
	if result.Committed || readErr != nil || snapshot.Revision != 2 || snapshot.Head.Ordinal != 1 || calls.Load() != 1 { t.Fatal("stale request adopted/retried or undid concurrent ACK") }
}

func TestHTTPRedirectAndUnknownWriteNeverRetry(t *testing.T) {
	for _, redirect := range []bool{false, true} {
		t.Run(map[bool]string{false: "response-lost", true: "redirect"}[redirect], func(t *testing.T) {
			var calls, followed atomic.Int32
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { followed.Add(1); w.WriteHeader(200) }))
			defer target.Close()
			remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if redirect { w.Header().Set("Location", target.URL); w.WriteHeader(307); return }
				if _, err := io.Copy(io.Discard, r.Body); err != nil { t.Error(err) }
				connection, _, err := w.(http.Hijacker).Hijack()
				if err != nil { t.Error(err); return }
				_ = connection.Close()
			}))
			defer remote.Close()
			f := setupEndpoint(t, func() int64 { return 1200 }, remote.URL+"/mcp")
			sender, err := rotationclient.NewHTTP(f.store, fixtureSigner(61), 2*time.Second)
			if err != nil { t.Fatal(err) }
			if reply, err := sender.Call(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)); err == nil || reply.Body != nil {
				t.Fatal("redirect/unknown write exposed success")
			} else if redirect && !errors.Is(err, client.ErrRedirectRefused) { t.Fatal("redirect refusal changed") } else if !redirect && !errors.Is(err, rotationclient.ErrRequestUnavailable) { t.Fatal("unknown HTTP outcome was misclassified as trust ACK") }
			if calls.Load() != 1 || followed.Load() != 0 { t.Fatal("request retried or redirect followed") }
		})
	}
}

func TestHTTPAbsoluteDeadlineNeverRetries(t *testing.T) {
	var calls atomic.Int32
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if _, err := io.Copy(io.Discard, r.Body); err != nil { t.Error(err); return }
		<-r.Context().Done()
	}))
	defer remote.Close()
	f := setupEndpoint(t, func() int64 { return 1200 }, remote.URL+"/mcp")
	sender, err := rotationclient.NewHTTP(f.store, fixtureSigner(61), time.Second)
	if err != nil { t.Fatal(err) }
	reply, err := sender.Call(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	if !errors.Is(err, context.DeadlineExceeded) || reply.Body != nil || calls.Load() != 1 { t.Fatalf("deadline failed or retried: %v", err) }
}

func TestHTTPContextCancellationClosesOutstandingResponse(t *testing.T) {
	entered := make(chan struct{}, 1)
	closed := make(chan struct{}, 1)
	var calls atomic.Int32
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if _, err := io.Copy(io.Discard, r.Body); err != nil { t.Error(err); return }
		select { case entered <- struct{}{}: default: t.Error("unexpected repeated request"); return }
		<-r.Context().Done()
		select { case closed <- struct{}{}: default: t.Error("unexpected repeated resource close") }
	}))
	defer remote.Close()
	f := setupEndpoint(t, func() int64 { return 1200 }, remote.URL+"/mcp")
	sender, err := rotationclient.NewHTTP(f.store, fixtureSigner(61), 2*time.Second)
	if err != nil { t.Fatal(err) }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := sender.Call(ctx, []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)); result <- err }()
	select { case <-entered: case <-time.After(3*time.Second): t.Fatal("request never reached bounded fixture") }
	cancel()
	select { case err := <-result: if !errors.Is(err, context.Canceled) { t.Fatalf("cancellation lost: %v", err) }; case <-time.After(3*time.Second): t.Fatal("request did not stop") }
	select { case <-closed: case <-time.After(3*time.Second): t.Fatal("HTTP response resource remained open") }
	if calls.Load() != 1 { t.Fatal("cancelled request retried") }
}
