package portable

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
	rotationclient "github.com/PHPCraftdream/mcp-jack/client/rotation"
	"github.com/PHPCraftdream/mcp-jack/rotation"
)

func httpPortableResponse(w http.ResponseWriter, r *http.Request, key portableSigner, body []byte) {
	auth, err := jack.ParseRequestAuth(r.Header.Values("Jack-Auth"))
	if err != nil {
		w.WriteHeader(400)
		return
	}
	kid := key.KID()
	msg := jack.ResponseSigningString(200, auth.Sig, kid, 1200, body)
	w.Header().Set("Jack-Auth", jack.FormatResponseAuth(jack.ResponseAuth{Kid: kid, TS: 1200, Sig: jack.EncodeBase64URL(ed25519.Sign(key.key, []byte(msg)))}))
	_, _ = w.Write(body)
}
func TestPortableHTTPCallAndRefresh(t *testing.T) {
	anchor, next := portableKey(41), portableKey(42)
	binding := rotation.Binding{Audience: "portable-http"}
	var record rotation.Record
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		responseBody := []byte("http ordinary")
		if json.Valid(body) && bytes.Contains(body, []byte("jack.server.key")) {
			responseBody = pageEnvelope(t, anchor, []rotation.Record{record}, rotation.ResultCursor{Ordinal: 1, Hash: record.Hash})
		}
		httpPortableResponse(w, r, anchor, responseBody)
	}))
	defer server.Close()
	binding.Endpoint = server.URL + "/mcp"
	checkpoint := rotation.Checkpoint{Hash: "-", KID: anchor.KID()}
	copy(checkpoint.PublicKey[:], anchor.PublicKey())
	record, err := rotation.CreateRecord(binding, checkpoint, anchor, next, 1000)
	if err != nil {
		t.Fatal(err)
	}
	store := newMemStore(binding, 30, checkpoint, anchor, 1200)
	sender, err := rotationclient.NewHTTP(store, portableKey(43), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := sender.Call(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	if err != nil || string(reply.Body) != "http ordinary" {
		t.Fatalf("call %+v %v", reply, err)
	}
	result, err := sender.Refresh(context.Background())
	if err != nil || !result.Committed {
		t.Fatalf("refresh %+v %v", result, err)
	}
}
func TestPortableHTTPTimeoutAndStoreFailure(t *testing.T) {
	store, _, _ := portableSetup(t)
	for _, timeout := range []time.Duration{0, 31 * time.Second} {
		if _, err := rotationclient.NewHTTP(store, portableKey(44), timeout); err == nil {
			t.Fatal("accepted invalid timeout")
		} else {
			portableCode(t, err, "rotation_state_unknown")
		}
	}
	anchor := portableKey(31)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpPortableResponse(w, r, anchor, []byte("raw clock refused"))
	}))
	defer server.Close()
	binding := rotation.Binding{Endpoint: server.URL + "/mcp", Audience: "portable-test"}
	cp := rotation.Checkpoint{Hash: "-", KID: anchor.KID()}
	copy(cp.PublicKey[:], anchor.PublicKey())
	store = newMemStore(binding, 30, cp, anchor, 1200)
	store.rawErr = &rotation.Error{Code: "rotation_clock_unavailable"}
	sender, err := rotationclient.NewHTTP(store, portableKey(45), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, err = sender.Call(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	portableCode(t, err, "rotation_clock_unavailable")
}

func TestPortableHTTPRefreshConflictAndUnknownOutcome(t *testing.T) {
	anchor, next := portableKey(51), portableKey(52)
	binding := rotation.Binding{Audience: "portable-http-conflict"}
	var store *memStore
	var record rotation.Record
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := pageEnvelope(t, anchor, []rotation.Record{record}, rotation.ResultCursor{Ordinal: 1, Hash: record.Hash})
		httpPortableResponse(w, r, anchor, page)
	}))
	defer server.Close()
	binding.Endpoint = server.URL + "/mcp"
	checkpoint := rotation.Checkpoint{Hash: "-", KID: anchor.KID()}
	copy(checkpoint.PublicKey[:], anchor.PublicKey())
	record, err := rotation.CreateRecord(binding, checkpoint, anchor, next, 1000)
	if err != nil {
		t.Fatal(err)
	}
	store = newMemStore(binding, 30, checkpoint, anchor, 1200)
	sender, err := rotationclient.NewHTTP(store, portableKey(53), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	store.casConflict = true
	before := append([]byte(nil), store.encoded...)
	_, err = sender.Refresh(context.Background())
	portableCode(t, err, "rotation_state_changed")
	if !bytes.Equal(before, store.encoded) {
		t.Fatal("CAS conflict modified snapshot")
	}
}

func TestPortableHTTPUnknownRefreshOutcome(t *testing.T) {
	anchor := portableKey(54)
	var calls atomic.Int32
	hijacked := make(chan io.Closer, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Error(err)
			return
		}
		connection, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		hijacked <- connection
	}))
	defer server.Close()
	// The hijacked socket is silent and server-owned: close it here, after the client gave up.
	defer func() {
		select {
		case connection := <-hijacked:
			_ = connection.Close()
		default:
		}
	}()
	binding := rotation.Binding{Endpoint: server.URL + "/mcp", Audience: "portable-http-unknown"}
	checkpoint := rotation.Checkpoint{Hash: "-", KID: anchor.KID()}
	copy(checkpoint.PublicKey[:], anchor.PublicKey())
	store := newMemStore(binding, 30, checkpoint, anchor, 1200)
	before := append([]byte(nil), store.encoded...)
	sender, err := rotationclient.NewHTTP(store, portableKey(55), 300*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	_, err = sender.Refresh(context.Background())
	if !errors.Is(err, context.DeadlineExceeded) { // The Call/Refresh context deadline or http.Client Timeout may fire; this accepts either.
		t.Fatalf("unknown outcome: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("request count: got %d want 1", calls.Load())
	}
	if !bytes.Equal(before, store.encoded) {
		t.Fatal("unknown outcome modified snapshot")
	}
}

func TestPortableHTTPLostResponse(t *testing.T) {
	anchor := portableKey(56)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Error(err)
			return
		}
		connection, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		_ = connection.Close()
	}))
	defer server.Close()
	binding := rotation.Binding{Endpoint: server.URL + "/mcp", Audience: "portable-http-lost-response"}
	checkpoint := rotation.Checkpoint{Hash: "-", KID: anchor.KID()}
	copy(checkpoint.PublicKey[:], anchor.PublicKey())
	store := newMemStore(binding, 30, checkpoint, anchor, 1200)
	before := append([]byte(nil), store.encoded...)
	sender, err := rotationclient.NewHTTP(store, portableKey(57), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, err = sender.Refresh(context.Background())
	if !errors.Is(err, rotationclient.ErrRequestUnavailable) {
		t.Fatalf("lost response: got %v want ErrRequestUnavailable", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("request count: got %d want 1", calls.Load())
	}
	if !bytes.Equal(before, store.encoded) {
		t.Fatal("lost response modified snapshot")
	}
}
