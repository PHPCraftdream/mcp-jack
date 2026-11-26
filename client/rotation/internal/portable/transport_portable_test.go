package portable

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PHPCraftdream/mcp-jack/client"
	rotationclient "github.com/PHPCraftdream/mcp-jack/client/rotation"
	"github.com/PHPCraftdream/mcp-jack/rotation"
)

// routeTransport stands in for a caller route such as an SSH tunnel.
type routeTransport struct {
	mu        sync.Mutex
	calls     int
	encodings []string
	next      func(*http.Request) (*http.Response, error)
}

func (r *routeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.calls++
	r.encodings = append(r.encodings, req.Header.Get("Accept-Encoding"))
	r.mu.Unlock()
	return r.next(req)
}

func (r *routeTransport) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

func TestPortableHTTPCallerTransportCarriesCallAndRefresh(t *testing.T) {
	anchor, next := portableKey(61), portableKey(62)
	binding := rotation.Binding{Audience: "portable-route"}
	var record rotation.Record
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		responseBody := []byte("routed ordinary")
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
	route := &routeTransport{next: server.Client().Transport.RoundTrip}
	sender, err := rotationclient.NewHTTPWithTransport(store, portableKey(63), 5*time.Second, route)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := sender.Call(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	if err != nil || string(reply.Body) != "routed ordinary" {
		t.Fatalf("call %+v %v", reply, err)
	}
	result, err := sender.Refresh(context.Background())
	if err != nil || !result.Committed {
		t.Fatalf("refresh %+v %v", result, err)
	}
	if route.count() != 2 {
		t.Fatalf("caller transport carried %d requests; want 2", route.count())
	}
	for _, encoding := range route.encodings {
		if encoding != "identity" {
			t.Fatalf("Accept-Encoding %q; want identity", encoding)
		}
	}
}

func TestPortableHTTPCallerTransportFailureIsNotRetried(t *testing.T) {
	store, _, _ := portableSetup(t)
	before := append([]byte(nil), store.encoded...)
	route := &routeTransport{next: func(*http.Request) (*http.Response, error) { return nil, errors.New("tunnel down") }}
	sender, err := rotationclient.NewHTTPWithTransport(store, portableKey(64), 5*time.Second, route)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sender.Refresh(context.Background()); !errors.Is(err, rotationclient.ErrRequestUnavailable) {
		t.Fatalf("got %v; want ErrRequestUnavailable", err)
	}
	if route.count() != 1 {
		t.Fatalf("caller transport saw %d requests; want 1", route.count())
	}
	if !bytes.Equal(before, store.encoded) {
		t.Fatal("failed refresh modified snapshot")
	}
}

func TestPortableHTTPCallerTransportRedirectRefused(t *testing.T) {
	store, _, _ := portableSetup(t)
	route := &routeTransport{next: func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": {"https://elsewhere.invalid/mcp"}}, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
	}}
	sender, err := rotationclient.NewHTTPWithTransport(store, portableKey(65), 5*time.Second, route)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sender.Call(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)); !errors.Is(err, client.ErrRedirectRefused) {
		t.Fatalf("got %v; want ErrRedirectRefused", err)
	}
	if route.count() != 1 {
		t.Fatalf("redirect followed: %d requests", route.count())
	}
}

func TestPortableHTTPCallerTransportRefusals(t *testing.T) {
	store, _, _ := portableSetup(t)
	var typedNil *http.Transport
	for name, base := range map[string]http.RoundTripper{"signing transport": &client.Transport{}, "typed nil": typedNil} {
		if _, err := rotationclient.NewHTTPWithTransport(store, portableKey(66), 5*time.Second, base); err == nil {
			t.Fatalf("%s accepted", name)
		} else {
			portableCode(t, err, "rotation_state_unknown")
		}
	}
	if _, err := rotationclient.NewHTTPWithTransport(store, portableKey(66), 5*time.Second, nil); err != nil {
		t.Fatalf("nil base must mean the built-in transport: %v", err)
	}
}
