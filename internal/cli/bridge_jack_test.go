package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/userkey"
)

const jackTestInitialize = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`

const jackTestInitializeReply = `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"fixture","version":"1"}}}`

const jackTestInitialized = `{"jsonrpc":"2.0","method":"notifications/initialized"}`

const jackTestAdminCall = `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"jack.admin.user.create","arguments":{"name":"ghost-admin","public_key":"AA"}}}`

const jackTestEnrollCall = `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"jack.enroll","arguments":{"code":"QUI","name":"ghost","public_key":"AA"}}}`

const jackTestEchoCall = `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hello"}}}`

const jackTestEchoReply = `{"jsonrpc":"2.0","id":4,"result":{"ok":true}}`

// countingGateway records every request body that reaches the fake gateway.
type countingGateway struct {
	mu    sync.Mutex
	calls []string
}

func (g *countingGateway) bodies() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.calls...)
}

// signTestResponse answers like a gateway: every response is signed, including
// the empty 202 (spec 01 section 5).
func signTestResponse(t *testing.T, r *http.Request, w http.ResponseWriter, priv ed25519.PrivateKey, pub ed25519.PublicKey, status int, body []byte) {
	t.Helper()
	auth, err := jack.ParseRequestAuth(r.Header.Values("Jack-Auth"))
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	now := time.Now().Unix()
	sig := ed25519.Sign(priv, []byte(jack.ResponseSigningString(status, auth.Sig, jack.KeyID(pub), now, body)))
	w.Header().Set("Jack-Auth", jack.FormatResponseAuth(jack.ResponseAuth{Kid: jack.KeyID(pub), TS: now, Sig: jack.EncodeBase64URL(sig)}))
	if status != http.StatusAccepted || len(body) != 0 {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(status)
	if len(body) != 0 {
		_, _ = w.Write(body)
	}
}

// jackTestServer serves a counting fake gateway over the exact signed-response
// contract. Anything that is not one of the scripted frames is answered with a
// generic id-echoed result, so a wrongly forwarded native call would count and
// be answered here instead of being refused locally.
func jackTestServer(t *testing.T) (*countingGateway, *httptest.Server, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	g := &countingGateway{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error("request body read failed")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		g.mu.Lock()
		g.calls = append(g.calls, string(b))
		g.mu.Unlock()
		switch string(b) {
		case jackTestInitialize:
			signTestResponse(t, r, w, priv, pub, http.StatusOK, []byte(jackTestInitializeReply))
		case jackTestInitialized:
			signTestResponse(t, r, w, priv, pub, http.StatusAccepted, nil)
		case jackTestEchoCall:
			signTestResponse(t, r, w, priv, pub, http.StatusOK, []byte(jackTestEchoReply))
		default:
			forwarded, parseErr := object(b)
			if parseErr != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			reply := []byte(`{"jsonrpc":"2.0","id":` + string(forwarded["id"]) + `,"result":{"ok":true}}`)
			signTestResponse(t, r, w, priv, pub, http.StatusOK, reply)
		}
	}))
	t.Cleanup(server.Close)
	return g, server, pub
}

func jackTestConnection(t *testing.T, endpoint string, pub ed25519.PublicKey) *connection {
	t.Helper()
	issued, _, err := userkey.IssueLocalPair()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := userkey.ImportClientKey(issued.Secret())
	if err != nil {
		t.Fatal(err)
	}
	return &connection{endpoint: endpoint, aud: "svc", pin: pub, signer: signer, timeout: 2 * time.Second}
}

// assertLocalDenial checks one single-line refusal carrying the original id,
// the fixed code/message and no argument echo.
func assertLocalDenial(t *testing.T, name, body, got string) {
	t.Helper()
	if strings.Count(got, "\n") != 1 || !strings.HasSuffix(got, "\n") {
		t.Fatalf("%s refusal is not a single line: %q", name, got)
	}
	request, err := object([]byte(body))
	if err != nil {
		t.Fatalf("%s request fixture is invalid: %v", name, err)
	}
	refusal, err := object([]byte(strings.TrimSuffix(got, "\n")))
	if err != nil {
		t.Fatalf("%s refusal is not a JSON object: %v", name, err)
	}
	if text(refusal["jsonrpc"]) != "2.0" || !sameID(refusal["id"], request["id"]) {
		t.Fatalf("%s refusal lost jsonrpc or the original id: %q", name, got)
	}
	failure, err := object(refusal["error"])
	if err != nil {
		t.Fatalf("%s refusal error shape: %v", name, err)
	}
	var code int64
	if json.Unmarshal(failure["code"], &code) != nil || code != -32602 {
		t.Fatalf("%s refusal code: %q", name, got)
	}
	if text(failure["message"]) != bridgeNativeDenialMessage {
		t.Fatalf("%s refusal message: %q", name, got)
	}
	for _, secret := range []string{"ghost-admin", "ghost", "public_key", "AA"} {
		if strings.Contains(got, secret) {
			t.Fatalf("%s refusal echoed argument data %q: %q", name, secret, got)
		}
	}
}

// The relay must answer native jack.* tools locally: the counting fake gateway
// records zero forwarded native calls, the client sees the fixed single-line
// error with its own id, and an ordinary tools/call still flows afterwards.
func TestRelayFrameRefusesNativeJackTools(t *testing.T) {
	g, server, pub := jackTestServer(t)
	c := jackTestConnection(t, server.URL+"/mcp", pub)
	state := 0
	var out bytes.Buffer
	ctx := context.Background()

	if err := relayFrame(ctx, c, &out, []byte(jackTestInitialize), &state); err != nil || state != 1 {
		t.Fatalf("initialize relay: %v state=%d", err, state)
	}
	if got := out.String(); got != jackTestInitializeReply+"\n" {
		t.Fatalf("initialize output=%q", got)
	}
	if err := relayFrame(ctx, c, &out, []byte(jackTestInitialized), &state); err != nil || state != 2 {
		t.Fatalf("initialized relay: %v state=%d", err, state)
	}
	if out.String() != jackTestInitializeReply+"\n" {
		t.Fatal("notification produced output")
	}

	for _, tc := range []struct{ name, body string }{
		{"admin-create", jackTestAdminCall},
		{"enroll", jackTestEnrollCall},
	} {
		before := out.Len()
		if err := relayFrame(ctx, c, &out, []byte(tc.body), &state); err != nil || state != 2 {
			t.Fatalf("%s relay: %v state=%d", tc.name, err, state)
		}
		assertLocalDenial(t, tc.name, tc.body, out.String()[before:])
	}
	calls := g.bodies()
	if len(calls) != 2 || calls[0] != jackTestInitialize || calls[1] != jackTestInitialized {
		t.Fatalf("gateway calls=%q; native jack tools must never be forwarded", calls)
	}

	if err := relayFrame(ctx, c, &out, []byte(jackTestEchoCall), &state); err != nil || state != 2 {
		t.Fatalf("echo relay: %v state=%d", err, state)
	}
	if got := out.String(); !strings.HasSuffix(got, jackTestEchoReply+"\n") {
		t.Fatalf("echo output=%q", got)
	}
	calls = g.bodies()
	if len(calls) != 3 || calls[2] != jackTestEchoCall {
		t.Fatalf("gateway calls=%q; the ordinary call must be forwarded last", calls)
	}
}
