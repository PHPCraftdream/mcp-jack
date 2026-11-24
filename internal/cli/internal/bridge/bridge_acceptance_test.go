//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package bridge

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/stdio"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/transport"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/wire"
	"github.com/PHPCraftdream/mcp-jack/userkey"
)

const modernBridgeEvent = `{"jsonrpc":"2.0","method":"notifications/event","params":{"name":"incident.created"}}`

type modernSignatureKey struct{}

func modernBridgeFixture(t *testing.T) (*transport.Connection, ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issued, _, err := userkey.IssueLocalPair()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := userkey.ImportClientKey(issued.Secret())
	if err != nil {
		t.Fatal(err)
	}
	return &transport.Connection{Aud: "svc", Pin: public, Signer: signer, Timeout: 2 * time.Second, Era: "modern"}, private, public
}
func modernBridgeBody(id int, method, params string) []byte {
	var values map[string]json.RawMessage
	_ = json.Unmarshal([]byte(params), &values)
	if values == nil {
		values = make(map[string]json.RawMessage)
	}
	values["_meta"] = json.RawMessage(`{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"bridge-test","version":"1"}}`)
	encoded, _ := json.Marshal(values)
	return []byte(`{"jsonrpc":"2.0","id":` + strconv.Itoa(id) + `,"method":` + strconv.Quote(method) + `,"params":` + string(encoded) + `}`)
}
func signedModernStreamReply(t *testing.T, priv ed25519.PrivateKey, pub ed25519.PublicKey, requestSig string, data []string) (string, []byte) {
	t.Helper()
	kid := jack.KeyID(pub)
	sid := jack.EncodeBase64URL(bytes.Repeat([]byte{7}, 16))
	ts := time.Now().Unix()
	openString := strings.Join([]string{"mcp-jack/stream1/open", "200", requestSig, kid, strconv.FormatInt(ts, 10), sid}, "\n")
	openSig := jack.EncodeBase64URL(ed25519.Sign(priv, []byte(openString)))
	var body strings.Builder
	previous := openSig
	for seq, value := range data {
		hash := jack.BodyHash([]byte(value))
		sig := jack.EncodeBase64URL(ed25519.Sign(priv, []byte(strings.Join([]string{"mcp-jack/stream1/frame", sid, strconv.Itoa(seq), strconv.FormatInt(ts, 10), previous, hash}, "\n"))))
		body.WriteString("event: message\ndata: " + value + "\njack: seq=" + strconv.Itoa(seq) + ",ts=" + strconv.FormatInt(ts, 10) + ",sig=" + sig + "\n\n")
		previous = sig
	}
	end := jack.EncodeBase64URL(ed25519.Sign(priv, []byte(strings.Join([]string{"mcp-jack/stream1/frame", sid, strconv.Itoa(len(data)), strconv.FormatInt(ts, 10), previous, jack.BodyHash(nil)}, "\n"))))
	body.WriteString("event: jack-end\ndata:\njack: seq=" + strconv.Itoa(len(data)) + ",ts=" + strconv.FormatInt(ts, 10) + ",sig=" + end + "\n\n")
	return "s1 kid=" + kid + ",ts=" + strconv.FormatInt(ts, 10) + ",sid=" + sid + ",sig=" + openSig, []byte(body.String())
}
func modernBridgeHandler(t *testing.T, next http.Handler) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth, err := jack.ParseRequestAuth(r.Header.Values("Jack-Auth"))
		if err != nil {
			w.WriteHeader(401)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), modernSignatureKey{}, auth.Sig)))
	})
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

type nopReadCloser struct{ io.Reader }

func (nopReadCloser) Close() error { return nil }

// TestModernBridgeProcessSubprocess proves real-process concurrency, cancellation, and continued dispatch.
func TestModernBridgeProcessSubprocess(t *testing.T) {
	if os.Getenv("MCP_JACK_MODERN_BRIDGE_HELPER") == "1" {
		modernBridgeProcessHelper()
		return
	}
	_, priv, pub := modernBridgeFixture(t)
	started := make(chan int, 4)
	gate302 := make(chan struct{})
	cancelled := make(chan int, 2)
	var active, maximum atomic.Int32
	server := httptest.NewServer(modernBridgeHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		m, _ := wire.Object(b)
		var id int
		_ = json.Unmarshal(m["id"], &id)
		now := active.Add(1)
		for old := maximum.Load(); now > old && !maximum.CompareAndSwap(old, now); old = maximum.Load() {
		}
		defer active.Add(-1)
		started <- id
		if id == 301 || id == 304 {
			<-r.Context().Done()
			cancelled <- id
			return
		}
		if id == 302 {
			select {
			case <-gate302:
			case <-r.Context().Done():
				return
			}
			open, data := signedModernStreamReply(t, priv, pub, r.Context().Value(modernSignatureKey{}).(string), []string{"{\n}"})
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Jack-Auth", open)
			w.WriteHeader(200)
			_, _ = w.Write(data)
			return
		}
		if id == 303 {
			auth, _ := jack.ParseRequestAuth(r.Header.Values("Jack-Auth"))
			reply := []byte(`{"jsonrpc":"2.0","id":303,"result":{"tools":[]}}`)
			ts := time.Now().Unix()
			sig := ed25519.Sign(priv, []byte(jack.ResponseSigningString(200, auth.Sig, jack.KeyID(pub), ts, reply)))
			w.Header().Set("Jack-Auth", jack.FormatResponseAuth(jack.ResponseAuth{Kid: jack.KeyID(pub), TS: ts, Sig: jack.EncodeBase64URL(sig)}))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			_, _ = w.Write(reply)
			return
		}
	})))
	defer server.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestModernBridgeProcessSubprocess$")
	cmd.Env = append(os.Environ(), "MCP_JACK_MODERN_BRIDGE_HELPER=1", "MCP_JACK_MODERN_ENDPOINT="+base64.RawURLEncoding.EncodeToString([]byte(server.URL+"/mcp")), "MCP_JACK_MODERN_PIN="+base64.RawURLEncoding.EncodeToString(pub))
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill() }()
	send := func(frames ...[]byte) {
		t.Helper()
		for _, f := range frames {
			if _, werr := in.Write(append(f, '\n')); werr != nil {
				t.Fatal(werr)
			}
		}
	}
	waitStarted := func(want ...int) {
		t.Helper()
		seen := make(map[int]bool, len(want))
		for range want {
			select {
			case id := <-started:
				seen[id] = true
			case <-time.After(4 * time.Second):
				t.Fatalf("requests did not reach server: seen %v, want %v", seen, want)
			}
		}
		for _, id := range want {
			if !seen[id] {
				t.Fatalf("request %d did not reach server: seen %v", id, seen)
			}
		}
	}
	got := make(chan string, 1)
	go func() { line, _ := bufio.NewReader(out).ReadString('\n'); got <- line }()
	// The cancellation must follow the server-side start of its target: sent
	// earlier, it can abort the request before the connection exists.
	send(modernBridgeBody(301, "events/stream", `{"name":"one"}`), modernBridgeBody(302, "events/stream", `{"name":"two"}`))
	waitStarted(301, 302)
	if maximum.Load() < 2 {
		t.Fatalf("concurrent requests=%d", maximum.Load())
	}
	close(gate302)
	send([]byte(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":301}}`), modernBridgeBody(303, "tools/list", `{}`), modernBridgeBody(304, "events/stream", `{"name":"eof"}`))
	waitStarted(303, 304)
	select {
	case id := <-cancelled:
		if id != 301 {
			t.Fatalf("notification cancelled request %d", id)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("request not cancelled")
	}
	select {
	case line := <-got:
		if !strings.Contains(line, `"id":303`) {
			t.Fatalf("later response missing: %q", line)
		}
		if strings.Contains(line, modernBridgeEvent) {
			t.Fatalf("aborted stream leaked: %q", line)
		}
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("response did not arrive")
	}
	if err := in.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case id := <-cancelled:
		if id != 304 {
			t.Fatalf("EOF cancelled request %d", id)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("EOF did not cancel active stream")
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("helper: %v %s", err, stderr.String())
	}
}
func modernBridgeProcessHelper() {
	endpoint, _ := base64.RawURLEncoding.DecodeString(os.Getenv("MCP_JACK_MODERN_ENDPOINT"))
	pin, _ := base64.RawURLEncoding.DecodeString(os.Getenv("MCP_JACK_MODERN_PIN"))
	issued, _, err := userkey.IssueLocalPair()
	if err != nil {
		os.Exit(21)
	}
	signer, err := userkey.ImportClientKey(issued.Secret())
	if err != nil {
		os.Exit(22)
	}
	conn := &transport.Connection{Endpoint: string(endpoint), Aud: "svc", Pin: pin, Signer: signer, Timeout: time.Second, Era: "modern"}
	if runModernBridge(context.Background(), conn, stdio.IO{In: nopReadCloser{os.Stdin}, Out: nopWriteCloser{os.Stdout}, Err: os.Stderr}) != nil {
		os.Exit(23)
	}
}
