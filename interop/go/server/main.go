// Command interop-server implements the interop-server contract of
// interop/README.md section 4 on top of the mcp-jack server package.
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/PHPCraftdream/mcp-jack/server"

	jack "github.com/PHPCraftdream/mcp-jack"
)

// fail prints a startup error to stderr and exits nonzero. Startup failures
// must never touch stdout so the harness never sees a partial ready line.
func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "interop-server: "+format+"\n", args...)
	os.Exit(1)
}

func main() {
	aud := flag.String("aud", "", "audience (required)")
	statePath := flag.String("state", "", "state file (required)")
	seedHex := flag.String("server-seed-hex", "", "server Ed25519 seed, 64 hex chars (required)")
	bootstrapTTL := flag.String("bootstrap-ttl", "", "create an admin invite with this TTL in seconds")
	verifyOnly := flag.Bool("verify-only", false, "verify one request from stdin and exit")
	flag.Parse()
	if *aud == "" || *statePath == "" || *seedHex == "" {
		fail("--aud, --state and --server-seed-hex are required")
	}

	seed, err := hex.DecodeString(*seedHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		fail("--server-seed-hex must be 64 hex chars (32 bytes)")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	kid := jack.KeyID(pub)
	pubB64 := jack.EncodeBase64URL(pub)

	state, err := server.OpenFileState(*statePath)
	if err != nil {
		fail("state file: %v", err)
	}
	if *verifyOnly {
		runVerifyOnly(*aud, state)
		return
	}

	if *bootstrapTTL != "" {
		ttl, err := strconv.ParseInt(*bootstrapTTL, 10, 64)
		if err != nil {
			fail("--bootstrap-ttl must be an integer number of seconds")
		}
		code, err := server.BootstrapAdmin(state, time.Now().Unix(), ttl, server.NativeOptions{})
		if err != nil {
			fail("--bootstrap-ttl: %v", err)
		}
		b, _ := json.Marshal(struct {
			Invite string `json:"bootstrap_invite"`
		}{code})
		fmt.Fprintln(os.Stderr, string(b))
	}

	verifier, err := server.NewVerifier(server.Config{
		Aud:    *aud,
		State:  state,
		Nonces: server.NewNonceStore(),
		Native: server.NewNativeTools(server.NativeOptions{}),
	})
	if err != nil {
		fail("verifier: %v", err)
	}
	h, err := server.NewHandler(server.HandlerConfig{Verifier: verifier, ServerKey: priv}, mcpHandler())
	if err != nil {
		fail("handler: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fail("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	// The ready line is the first and only stdout output of serve mode.
	ready, _ := json.Marshal(struct {
		Ready     bool   `json:"ready"`
		Port      int    `json:"port"`
		PublicKey string `json:"server_public_key"`
		Kid       string `json:"server_kid"`
	}{true, port, pubB64, kid})
	fmt.Println(string(ready))

	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, os.Interrupt)
	stdinDone := make(chan struct{})
	// Harness closes stdin to stop the server.
	go func() { _, _ = io.Copy(io.Discard, os.Stdin); close(stdinDone) }()

	select {
	case <-sig:
	case <-stdinDone:
	case err := <-serveErr:
		if err != nil && err != http.ErrServerClosed {
			fail("serve: %v", err)
		}
	}
	_ = srv.Close()
}

// verifyInput is the one JSON object --verify-only reads from stdin.
type verifyInput struct {
	Method   string `json:"method"`
	Target   string `json:"target"`
	JackAuth string `json:"jack_auth"`
	BodyB64U string `json:"body_b64u"`
}

type verdict struct {
	Verify string `json:"verify"`
	Kid    string `json:"kid,omitempty"`
	Code   string `json:"code,omitempty"`
}

func runVerifyOnly(aud string, state *server.FileState) {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		fail("read stdin: %v", err)
	}
	var in verifyInput
	if err := json.Unmarshal(data, &in); err != nil {
		fail("stdin: %v", err)
	}
	body, err := jack.DecodeBase64URL(in.BodyB64U)
	if err != nil {
		fail("body_b64u: %v", err)
	}

	// Steps 1-3 of spec 01 section 4: header grammar and version.
	auth, err := jack.ParseRequestAuth([]string{in.JackAuth})
	if err != nil {
		var je *jack.Error
		if errors.As(err, &je) {
			printVerdict(verdict{Verify: "reject", Code: je.Code})
		}
		fail("jack_auth: %v", err)
	}
	// Step 4: kid lookup.
	entry, ok := state.Lookup(auth.Kid)
	if !ok {
		printVerdict(verdict{Verify: "reject", Code: jack.CodeUnknownKey})
	}
	// Steps 5/6/8 (validity, window, nonce) are skipped: the sign cases use
	// fixed ts values 0 and 999999999999.
	pubBytes, err := jack.DecodeBase64URLFixed(entry.PublicKey, 32)
	if err != nil {
		// Unreachable: the state loader validated every entry's public key.
		fail("registry public key: %v", err)
	}
	sig, err := jack.DecodeBase64URLFixed(auth.Sig, 64)
	if err != nil {
		printVerdict(verdict{Verify: "reject", Code: jack.CodeBadSignature})
	}
	// Step 7: strict Ed25519 over the canonical signing string.
	signing := jack.RequestSigningString(in.Method, in.Target, aud, auth.Kid, auth.TS, auth.Nonce, body)
	if !jack.Verify(pubBytes, []byte(signing), sig) {
		printVerdict(verdict{Verify: "reject", Code: jack.CodeBadSignature})
	}
	printVerdict(verdict{Verify: "accept", Kid: auth.Kid})
}

// printVerdict writes the single verdict line and exits 0 (both verdicts).
func printVerdict(v verdict) {
	b, err := json.Marshal(v)
	if err != nil {
		fail("verdict: %v", err)
	}
	fmt.Println(string(b))
	os.Exit(0)
}

// mcpHandler returns the fixed trivial MCP handler of interop/README.md
// section 4. It only ever sees authorized requests.
// Wire types of the fixed trivial MCP handler (interop README section 4).
type trivialParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

type trivialRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  trivialParams   `json:"params"`
}

type trivialText struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type trivialContent struct {
	Content []trivialText `json:"content"`
}

type forwardedIdentity struct {
	Kid      string `json:"kid"`
	Name     string `json:"name"`
	Admin    bool   `json:"admin"`
	BodyB64U string `json:"body_b64u"`
	Method   string `json:"method"`
	Target   string `json:"target"`
}

type trivialEnvelope struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      json.RawMessage  `json:"id"`
	Result  json.RawMessage  `json:"result,omitempty"`
	Error   *trivialRPCError `json:"error,omitempty"`
}

type trivialRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func forwardedIdentityFor(r *http.Request, body []byte) (forwardedIdentity, bool) {
	identity, ok := server.IdentityFromContext(r.Context())
	if !ok {
		return forwardedIdentity{}, false
	}
	kid, name, admin := identity.Kid(), identity.Name(), identity.Admin()
	if identity.Kid() != kid || identity.Name() != name || identity.Admin() != admin {
		return forwardedIdentity{}, false
	}
	target := r.RequestURI
	if target == "" {
		target = r.URL.RequestURI()
	}
	return forwardedIdentity{
		Kid:      kid,
		Name:     name,
		Admin:    admin,
		BodyB64U: jack.EncodeBase64URL(body),
		Method:   r.Method,
		Target:   target,
	}, true
}

func writeIdentityError(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	_, _ = w.Write([]byte(`{"error":{"code":"application_identity_unavailable","message":"verified application identity unavailable"}}`))
}

type identityToolResult struct {
	Content           []trivialText     `json:"content"`
	StructuredContent forwardedIdentity `json:"structuredContent"`
	IsError           bool              `json:"isError"`
}

func identityResult(identity forwardedIdentity) identityToolResult {
	return identityToolResult{
		Content:           []trivialText{{Type: "text", Text: "identity"}},
		StructuredContent: identity,
		IsError:           false,
	}
}

func writeIdentity(w http.ResponseWriter, r *http.Request, body []byte) {
	identity, ok := forwardedIdentityFor(r, body)
	if !ok {
		writeIdentityError(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	payload, _ := json.Marshal(identityResult(identity))
	encoded, _ := json.Marshal(trivialEnvelope{JSONRPC: "2.0", ID: json.RawMessage("null"), Result: payload})
	_, _ = w.Write(encoded)
}

func mcpHandler() http.Handler {
	notFound := func(id json.RawMessage) []byte {
		if len(id) == 0 {
			id = json.RawMessage("null")
		}
		b, _ := json.Marshal(trivialEnvelope{JSONRPC: "2.0", ID: id, Error: &trivialRPCError{Code: -32601, Message: "method not found"}})
		return b
	}
	result := func(id json.RawMessage, res any) []byte {
		if len(id) == 0 {
			id = json.RawMessage("null")
		}
		rb, _ := json.Marshal(res)
		b, _ := json.Marshal(trivialEnvelope{JSONRPC: "2.0", ID: id, Result: rb})
		return b
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
		case http.MethodGet:
			if r.URL.Path == "/sse" {
				// Finite SSE answer; the wrapper buffers it and replies with
				// the signed 501 streaming_unsupported itself.
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = w.Write([]byte("data: hello\n\n"))
				return
			}
			if r.URL.Path == "/identity" || r.URL.Path == "/a/../identity" {
				writeIdentity(w, r, nil)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":null,"result":{}}`))
			return
		default:
			// Unreachable: the middleware rejects other methods first.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusMethodNotAllowed)
			_, _ = w.Write([]byte(`{"error":{"code":"method_not_allowed","message":"only GET and POST are defined"}}`))
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(notFound(json.RawMessage("null")))
			return
		}
		var in trivialRequest
		if err := json.Unmarshal(body, &in); err != nil {
			// Unreachable: the verifier rejects unparseable bodies earlier.
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(notFound(json.RawMessage("null")))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		switch in.Method {
		case "ping":
			_, _ = w.Write(result(in.ID, struct{}{}))
		case "tools/list":
			_, _ = w.Write(result(in.ID, map[string]any{"tools": []map[string]string{{"name": "echo"}}}))
		case "tools/call":
			switch in.Params.Name {
			case "app.identity":
				identity, ok := forwardedIdentityFor(r, body)
				if !ok {
					writeIdentityError(w)
					return
				}
				_, _ = w.Write(result(in.ID, identityResult(identity)))
			case "echo":
				var args map[string]json.RawMessage
				if err := json.Unmarshal(in.Params.Arguments, &args); err != nil {
					_, _ = w.Write(notFound(in.ID))
					return
				}
				var text string
				if err := json.Unmarshal(args["text"], &text); err != nil {
					_, _ = w.Write(notFound(in.ID))
					return
				}
				_, _ = w.Write(result(in.ID, trivialContent{Content: []trivialText{{Type: "text", Text: text}}}))
			case "svc.config.set", "config.set":
				identity, ok := server.IdentityFromContext(r.Context())
				if !ok || identity.Name() != "bob" {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusForbidden)
					_, _ = w.Write([]byte(`{"error":{"code":"application_permission_denied","message":"application permission required"}}`))
					return
				}
				_, _ = w.Write(result(in.ID, trivialContent{Content: []trivialText{{Type: "text", Text: "ok"}}}))
			case "logs.tail":
				_, _ = w.Write(result(in.ID, trivialContent{Content: []trivialText{{Type: "text", Text: "ok"}}}))
			default:
				_, _ = w.Write(notFound(in.ID))
			}
		default:
			_, _ = w.Write(notFound(in.ID))
		}
	})
}
