// rotation-server: Go rotation interop executable (rotation matrix, server
// side). Serves authenticated MCP behind the candidate response-key rotation
// provider and accepts OOB announce commands on stdin. Serve-mode stdout
// carries only the ready line and announce result lines; startup failures
// never touch stdout.
package main

import (
	"bufio"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/durable"
	"github.com/PHPCraftdream/mcp-jack/rotation"
	"github.com/PHPCraftdream/mcp-jack/server"
	rotationserver "github.com/PHPCraftdream/mcp-jack/server/rotation"
)

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "rotation-server: "+format+"\n", args...)
	os.Exit(1)
}

// seedSigner adapts an Ed25519 private key to the server.ResponseSigner
// interface. PublicKey returns a copy; Sign never mutates the key.
type seedSigner struct {
	priv ed25519.PrivateKey
}

func (s seedSigner) PublicKey() []byte {
	pub := s.priv.Public().(ed25519.PublicKey)
	return append([]byte(nil), pub...)
}

func (s seedSigner) Sign(message []byte) ([]byte, error) {
	return ed25519.Sign(s.priv, message), nil
}

// ringSeeds collects repeatable --ring-seed ref=hex flags; the value may
// contain '=', so split at the FIRST '=' only.
type ringSeeds []string

func (r *ringSeeds) String() string     { return strings.Join(*r, ",") }
func (r *ringSeeds) Set(v string) error { *r = append(*r, v); return nil }

// fileClock reads the clock file on EVERY call and keeps the last good value.
// A read/parse failure returns the last value; with no prior success it
// panics, which durable.sampleTrustNow turns into store-unavailable errors.
type fileClock struct {
	path  string
	mu    sync.Mutex
	value int64
	set   bool
}

func (c *fileClock) Now() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	data, err := os.ReadFile(c.path)
	if err == nil {
		parsed, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
		if err == nil {
			c.value, c.set = parsed, true
		}
	}
	if !c.set {
		panic("rotation-server: clock file never readable")
	}
	return c.value
}

// readClockOnce reads the raw file value for the one-shot wire path; the
// caller treats a failure as a harness-level fatal.
func readClockOnce(path string) (int64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
}

func main() {
	aud := flag.String("aud", "", "audience (required)")
	urlFlag := flag.String("url", "", "exact binding endpoint (required)")
	statePath := flag.String("state", "", "registry state file (required)")
	seedHex := flag.String("server-seed-hex", "", "anchor K0 seed, 64 hex chars (required)")
	storePath := flag.String("rotation-store", "", "server ring store path (required)")
	clockFile := flag.String("clock-file", "", "clock file holding one decimal integer (required)")
	port := flag.Int("port", 0, "port to bind on 127.0.0.1 (0 = any)")
	var seeds ringSeeds
	flag.Var(&seeds, "ring-seed", "repeatable ref=hex extra signer seed")
	flag.Parse()
	if *aud == "" || *urlFlag == "" || *statePath == "" || *seedHex == "" || *storePath == "" || *clockFile == "" {
		fail("--aud, --url, --state, --server-seed-hex, --rotation-store and --clock-file are required")
	}

	seed, err := hex.DecodeString(*seedHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		fail("--server-seed-hex must be 64 hex chars (32 bytes)")
	}
	priv0 := ed25519.NewKeyFromSeed(seed)
	pub0 := priv0.Public().(ed25519.PublicKey)
	// [32]byte(pub0) is not a legal Go conversion; copy the bytes explicitly.
	var anchorPub [32]byte
	copy(anchorPub[:], pub0)
	kid0 := jack.KeyID(pub0)
	pub0B64 := jack.EncodeBase64URL(pub0)

	clock := &fileClock{path: *clockFile}
	opts := durable.TrustOptions{
		Binding: rotation.Binding{Endpoint: *urlFlag, Audience: *aud},
		Window:  30,
		Checkpoint: rotation.Checkpoint{
			Ordinal: 0, Hash: "-", KID: kid0, PublicKey: anchorPub, PublishedAt: 0,
		},
		Now: clock.Now,
	}
	serverOpts := durable.ServerOptions{TrustOptions: opts, AnchorReference: "ring-0"}
	if _, err := os.Stat(*storePath); os.IsNotExist(err) {
		if err := durable.InitializeServerUnused(*storePath, serverOpts); err != nil {
			fail("rotation store init: %v", err)
		}
	} else if err != nil {
		fail("rotation store stat: %v", err)
	}
	store, err := durable.OpenServer(*storePath, serverOpts)
	if err != nil {
		fail("rotation store open: %v", err)
	}

	keys := []rotationserver.Key{{Reference: "ring-0", Signer: seedSigner{priv: priv0}}}
	for i, entry := range seeds {
		ref, hexSeed, found := strings.Cut(entry, "=")
		if !found || ref == "" {
			fail("--ring-seed[%d] must be ref=hex", i)
		}
		seedBytes, err := hex.DecodeString(hexSeed)
		if err != nil || len(seedBytes) != ed25519.SeedSize {
			fail("--ring-seed[%d] seed must be 64 hex chars (32 bytes)", i)
		}
		keys = append(keys, rotationserver.Key{Reference: ref, Signer: seedSigner{priv: ed25519.NewKeyFromSeed(seedBytes)}})
	}
	provider, err := rotationserver.New(store, keys)
	if err != nil {
		fail("rotation provider: %v", err)
	}

	state, err := server.OpenFileState(*statePath)
	if err != nil {
		fail("state file: %v", err)
	}
	verifier, err := server.NewVerifier(server.Config{
		Aud:        *aud,
		State:      state,
		Nonces:     server.NewNonceStore(),
		Native:     server.NewNativeTools(server.NativeOptions{}),
		ServerKeys: provider,
		Now:        clock.Now,
	})
	if err != nil {
		fail("verifier: %v", err)
	}
	h, err := server.NewHandler(server.HandlerConfig{Verifier: verifier, ResponseKeys: provider}, mcpHandler())
	if err != nil {
		fail("handler: %v", err)
	}

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", *port))
	if err != nil {
		fail("listen: %v", err)
	}
	portNum := ln.Addr().(*net.TCPAddr).Port

	// The ready line is the first and only pre-announce stdout output.
	ready, _ := json.Marshal(struct {
		Ready     bool   `json:"ready"`
		Port      int    `json:"port"`
		PublicKey string `json:"server_public_key"`
		Kid       string `json:"server_kid"`
	}{true, portNum, pub0B64, kid0})
	fmt.Println(string(ready))

	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, os.Interrupt)
	stdinDone := make(chan struct{})
	// Harness sends announce lines and closes stdin to stop the server.
	go func() {
		controlStdin(provider, bufio.NewScanner(os.Stdin))
		close(stdinDone)
	}()

	select {
	case <-sig:
	case <-stdinDone:
	case err := <-serveErr:
		if err != nil && err != http.ErrServerClosed {
			fail("serve: %v", err)
		}
	}
	_ = srv.Close()
	_ = store.Close()
}

// controlInput is one stdin line: {"op":"announce","reference":...,"kid":...}.
type controlInput struct {
	Op        string `json:"op"`
	Reference string `json:"reference"`
	Kid       string `json:"kid"`
}

type announceResult struct {
	Announced   bool   `json:"announced"`
	Ordinal     uint64 `json:"ordinal,omitempty"`
	HeadOrdinal uint64 `json:"head_ordinal,omitempty"`
	HeadHash    string `json:"head_hash,omitempty"`
	PublishedAt int64  `json:"published_at,omitempty"`
	ActivatesAt int64  `json:"activates_at,omitempty"`
	Revision    uint64 `json:"revision,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

func controlStdin(provider *rotationserver.Provider, scanner *bufio.Scanner) {
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var in controlInput
		if err := json.Unmarshal([]byte(line), &in); err != nil || in.Op != "announce" {
			fmt.Fprintf(os.Stderr, "rotation-server: ignoring stdin line: %s\n", line)
			continue
		}
		publication, err := provider.Announce(in.Reference, in.Kid)
		if err != nil {
			fmt.Fprintln(os.Stdout, `{"announced":false,"reason":"rotation_state_unavailable"}`)
			continue
		}
		record := publication.Record
		b, _ := json.Marshal(announceResult{
			Announced:   true,
			Ordinal:     record.Ordinal,
			HeadOrdinal: record.Ordinal,
			HeadHash:    record.Hash,
			PublishedAt: record.PublishedAt,
			ActivatesAt: record.ActivatesAt,
			Revision:    publication.Revision,
		})
		fmt.Println(string(b))
	}
}

// mcpHandler returns the minimal MCP handler of the rotation matrix. It only
// ever sees authenticated requests.
type rotationRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
}

type rotationEnvelope struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func mcpHandler() http.Handler {
	notFound := func(id json.RawMessage) []byte {
		if len(id) == 0 {
			id = json.RawMessage("null")
		}
		b, _ := json.Marshal(rotationEnvelope{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: -32601, Message: "method not found"}})
		return b
	}
	result := func(id json.RawMessage) []byte {
		if len(id) == 0 {
			id = json.RawMessage("null")
		}
		b, _ := json.Marshal(rotationEnvelope{JSONRPC: "2.0", ID: id, Result: json.RawMessage("{}")})
		return b
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":null,"result":{}}`))
			return
		case http.MethodPost:
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
			_, _ = w.Write([]byte(`{"error":{"code":"method_not_allowed","message":"only GET and POST are defined"}}`))
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			_, _ = w.Write(notFound(json.RawMessage("null")))
			return
		}
		var in rotationRequest
		if err := json.Unmarshal(body, &in); err != nil {
			_, _ = w.Write(notFound(json.RawMessage("null")))
			return
		}
		switch in.Method {
		case "ping":
			// Preserve the raw request id text; missing/null id answers null.
			_, _ = w.Write(result(in.ID))
		default:
			_, _ = w.Write(notFound(in.ID))
		}
	})
}
