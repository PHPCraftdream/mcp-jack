// modern-server: Go modern interop executable (modern matrix, server side).
// It configures the mcp-jack server SDK with the deployment profile of spec 04
// section 3, the fixture identity and a fixed file clock, then wraps its own
// fixed MCP handler (interop/modern/contract.md 3.1 to 3.5). Authentication,
// the era decision, mirror validation, refusals and response signing are the
// SDK's job and are not reimplemented here. stdout carries only the ready
// line; startup failures never touch stdout.
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
	"strings"
	"sync"
	"syscall"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/server"
)

const (
	// defaultSupportedVersions is the --supported-versions default of
	// contract 3.1.
	defaultSupportedVersions = "2026-07-28,2025-11-25"
	// The three --profile deployment profiles of spec 04 section 3.
	profileLegacy = "legacy"
	profileModern = "modern"
	profileBoth   = "both"
)

// fail prints a startup error to stderr and exits 1 (contract section 2).
// Environment failures must never touch stdout, so the harness never sees a
// partial ready line.
func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "modern-server: "+format+"\n", args...)
	os.Exit(1)
}

// requireReadableFile reports whether path names an existing regular file this
// process can open for reading.
func requireReadableFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("%s is a directory", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	return f.Close()
}

// fileClock reads the clock file on EVERY call and keeps the last good value
// (contract section 2: the wall clock is never consulted). A read/parse
// failure returns the last value; with no prior success it panics.
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
		if parsed, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64); err == nil {
			c.value, c.set = parsed, true
		}
	}
	if !c.set {
		panic("modern-server: clock file never readable")
	}
	return c.value
}

// newFileClock validates the clock file once at startup and seeds the cached
// value, so a bad file can never yield a ready line (contract 3.2).
func newFileClock(path string) (*fileClock, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	value, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("clock file %q does not hold a decimal integer", path)
	}
	return &fileClock{path: path, value: value, set: true}, nil
}

// parseVersions splits --supported-versions on ',' and keeps the given order
// (contract 3.1): entries are trimmed, empty ones dropped, and the result
// stays non-nil so a refusal always renders an array.
func parseVersions(list string) []string {
	versions := []string{}
	for _, entry := range strings.Split(list, ",") {
		if trimmed := strings.TrimSpace(entry); trimmed != "" {
			versions = append(versions, trimmed)
		}
	}
	return versions
}

func main() {
	// ContinueOnError with a discarded output keeps every diagnostic to the
	// single line contract section 2 allows.
	fs := flag.NewFlagSet("modern-server", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	profile := fs.String("profile", "", "deployment profile: legacy, modern or both (required)")
	aud := fs.String("aud", "", "audience (required)")
	statePath := fs.String("state", "", "registry state file (required)")
	seedHex := fs.String("server-seed-hex", "", "server Ed25519 seed, 64 hex chars (required)")
	clockFile := fs.String("clock-file", "", "clock file holding one decimal integer (required)")
	// A sentinel default, not 0: 0 is a legal value (any free port), so it
	// cannot distinguish "flag absent" from "--port 0". Contract 3.1 makes the
	// flag required.
	port := fs.Int("port", -1, "port to bind on 127.0.0.1, 0 = any free port (required)")
	requestLogPath := fs.String("request-log", "", "append one JSON line per handler request")
	versionList := fs.String("supported-versions", defaultSupportedVersions, "comma-separated supported protocol versions")
	mode := fs.String("discover-version-mode", discoverSupported, "discover version mode: supported, refuse-first or refuse-always")
	if err := fs.Parse(os.Args[1:]); err != nil {
		// Contract section 2 reserves exit 2 for usage output only: -h/--help
		// asked for it, every other flag error is a startup failure.
		if errors.Is(err, flag.ErrHelp) {
			// Contract section 2 reserves exit 2 for usage output: print the
			// flag defaults to stderr and leave stdout untouched.
			fs.SetOutput(os.Stderr)
			fmt.Fprintf(os.Stderr, "usage: %s [flags]\n", fs.Name())
			fs.PrintDefaults()
			os.Exit(2)
		}
		fail("%v", err)
	}
	if fs.NArg() > 0 {
		fail("unexpected argument %q", fs.Arg(0))
	}
	if *aud == "" || *statePath == "" || *seedHex == "" || *clockFile == "" {
		fail("--aud, --state, --server-seed-hex and --clock-file are required")
	}
	switch *profile {
	case profileLegacy, profileModern, profileBoth:
	default:
		fail("--profile must be legacy, modern or both, got %q", *profile)
	}
	switch *mode {
	case discoverSupported, discoverRefuseFirst, discoverRefuseAlways:
	default:
		fail("--discover-version-mode must be supported, refuse-first or refuse-always, got %q", *mode)
	}
	if *port < 0 || *port > 65535 {
		fail("--port must be an integer from 0 through 65535, got %d", *port)
	}
	seed, err := hex.DecodeString(*seedHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		fail("--server-seed-hex must be 64 hex chars (32 bytes)")
	}
	versions := parseVersions(*versionList)

	clock, err := newFileClock(*clockFile)
	if err != nil {
		fail("clock file: %v", err)
	}
	reqLog, err := openRequestLog(*requestLogPath)
	if err != nil {
		fail("request log: %v", err)
	}
	defer reqLog.close()

	// Contract 3.1 and section 2: an unreadable state file is a startup error.
	// OpenFileState treats a MISSING file as an empty registry, which would turn
	// a harness mistake into later authentication failures instead of a startup
	// failure, so existence and readability are checked here first.
	if err := requireReadableFile(*statePath); err != nil {
		fail("state file: %v", err)
	}
	state, err := server.OpenFileState(*statePath)
	if err != nil {
		fail("state file: %v", err)
	}
	verifier, err := server.NewVerifier(server.Config{
		Aud:    *aud,
		State:  state,
		Nonces: server.NewNonceStore(),
		Native: server.NewNativeTools(server.NativeOptions{}),
		Now:    clock.Now,
	})
	if err != nil {
		fail("verifier: %v", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	// Responses are signed by the SDK (spec 01 section 5); this process never
	// signs anything itself.
	h, err := server.NewHandler(server.HandlerConfig{
		Verifier:  verifier,
		ServerKey: priv,
		Profile:   server.Profile(*profile),
	}, newHandler(*profile, versions, *mode, reqLog))
	if err != nil {
		fail("handler: %v", err)
	}

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", *port))
	if err != nil {
		fail("listen: %v", err)
	}
	portNum := ln.Addr().(*net.TCPAddr).Port

	// The ready line is the first and only stdout output (contract 3.2).
	ready, _ := json.Marshal(struct {
		Ready     bool   `json:"ready"`
		Port      int    `json:"port"`
		PublicKey string `json:"server_public_key"`
		Kid       string `json:"server_kid"`
		Profile   string `json:"profile"`
	}{true, portNum, jack.EncodeBase64URL(pub), jack.KeyID(pub), *profile})
	fmt.Println(string(ready))

	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, os.Interrupt)
	stdinDone := make(chan struct{})
	// Contract 3.2: the harness stops the server with a signal or by closing
	// stdin. The stream itself carries no commands, so it is only drained.
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
