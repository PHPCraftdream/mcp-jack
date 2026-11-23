// modern-client: Go modern interop executable (modern matrix, client side).
//
// It performs the fixed request sequence of one scenario of
// interop/modern/contract.md section 4.4 and prints exactly one JSON result
// line on stdout (contract 4.2). Every request is signed and every response is
// verified by the SDK's signing transport (contract 4.1 last paragraph); this
// program never signs or verifies anything itself and never adds a request the
// scenario's row does not list. stdout carries the result line and nothing
// else: exit 2 is reserved for --help usage output, every startup failure
// exits 1 with one stderr line and no result line (contract section 2).
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/client"
)

// scenarioIDs lists the --scenario values of contract 4.4 in table order, so
// the usage error can name them and a typo never silently changes a run.
var scenarioIDs = []string{
	"modern-discover",
	"modern-call-projection",
	"modern-mismatch-name",
	"modern-repeated-version",
	"modern-get-405",
	"modern-head-405",
	"modern-session-stripped",
	"era-auto-modern",
	"era-auto-legacy",
	"era-retry-version",
	"legacy-both-parity",
	"native-era-shape",
	"refusal-id-forms",
}

// The three --era values of contract 4.1.
const (
	eraLegacy = "legacy"
	eraModern = "modern"
	eraAuto   = "auto"
)

// clientState is the whole run: the SDK client, the deterministic nonce source,
// the recorded steps and the pending client verdict.
type clientState struct {
	endpoint     string
	hc           *http.Client
	recorder     *recorder
	jsonID       string
	scenario     string
	era          string
	probeVersion string
	// aud, signer and anchor are the deployment profile the high-level client
	// needs to build the SDK's own transport, and clock feeds its verification
	// clock (contract 4.1, section 2).
	aud    string
	signer client.Signer
	anchor []byte
	clock  *fileClock
	// base is the unsigned transport below the recorder: the replay resends
	// stored bytes through it without signing again (contract section 2).
	base http.RoundTripper
	// nonceIndex is the index of the next new request (contract section 2); a
	// replay is not a new request, so it never advances this.
	nonceIndex int
	lastEra    string
	steps      []step
	pending    *verdict
}

// fail prints the one stderr diagnostic of a scenario that cannot be run at
// all and exits 1 (contract section 2); stdout stays untouched.
func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "modern-client: "+format+"\n", args...)
	os.Exit(1)
}

// fileClock is the fixed clock of contract section 2: the file is read on
// EVERY call and the last good value is kept. With no prior success it panics;
// newFileClock rules that out before any request is sent.
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
		panic("modern-client: clock file never readable")
	}
	return c.value
}

// newFileClock validates the clock file once at startup, so an unreadable or
// non-decimal file fails before any request (contract 4.2).
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

// knownScenario reports whether id is one of the contract 4.4 rows.
func knownScenario(id string) bool {
	for _, known := range scenarioIDs {
		if id == known {
			return true
		}
	}
	return false
}

func main() {
	// ContinueOnError with a discarded output keeps a bad flag to exactly one
	// stderr line; only an explicit -h/--help exits 2 (contract section 2).
	fs := flag.NewFlagSet("modern-client", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	urlFlag := fs.String("url", "", "endpoint base URL (required)")
	aud := fs.String("aud", "", "audience (required)")
	seedHex := fs.String("seed-hex", "", "client Ed25519 seed, 64 hex chars (required)")
	anchor := fs.String("anchor", "", "pinned server public key, base64url (required)")
	scenario := fs.String("scenario", "", "scenario id from contract 4.4 (required)")
	era := fs.String("era", "", "legacy, modern or auto (required)")
	clockFile := fs.String("clock-file", "", "clock file holding one decimal integer (required)")
	probeVersion := fs.String("probe-version", modernVersion, "protocol version a C9 probe asks for")
	jsonID := fs.String("json-id", defaultJSONID, "text inserted verbatim as the JSON-RPC id member")
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
	if *urlFlag == "" || *aud == "" || *seedHex == "" || *anchor == "" ||
		*scenario == "" || *era == "" || *clockFile == "" {
		fail("--url, --aud, --seed-hex, --anchor, --scenario, --era and --clock-file are required")
	}
	switch *era {
	case eraLegacy, eraModern, eraAuto:
	default:
		fail("--era must be legacy, modern or auto, got %q", *era)
	}
	if !knownScenario(*scenario) {
		fail("unknown --scenario %q, want one of %s", *scenario, strings.Join(scenarioIDs, ", "))
	}

	// Contract 4.2: an unreadable clock file, a bad seed or a bad anchor means
	// the scenario cannot be run at all, so these fail before any request.
	clock, err := newFileClock(*clockFile)
	if err != nil {
		fail("clock file: %v", err)
	}
	seed, err := hex.DecodeString(*seedHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		fail("--seed-hex must be 64 hex chars decoding to %d bytes", ed25519.SeedSize)
	}
	anchorBytes, err := jack.DecodeBase64URLFixed(*anchor, 32)
	if err != nil {
		fail("--anchor must be 32 raw bytes in base64url: %v", err)
	}
	signer, err := client.NewInMemorySigner(seed)
	if err != nil {
		fail("signer: %v", err)
	}

	c := &clientState{
		// Contract 4.1: the contract's only target is /mcp, so --url is only
		// where it lives.
		endpoint:     strings.TrimSuffix(*urlFlag, "/") + "/mcp",
		jsonID:       *jsonID,
		scenario:     *scenario,
		era:          *era,
		probeVersion: *probeVersion,
		aud:          *aud,
		signer:       signer,
		anchor:       anchorBytes,
		clock:        clock,
		lastEra:      eraModern,
		steps:        []step{},
	}
	if *era == eraLegacy {
		c.lastEra = eraLegacy
	}

	// Contract 4.1 last paragraph: requests go through the SDK's signing
	// transport, with the clock and nonce sources injected (contract 4.1,
	// section 2). One socket per request keeps the tamper proxy's
	// one-head-per-connection relay and the wire bytes predictable.
	base := &http.Transport{DisableKeepAlives: true}
	rec := &recorder{base: base}
	transport := client.NewTransport(rec, *aud, signer, anchorBytes)
	transport.Now = func() time.Time { return time.Unix(clock.Now(), 0) }
	transport.Nonce = c.nextNonce
	c.base = base
	c.recorder = rec
	c.hc = client.NewHTTPClient(transport)

	if err := c.runScenario(); err != nil && !errors.Is(err, errStopScenario) {
		// Connection failure, refused destination, redirect, oversized body:
		// the scenario could not be run at all (contract 4.2 last paragraph).
		fail("%v", err)
	}
	emit(c.resultLine())
}

// emit writes the one result line of contract 4.2 and returns, so the process
// exits 0.
func emit(line resultLine) {
	out, err := json.Marshal(line)
	if err != nil {
		fail("marshal result: %v", err)
	}
	out = append(out, '\n')
	if _, err := os.Stdout.Write(out); err != nil {
		fail("write result: %v", err)
	}
}
