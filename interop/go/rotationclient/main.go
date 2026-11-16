// rotation-client: Go rotation interop executable (rotation matrix, client
// side). Prints exactly one JSON result line on stdout; harness-level
// failures go to stderr with exit 1 and never touch stdout.
package main

import (
	"context"
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
	rotationclient "github.com/PHPCraftdream/mcp-jack/client/rotation"
	"github.com/PHPCraftdream/mcp-jack/durable"
	"github.com/PHPCraftdream/mcp-jack/rotation"
)

// result is the single stdout line; scenario carries the STEP name.
type result struct {
	Scenario   string  `json:"scenario"`
	Outcome    string  `json:"outcome"`
	HTTPStatus *int    `json:"http_status"`
	Code       *string `json:"code"`
	Data       any     `json:"data"`
}

// stepResult is the internal emit payload; kind/code/data mirror the
// interop client conventions.
type stepResult struct {
	kind    string
	status  int
	hasStat bool
	code    string
	data    any
}

// cleanups close open stores before os.Exit: otherwise the dirty mark remains
// and the next scenario step fails with "explicit recovery required".
var cleanups []func()

func runCleanups() {
	for i := len(cleanups) - 1; i >= 0; i-- {
		cleanups[i]()
	}
	cleanups = nil
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "rotation-client: "+format+"\n", args...)
	runCleanups()
	os.Exit(1)
}

// emit prints the one stdout result line and exits 0.
func emit(step string, r stepResult) {
	res := result{Scenario: step, Outcome: r.kind, Data: r.data}
	if r.hasStat {
		st := r.status
		res.HTTPStatus = &st
	}
	if r.code != "" {
		c := r.code
		res.Code = &c
	}
	b, err := json.Marshal(res)
	if err != nil {
		fatal("marshal result: %v", err)
	}
	fmt.Println(string(b))
	runCleanups()
	os.Exit(0)
}

// errorCodeFrom extracts a rotation/jack code from a verification error;
// an empty string means no stable code is known.
func errorCodeFrom(err error) string {
	var je *jack.Error
	if errors.As(err, &je) {
		return je.Code
	}
	var re *rotation.Error
	if errors.As(err, &re) {
		return re.Code
	}
	return ""
}

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
		panic("rotation-client: clock file never readable")
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

// openStore creates the trust store on first use (OOB initialization is never
// a recovery) and opens it; the caller closes it so the dirty epoch clears
// before process exit.
func openStore(storePath, urlFlag, aud string, window int64, now func() int64, anchorPub [32]byte) *durable.TrustStore {
	opts := durable.TrustOptions{
		Binding: rotation.Binding{Endpoint: urlFlag, Audience: aud},
		Window:  window,
		Checkpoint: rotation.Checkpoint{
			Ordinal: 0, Hash: "-", KID: jack.KeyID(anchorPub[:]), PublicKey: anchorPub, PublishedAt: 0,
		},
		Now: now,
	}
	if _, err := os.Stat(storePath); os.IsNotExist(err) {
		if err := durable.InitializeTrustUnused(storePath, opts); err != nil {
			fatal("rotation store init: %v", err)
		}
	} else if err != nil {
		fatal("rotation store stat: %v", err)
	}
	store, err := durable.OpenTrust(storePath, opts)
	if err != nil {
		fatal("rotation store open: %v", err)
	}
	cleanups = append(cleanups, func() { _ = store.Close() })
	return store
}

func main() {
	step := flag.String("step", "", "scenario step: call | refresh | wire | state (required)")
	urlFlag := flag.String("url", "", "exact binding endpoint (required)")
	aud := flag.String("aud", "", "audience (required)")
	seedHex := flag.String("seed-hex", "", "client seed, 64 hex chars (required)")
	clockFile := flag.String("clock-file", "", "clock file holding one decimal integer (required)")
	anchor := flag.String("anchor", "", "anchor K0 public key, 43-char base64url (call/refresh/state)")
	storePath := flag.String("store", "", "trust store path (call/refresh/state)")
	cursor := flag.String("cursor", "", "<ordinal>:<hash> cursor (wire, jack.server.key only)")
	tool := flag.String("tool", "jack.server.key", "wire step tool name")
	window := flag.Int("window", 30, "trust window seconds (1..120)")
	timeoutMs := flag.Int("timeout-ms", 10000, "HTTP timeout in milliseconds (clamped 1..30000)")
	flag.Parse()

	if *step != "call" && *step != "refresh" && *step != "wire" && *step != "state" {
		fatal("--step must be call, refresh, wire or state")
	}
	if *urlFlag == "" || *aud == "" || *seedHex == "" || *clockFile == "" {
		fatal("--url, --aud, --seed-hex and --clock-file are required")
	}
	if *window < 1 || *window > 120 {
		fatal("--window must be between 1 and 120")
	}
	if *timeoutMs < 1 {
		*timeoutMs = 1
	} else if *timeoutMs > 30000 {
		*timeoutMs = 30000
	}
	timeout := time.Duration(*timeoutMs) * time.Millisecond

	seed, err := hex.DecodeString(*seedHex)
	if err != nil || len(seed) != 32 {
		fatal("--seed-hex must be 64 hex chars decoding to 32 bytes")
	}
	signer, err := client.NewInMemorySigner(seed)
	if err != nil {
		fatal("signer: %v", err)
	}

	usesStore := *step == "call" || *step == "refresh" || *step == "state"
	var anchorPub [32]byte
	if usesStore {
		if *anchor == "" || *storePath == "" {
			fatal("--anchor and --store are required for call/refresh/state")
		}
		decoded, err := jack.DecodeBase64URLFixed(*anchor, 32)
		if err != nil || len(decoded) != 32 {
			fatal("--anchor must decode to 32 bytes")
		}
		copy(anchorPub[:], decoded)
	}

	clock := &fileClock{path: *clockFile}
	switch *step {
	case "call":
		runCall(*step, *urlFlag, *aud, *storePath, int64(*window), clock.Now, anchorPub, signer, timeout)
	case "refresh":
		runRefresh(*step, *urlFlag, *aud, *storePath, int64(*window), clock.Now, anchorPub, signer, timeout)
	case "wire":
		runWire(*step, *urlFlag, *aud, *clockFile, *tool, *cursor, signer, timeout)
	case "state":
		runState(*step, *urlFlag, *aud, *storePath, int64(*window), clock.Now, anchorPub)
	}
}

func runCall(step, urlFlag, aud, storePath string, window int64, now func() int64, anchorPub [32]byte, signer *client.InMemorySigner, timeout time.Duration) {
	store := openStore(storePath, urlFlag, aud, window, now, anchorPub)
	defer func() { _ = store.Close() }()

	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	snapshot, _, err := store.Snapshot()
	if err != nil {
		fatal("store snapshot: %v", err)
	}
	clock, err := store.CheckSnapshotClock(snapshot)
	if err != nil {
		fatal("store clock: %v", err)
	}
	controller, err := rotationclient.New(store)
	if err != nil {
		fatal("rotation controller: %v", err)
	}

	nonce, err := client.RandomNonce()
	if err != nil {
		fatal("nonce: %v", err)
	}
	header, err := client.SignRequest(signer, aud, "POST", "/", body, nonce, time.Unix(clock.HighWater, 0))
	if err != nil {
		fatal("SignRequest: %v", err)
	}
	auth, err := jack.ParseRequestAuth([]string{header})
	if err != nil {
		fatal("ParseRequestAuth: %v", err)
	}

	request, err := http.NewRequest(http.MethodPost, urlFlag, strings.NewReader(string(body)))
	if err != nil {
		fatal("request: %v", err)
	}
	request.Header.Set("Jack-Auth", header)
	request.Header.Set("Content-Type", "application/json")
	network := &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := network.Do(request)
	if err != nil {
		// Transport-level failure: no wire status exists, no retry.
		emit(step, stepResult{kind: "client_error", code: "rotation_request_unavailable"})
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode <= 399 {
		emit(step, stepResult{kind: "client_error", code: "rotation_redirect_refused"})
	}
	if len(resp.Header.Values("Content-Encoding")) != 0 {
		emit(step, stepResult{kind: "client_error", code: "rotation_result_invalid"})
	}
	const limit = 1 << 20
	raw, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		emit(step, stepResult{kind: "client_error", code: "rotation_request_unavailable"})
	}
	if len(raw) > limit {
		emit(step, stepResult{kind: "client_error", code: "rotation_result_invalid"})
	}

	response := rotationclient.Response{
		Status:           resp.StatusCode,
		Headers:          append([]string(nil), resp.Header.Values("Jack-Auth")...),
		RequestSignature: auth.Sig,
		Body:             raw,
	}
	verified, err := controller.VerifyResponse(response)
	if err != nil {
		code := errorCodeFrom(err)
		if code == "" {
			code = "rotation_state_unknown"
		}
		emit(step, stepResult{kind: "client_error", code: code})
	}
	if resp.StatusCode != http.StatusOK {
		emit(step, stepResult{kind: "rejected", status: resp.StatusCode, hasStat: true, code: errorCodeFromWire(verified)})
	}
	kid := "unknown"
	if rauth, err := jack.ParseResponseAuth(response.Headers); err == nil {
		kid = rauth.Kid
	}
	emit(step, stepResult{kind: "ok", status: http.StatusOK, hasStat: true, data: map[string]any{"signed_by": kid}})
}

// errorCodeFromWire best-effort parses {"error":{"code":...}} from a raw
// response body; a missing code yields an empty string (null code).
func errorCodeFromWire(body []byte) string {
	var parsed struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return ""
	}
	return parsed.Error.Code
}

func runRefresh(step, urlFlag, aud, storePath string, window int64, now func() int64, anchorPub [32]byte, signer *client.InMemorySigner, timeout time.Duration) {
	store := openStore(storePath, urlFlag, aud, window, now, anchorPub)
	defer func() { _ = store.Close() }()

	// NewHTTP+Refresh is the SDK's explicit single-page HTTP refresh; all
	// SDK-side refusals are scenario outcomes, never harness failures.
	httpc, err := rotationclient.NewHTTP(store, signer, timeout)
	if err != nil {
		code := errorCodeFrom(err)
		if code == "" {
			code = "rotation_state_unknown"
		}
		emit(step, stepResult{kind: "client_error", code: code})
	}
	refreshResult, err := httpc.Refresh(context.Background())
	if err != nil {
		code := errorCodeFrom(err)
		if code == "" {
			code = "rotation_state_unknown"
		}
		emit(step, stepResult{kind: "client_error", code: code})
	}
	emit(step, stepResult{kind: "ok", status: http.StatusOK, hasStat: true, data: map[string]any{
		"committed":        refreshResult.Committed,
		"head_ordinal":     refreshResult.Head.Ordinal,
		"head_hash":        refreshResult.Head.Hash,
		"terminal_ordinal": refreshResult.Terminal.Ordinal,
		"complete":         refreshResult.Complete,
		"revision":         refreshResult.Revision,
	}})
}

func runWire(step, urlFlag, aud, clockFile, tool, cursor string, signer *client.InMemorySigner, timeout time.Duration) {
	ts, err := readClockOnce(clockFile)
	if err != nil {
		fatal("clock file: %v", err)
	}

	var body []byte
	switch tool {
	case "jack.server.key":
		if cursor == "" {
			fatal("--cursor <ordinal>:<hash> is required for tool jack.server.key")
		}
		// Split at the FIRST ':' only; the hash is used verbatim.
		ordinalText, hash, _ := strings.Cut(cursor, ":")
		ordinal, err := strconv.ParseUint(ordinalText, 10, 64)
		if err != nil {
			fatal("--cursor ordinal must be a decimal uint64: %v", err)
		}
		body, err = json.Marshal(map[string]any{
			"jsonrpc": "2.0", "id": 1, "method": "tools/call",
			"params": map[string]any{"name": "jack.server.key", "arguments": map[string]any{"after_ordinal": ordinal, "after_hash": hash}},
		})
		if err != nil {
			fatal("marshal body: %v", err)
		}
	case "ping":
		body = []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	default:
		fatal("unknown --tool '%s'", tool)
	}

	nonce, err := client.RandomNonce()
	if err != nil {
		fatal("nonce: %v", err)
	}
	header, err := client.SignRequest(signer, aud, "POST", "/", body, nonce, time.Unix(ts, 0))
	if err != nil {
		fatal("SignRequest: %v", err)
	}
	request, err := http.NewRequest(http.MethodPost, urlFlag, strings.NewReader(string(body)))
	if err != nil {
		fatal("request: %v", err)
	}
	request.Header.Set("Jack-Auth", header)
	request.Header.Set("Content-Type", "application/json")
	network := &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := network.Do(request)
	if err != nil {
		emit(step, stepResult{kind: "client_error", code: "rotation_request_unavailable"})
	}
	defer resp.Body.Close()
	const limit = 1 << 20
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		emit(step, stepResult{kind: "ok", status: resp.StatusCode, hasStat: true})
	}
	emit(step, stepResult{kind: "rejected", status: resp.StatusCode, hasStat: true, code: errorCodeFromWire(raw)})
}

func runState(step, urlFlag, aud, storePath string, window int64, now func() int64, anchorPub [32]byte) {
	store := openStore(storePath, urlFlag, aud, window, now, anchorPub)
	defer func() { _ = store.Close() }()

	snapshot, _, err := store.Snapshot()
	if err != nil {
		fatal("store snapshot: %v", err)
	}
	emit(step, stepResult{kind: "ok", data: map[string]any{
		"head_ordinal": snapshot.Head.Ordinal,
		"head_hash":    snapshot.Head.Hash,
		"revision":     snapshot.Revision,
	}})
}
