// interop-client: Go interop executable (interop README sections 5-7).
// Prints exactly one JSON result line on stdout; harness-level failures go to
// stderr with exit 1.
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/client"
)

// scenarioResult is the single stdout line (interop README section 5).
type scenarioResult struct {
	Scenario   string  `json:"scenario"`
	Outcome    string  `json:"outcome"`
	HTTPStatus *int    `json:"http_status"`
	Code       *string `json:"code"`
	Data       any     `json:"data"`
}

// seedEntry is one identity from the seeds file (spec/fixtures/keys.json).
// Unknown members of the file are ignored by design.
type seedEntry struct {
	SeedHex string
	Kid     string
}

type seedsFile struct {
	Keys []struct {
		Name    string `json:"name"`
		SeedHex string `json:"seed_hex"`
		Kid     string `json:"kid"`
	} `json:"keys"`
}

// argList collects repeatable --arg k=v flags (value may contain '='; split at
// the FIRST '=' only).
type argList []string

func (a *argList) String() string     { return strings.Join(*a, ",") }
func (a *argList) Set(v string) error { *a = append(*a, v); return nil }

// tsFlag records whether --ts was given: ts=0 is a valid sign-case value, so
// a plain flag.Int64 cannot distinguish "missing" from "zero".
type tsFlag struct {
	v   int64
	set bool
}

func (t *tsFlag) String() string {
	if t == nil {
		return ""
	}
	return strconv.FormatInt(t.v, 10)
}

func (t *tsFlag) Set(s string) error {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return err
	}
	t.v, t.set = n, true
	return nil
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "interop-client: "+format+"\n", args...)
	os.Exit(1)
}

// emit prints the one stdout result line and exits 0.
func emit(scenario string, r stepResult) {
	res := scenarioResult{Scenario: scenario, Outcome: r.kind, Data: r.data}
	// http_status is reported only when a wire response was actually
	// received (interop README section 5); sign-only and client-side
	// verification failures report null.
	if r.hasStatus {
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
	os.Exit(0)
}

func main() {
	var argsRaw argList
	var seedsPath, seedHex, urlFlag, pubKey, aud, scenario, nonceFlag string
	var ts tsFlag
	flag.StringVar(&urlFlag, "url", "", "base URL of the server")
	flag.StringVar(&seedHex, "seed-hex", "", "primary identity seed (64 hex chars)")
	flag.StringVar(&pubKey, "server-public-key", "", "pinned server public key (b64u)")
	flag.StringVar(&aud, "aud", "", "audience string")
	flag.StringVar(&scenario, "scenario", "", "scenario name")
	flag.StringVar(&seedsPath, "seeds", "", "path of spec/fixtures/keys.json")
	flag.Var(&ts, "ts", "unix timestamp (sign-only)")
	flag.StringVar(&nonceFlag, "nonce", "", "nonce, b64u (sign-only)")
	flag.Var(&argsRaw, "arg", "repeatable k=v argument")
	flag.Parse()

	args := map[string]string{}
	for _, kv := range argsRaw {
		k, v, _ := strings.Cut(kv, "=")
		args[k] = v
	}
	if scenario == "" {
		fatal("--scenario is required")
	}
	if seedHex == "" {
		fatal("--seed-hex is required")
	}
	seed, err := hex.DecodeString(strings.ToLower(seedHex))
	if err != nil || len(seed) != 32 {
		fatal("--seed-hex must be 64 hex chars decoding to 32 bytes")
	}
	primary, err := client.NewInMemorySigner(seed)
	if err != nil {
		fatal("signer: %v", err)
	}

	// sign-only never touches the network and ignores --url/--server-public-key.
	if scenario == "sign-only" {
		runSignOnly(scenario, primary, aud, args, nonceFlag, ts)
		return
	}

	if urlFlag == "" {
		fatal("--url is required")
	}
	if pubKey == "" {
		fatal("--server-public-key is required")
	}
	if aud == "" {
		fatal("--aud is required")
	}
	if seedsPath == "" {
		fatal("--seeds is required")
	}
	serverKey, err := jack.DecodeBase64URLFixed(pubKey, 32)
	if err != nil {
		fatal("--server-public-key must decode to 32 bytes: %v", err)
	}
	raw, err := os.ReadFile(seedsPath)
	if err != nil {
		fatal("reading --seeds: %v", err)
	}
	var sf seedsFile
	if err := json.Unmarshal(raw, &sf); err != nil {
		fatal("parsing --seeds: %v", err)
	}
	seeds := map[string]seedEntry{}
	primaryName := ""
	for _, k := range sf.Keys {
		seeds[k.Name] = seedEntry{SeedHex: k.SeedHex, Kid: k.Kid}
		if strings.EqualFold(k.SeedHex, seedHex) {
			primaryName = k.Name
		}
	}

	e := &env{
		scenario:    scenario,
		baseURL:     urlFlag,
		aud:         aud,
		serverKey:   serverKey,
		args:        args,
		seeds:       seeds,
		primary:     primary,
		primaryName: primaryName,
		rawHTTP:     &http.Client{Timeout: 15 * time.Second},
		typedStash:  &wireStash{inner: http.DefaultTransport},
		clients:     map[string]*client.Client{},
	}
	// One shared signed transport; the base is the stashing wire transport
	// so raw 401 bodies land in the stash without reaching the SDK.
	e.typedHTTP = &http.Client{
		Transport: client.NewTransport(e.typedStash, aud, primary, serverKey),
		Timeout:   15 * time.Second,
	}

	fn, ok := scenarios[scenario]
	if !ok {
		fatal("unknown scenario '%s'", scenario)
	}
	emit(scenario, fn(e))
}

// runSignOnly reproduces the sign-cases oracle bytes without any network I/O.
func runSignOnly(scenario string, primary *client.InMemorySigner, aud string, args map[string]string, nonceB64 string, ts tsFlag) {
	method := args["method"]
	target := args["target"]
	bodyB64 := args["body-b64u"]
	if method == "" || target == "" {
		fatal("sign-only requires --arg method=... and --arg target=...")
	}
	if !ts.set {
		fatal("sign-only requires --ts")
	}
	if nonceB64 == "" {
		fatal("sign-only requires --nonce")
	}
	nonce, err := jack.DecodeBase64URLFixed(nonceB64, 16)
	if err != nil {
		fatal("--nonce must decode to 16 bytes: %v", err)
	}
	// Empty body-b64u is valid and means an empty body.
	body, err := jack.DecodeBase64URL(bodyB64)
	if err != nil {
		fatal("body-b64u: %v", err)
	}
	header, err := client.SignRequest(primary, aud, method, target, body, nonce, time.Unix(ts.v, 0))
	if err != nil {
		fatal("SignRequest: %v", err)
	}
	data := map[string]any{
		"signing_string": jack.RequestSigningString(method, target, aud, primary.KID(), ts.v, jack.EncodeBase64URL(nonce), body),
		"jack_auth":      header,
		"kid":            primary.KID(),
	}
	emit(scenario, stepResult{kind: "ok", data: data})
}
