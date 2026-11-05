// Scenario implementations for interop-client (interop README section 6).
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/client"
)

// stepResult is one scenario step (or the whole single-step scenario).
type stepResult struct {
	kind      string // "ok" | "rejected" | "client_error"
	status    int    // wire status, meaningful only when hasStatus
	hasStatus bool   // true only when a wire response was received and verified-or-reportable
	code      string // wire code (rejected) or client-side code (client_error); "" → null
	data      any    // set only for ok
}

// env is the shared per-run state.
type env struct {
	scenario    string
	baseURL     string
	aud         string
	serverKey   []byte
	args        map[string]string
	seeds       map[string]seedEntry
	primary     *client.InMemorySigner
	primaryName string
	typedHTTP   *http.Client
	rawHTTP     *http.Client
	typedStash  *wireStash
	clients     map[string]*client.Client
}

// wireStash is the raw wire transport under the shared signed client. The
// SDK never exposes the body of an unsigned 401 (spec 01 section 5), but
// interop outcomes must still report that response's wire code, so the raw
// body bytes are captured here — the Go mirror of the Rust interop client's
// TcpTransport response stash (rust/src/bin/interop/net.rs).
type wireStash struct {
	inner http.RoundTripper

	mu   sync.Mutex
	last []byte
}

func (s *wireStash) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := s.inner.RoundTrip(req)
	if err != nil || resp == nil {
		return resp, err
	}
	buf := &bytes.Buffer{}
	resp.Body = &stashBody{rc: resp.Body, buf: buf, stash: s.record}
	return resp, nil
}

func (s *wireStash) record(body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.last = body
}

// lastBody returns the body bytes of the most recent wire response.
func (s *wireStash) lastBody() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last
}

// stashBody tees every read into buf and hands the captured bytes to stash on
// Close. The signed transport fully reads and closes every body before it
// classifies the response, so the stash is populated before any outcome that
// consults it.
type stashBody struct {
	rc    io.ReadCloser
	buf   *bytes.Buffer
	stash func([]byte)
}

func (b *stashBody) Read(p []byte) (int, error) {
	n, err := b.rc.Read(p)
	if n > 0 {
		b.buf.Write(p[:n])
	}
	return n, err
}

func (b *stashBody) Close() error {
	b.stash(b.buf.Bytes())
	return b.rc.Close()
}

// authFailureCodes: the only responses that may be unsigned (spec 01
// section 5): 401 answers to requests that failed authentication.
var authFailureCodes = map[string]bool{
	"missing_auth":            true,
	"malformed_auth":          true,
	"unsupported_version":     true,
	"unknown_key":             true,
	"key_inactive":            true,
	"timestamp_out_of_window": true,
	"bad_signature":           true,
	"replayed_nonce":          true,
}

// rpcCall is the JSON-RPC body builder; Params is nil for ping so the params
// member is omitted entirely.
type rpcCall struct {
	JSONRPC string     `json:"jsonrpc"`
	ID      int64      `json:"id"`
	Method  string     `json:"method"`
	Params  *rpcParams `json:"params,omitempty"`
}

type rpcParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments,omitempty"`
}

func rpcBody(id int64, tool string, args map[string]any) []byte {
	c := rpcCall{JSONRPC: "2.0", ID: id, Method: "ping"}
	if tool != "" {
		c.Method = "tools/call"
		c.Params = &rpcParams{Name: tool, Arguments: args}
	}
	b, err := json.Marshal(c)
	if err != nil {
		fatal("marshal rpc body: %v", err)
	}
	return b
}

// signer returns the signer for a fixture identity name.
func (e *env) signer(name string) client.Signer {
	if name == e.primaryName {
		return e.primary
	}
	s, ok := e.seeds[name]
	if !ok {
		fatal("unknown identity '%s'", name)
	}
	seed, err := hex.DecodeString(strings.ToLower(s.SeedHex))
	if err != nil || len(seed) != 32 {
		fatal("bad seed hex for identity '%s'", name)
	}
	signer, err := client.NewInMemorySigner(seed)
	if err != nil {
		fatal("signer for '%s': %v", name, err)
	}
	return signer
}

// kid returns the fixture kid of an identity.
func (e *env) kid(name string) string {
	s, ok := e.seeds[name]
	if !ok {
		fatal("unknown identity '%s'", name)
	}
	return s.Kid
}

// typed returns a memoized SDK client for an identity.
func (e *env) typed(name string) *client.Client {
	if c, ok := e.clients[name]; ok {
		return c
	}
	c, err := client.NewClient(client.Config{
		BaseURL:   e.baseURL + "/mcp",
		Aud:       e.aud,
		Signer:    e.signer(name),
		ServerKey: e.serverKey,
		HTTP:      e.typedHTTP,
	})
	if err != nil {
		fatal("client for '%s': %v", name, err)
	}
	e.clients[name] = c
	return c
}

// rawCall signs one request with a random (or pinned) nonce and timestamp,
// then sends it.
func (e *env) rawCall(signer client.Signer, method, target string, body []byte, tsOverride *time.Time, nonceB64 string) stepResult {
	var nonce []byte
	if nonceB64 != "" {
		var err error
		nonce, err = jack.DecodeBase64URLFixed(nonceB64, 16)
		if err != nil {
			fatal("nonce must decode to 16 bytes: %v", err)
		}
	} else {
		nonce = make([]byte, 16)
		if _, err := rand.Read(nonce); err != nil {
			fatal("nonce: %v", err)
		}
	}
	ts := time.Now()
	if tsOverride != nil {
		ts = *tsOverride
	}
	header, err := client.SignRequest(signer, e.aud, method, target, body, nonce, ts)
	if err != nil {
		fatal("SignRequest: %v", err)
	}
	auth, err := jack.ParseRequestAuth([]string{header})
	if err != nil {
		fatal("ParseRequestAuth: %v", err)
	}
	return e.sendWithHeader(header, auth.Sig, method, target, body)
}

// sendWithHeader sends exact pre-signed bytes and classifies the response.
func (e *env) sendWithHeader(header, requestSig, method, target string, body []byte) stepResult {
	req, err := http.NewRequest(method, e.baseURL+target, bytes.NewReader(body))
	if err != nil {
		fatal("build request: %v", err)
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Jack-Auth", header)
	resp, err := e.rawHTTP.Do(req)
	if err != nil {
		fatal("cannot connect: %v", err)
	}
	respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20+1))
	_ = resp.Body.Close()
	if readErr != nil {
		fatal("reading response body: %v", readErr)
	}
	status := resp.StatusCode
	headers := resp.Header.Values("Jack-Auth")
	wireCode := parseErrorBody(respBody)

	// 401 answers to failed authentication may be unsigned; if a header IS
	// present we still verify it and fail the client on a bad signature.
	if status == http.StatusUnauthorized && authFailureCodes[wireCode] {
		if len(headers) > 0 {
			if vErr := client.VerifyResponse(e.serverKey, status, headers, requestSig, respBody, time.Now(), 0); vErr != nil {
				var jErr *jack.Error
				if errors.As(vErr, &jErr) {
					return stepResult{kind: "client_error", code: jErr.Code}
				}
				fatal("verify response: %v", vErr)
			}
		}
		return stepResult{kind: "rejected", status: status, hasStatus: true, code: wireCode}
	}

	// Everything else must carry a valid signature (spec 01 section 5).
	if vErr := client.VerifyResponse(e.serverKey, status, headers, requestSig, respBody, time.Now(), 0); vErr != nil {
		var jErr *jack.Error
		if errors.As(vErr, &jErr) {
			return stepResult{kind: "client_error", code: jErr.Code}
		}
		fatal("verify response: %v", vErr)
	}
	// The typedRawCall helper factors the 2xx classification out of here.
	if status >= 200 && status < 300 {
		return resultFrom2xx(respBody)
	}
	return stepResult{kind: "rejected", status: status, hasStatus: true, code: wireCode}
}

// resultFrom2xx classifies a signature-verified 2xx JSON-RPC envelope; the
// result member is kept verbatim (interop README section 5: data is the
// result member verbatim).
func resultFrom2xx(body []byte) stepResult {
	var envelope struct {
		Result *json.RawMessage `json:"result"`
		Error  *struct {
			Code json.RawMessage `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		fatal("malformed json-rpc envelope: %v", err)
	}
	if envelope.Error != nil {
		return stepResult{kind: "rejected", status: http.StatusOK, hasStatus: true, code: rawMessageString(envelope.Error.Code)}
	}
	if envelope.Result == nil {
		fatal("malformed json-rpc envelope: no result member")
	}
	return stepResult{kind: "ok", status: http.StatusOK, hasStatus: true, data: *envelope.Result}
}

// parseErrorBody tolerantly extracts {"error":{"code":...}}.
func parseErrorBody(body []byte) string {
	var w struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &w); err != nil {
		return ""
	}
	return w.Error.Code
}

func rawMessageString(raw json.RawMessage) string {
	return string(bytes.Trim(raw, "\""))
}

// typedRawCall sends one tools/call through the shared signed transport
// (per-identity signer via the SDK's context override) and classifies the
// answer, keeping the JSON-RPC result member verbatim for reported data.
func (e *env) typedRawCall(signer client.Signer, tool string, args map[string]any) stepResult {
	body := rpcBody(1, tool, args)
	ctx := client.WithRequestSigner(context.Background(), signer)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.baseURL+"/mcp", bytes.NewReader(body))
	if err != nil {
		fatal("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.typedHTTP.Do(req)
	if err != nil {
		// Verification failures surface as transport errors; a returned
		// response is already signature-verified by the transport.
		return e.classifyTransportError(err)
	}
	respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20+1))
	_ = resp.Body.Close()
	if readErr != nil {
		fatal("reading response body: %v", readErr)
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return resultFrom2xx(respBody)
	}
	return stepResult{kind: "rejected", status: resp.StatusCode, hasStatus: true, code: parseErrorBody(respBody)}
}

// classifyTransportError maps an error returned by the shared signed
// transport: an unsigned 401 whose wire body code is one of the auth-failure
// codes is a wire rejection; any other unsigned 401 must not be acted on
// beyond its status (spec 01 section 5: absent header is missing_auth), and
// any other verification failure is client_error. Everything else is a
// harness-level failure. The wire code comes from the typedStash: the SDK
// deliberately never parses an unsigned 401 body.
func (e *env) classifyTransportError(err error) stepResult {
	var uErr *client.UnauthenticatedResponseError
	var jErr *jack.Error
	switch {
	case errors.As(err, &uErr):
		wireCode := parseErrorBody(e.typedStash.lastBody())
		if authFailureCodes[wireCode] {
			return stepResult{kind: "rejected", status: uErr.Status, hasStatus: true, code: wireCode}
		}
		return stepResult{kind: "client_error", code: jack.CodeMissingAuth}
	case errors.As(err, &jErr):
		return stepResult{kind: "client_error", code: jErr.Code}
	default:
		fatal("unexpected error from typed call: %v", err)
		return stepResult{}
	}
}

// sdkStep classifies one SDK typed call.
func (e *env) sdkStep(data any, err error) stepResult {
	var hErr *client.HTTPError
	var uErr *client.UnauthenticatedResponseError
	var rErr *client.RPCError
	var jErr *jack.Error
	switch {
	case err == nil:
		return stepResult{kind: "ok", status: http.StatusOK, hasStatus: true, data: data}
	case errors.As(err, &hErr):
		return stepResult{kind: "rejected", status: hErr.Status, hasStatus: true, code: hErr.Code}
	case errors.As(err, &uErr):
		// The transport only maps an unsigned (missing_auth) 401 to this
		// type: a 401 with an auth-failure wire body code is a wire
		// rejection; any other unsigned 401 is a client-side anomaly
		// (spec 01 section 5). The wire code comes from the typedStash —
		// the SDK never parses the unsigned body itself.
		wireCode := parseErrorBody(e.typedStash.lastBody())
		if authFailureCodes[wireCode] {
			return stepResult{kind: "rejected", status: uErr.Status, hasStatus: true, code: wireCode}
		}
		return stepResult{kind: "client_error", code: jack.CodeMissingAuth}
	case errors.As(err, &rErr):
		return stepResult{kind: "rejected", status: http.StatusOK, hasStatus: true, code: strconv.Itoa(rErr.Code)}
	case errors.As(err, &jErr):
		return stepResult{kind: "client_error", code: jErr.Code}
	default:
		fatal("unexpected error from typed call: %v", err)
		return stepResult{}
	}
}

// requireIntermediate checks a step's documented expectation; the second
// return is false when the caller must emit the failure wrapper.
func requireIntermediate(idx int, wantRejected bool, wantStatus int, wantCode string, got stepResult) (stepResult, bool) {
	matched := false
	if wantRejected {
		matched = got.kind == "rejected" && got.status == wantStatus && got.code == wantCode
	} else {
		matched = got.kind == "ok"
	}
	if matched {
		return got, true
	}
	out := stepResult{kind: "client_error", data: map[string]int{"step": idx}}
	if got.kind == "client_error" {
		out.code = got.code
	} else {
		// A failed intermediate carries its step's wire status (README 5).
		out.status = got.status
		out.hasStatus = true
		out.code = got.code
	}
	return out, false
}

var scenarios = map[string]func(*env) stepResult{
	"ping": func(e *env) stepResult {
		return e.rawCall(e.primary, http.MethodPost, "/mcp", rpcBody(1, "", nil), nil, "")
	},
	"echo": func(e *env) stepResult {
		text, ok := e.args["text"]
		if !ok {
			fatal("echo requires --arg text=...")
		}
		return e.rawCall(e.primary, http.MethodPost, "/mcp", rpcBody(1, "echo", map[string]any{"text": text}), nil, "")
	},
	"whoami": func(e *env) stepResult {
		return e.typedRawCall(e.signer(e.primaryName), client.ToolWhoAmI, nil)
	},
	"denied-tool": func(e *env) stepResult {
		return e.rawCall(e.primary, http.MethodPost, "/mcp", rpcBody(1, "svc.config.set", nil), nil, "")
	},
	"unmapped-tool": func(e *env) stepResult {
		return e.rawCall(e.primary, http.MethodPost, "/mcp", rpcBody(1, "other.tool", nil), nil, "")
	},
	"unknown-key": func(e *env) stepResult {
		return e.rawCall(e.primary, http.MethodPost, "/mcp", rpcBody(1, "svc.status", nil), nil, "")
	},
	"replay": func(e *env) stepResult {
		// Build the exact bytes and header ONCE; both sends reuse them.
		// ping is answered by the fixed handler (scenarios.json replay
		// step 0); svc.status would get a signed -32601 instead.
		body := rpcBody(1, "", nil)
		nonce := make([]byte, 16)
		if _, err := rand.Read(nonce); err != nil {
			fatal("nonce: %v", err)
		}
		header, err := client.SignRequest(e.primary, e.aud, http.MethodPost, "/mcp", body, nonce, time.Now())
		if err != nil {
			fatal("SignRequest: %v", err)
		}
		auth, err := jack.ParseRequestAuth([]string{header})
		if err != nil {
			fatal("ParseRequestAuth: %v", err)
		}
		first := e.sendWithHeader(header, auth.Sig, http.MethodPost, "/mcp", body)
		if out, ok := requireIntermediate(0, false, 0, "", first); !ok {
			return out
		}
		return e.sendWithHeader(header, auth.Sig, http.MethodPost, "/mcp", body)
	},
	"clock-skew": func(e *env) stepResult {
		ts := time.Now().Add(-120 * time.Second)
		return e.rawCall(e.primary, http.MethodPost, "/mcp", rpcBody(1, "svc.status", nil), &ts, "")
	},
	"tampered-body": func(e *env) stepResult {
		body := rpcBody(1, "svc.restart", nil)
		nonce := make([]byte, 16)
		if _, err := rand.Read(nonce); err != nil {
			fatal("nonce: %v", err)
		}
		header, err := client.SignRequest(e.primary, e.aud, http.MethodPost, "/mcp", body, nonce, time.Now())
		if err != nil {
			fatal("SignRequest: %v", err)
		}
		auth, err := jack.ParseRequestAuth([]string{header})
		if err != nil {
			fatal("ParseRequestAuth: %v", err)
		}
		// Mutate AFTER signing: final '}' (0x7D) becomes '|' (0x7C).
		mutated := append([]byte(nil), body...)
		mutated[len(mutated)-1] = 0x7C
		return e.sendWithHeader(header, auth.Sig, http.MethodPost, "/mcp", mutated)
	},
	// The harness pins the WRONG key (mallory) for this scenario; the signed
	// 200 answer then fails client verification.
	"bad-server-key": func(e *env) stepResult {
		return e.rawCall(e.primary, http.MethodPost, "/mcp", rpcBody(1, "", nil), nil, "")
	},
	"expired-key": func(e *env) stepResult {
		return e.rawCall(e.primary, http.MethodPost, "/mcp", rpcBody(1, "svc.status", nil), nil, "")
	},
	"key-not-yet-valid": func(e *env) stepResult {
		return e.rawCall(e.primary, http.MethodPost, "/mcp", rpcBody(1, "svc.status", nil), nil, "")
	},
	"stream": func(e *env) stepResult {
		return e.rawCall(e.primary, http.MethodGet, "/sse", nil, nil, "")
	},
	"agent-admin": func(e *env) stepResult {
		return e.typedRawCall(e.signer(e.primaryName), client.ToolAdminUserList, nil)
	},
	"invalid-request": func(e *env) stepResult {
		return e.rawCall(e.primary, http.MethodPost, "/mcp", []byte("this is not JSON"), nil, "")
	},
	"unknown-native-tool": func(e *env) stepResult {
		return e.rawCall(e.primary, http.MethodPost, "/mcp", rpcBody(1, "jack.admin.nuke", nil), nil, "")
	},
	"enroll": func(e *env) stepResult {
		ctx := context.Background()
		inv, err := e.typed("root").AdminInviteCreate(ctx, client.InviteCreateParams{Scopes: []string{"read"}})
		if out, ok := requireIntermediate(0, false, 0, "", e.sdkStep(nil, err)); !ok {
			return out
		}
		_, err = e.typed(e.primaryName).Enroll(ctx, inv.Code, "newbie", e.signer(e.primaryName))
		if out, ok := requireIntermediate(1, false, 0, "", e.sdkStep(nil, err)); !ok {
			return out
		}
		return e.typedRawCall(e.signer(e.primaryName), client.ToolWhoAmI, nil)
	},
	"enroll-used-invite": func(e *env) stepResult {
		ctx := context.Background()
		inv, err := e.typed("root").AdminInviteCreate(ctx, client.InviteCreateParams{Scopes: []string{"read"}})
		if out, ok := requireIntermediate(0, false, 0, "", e.sdkStep(nil, err)); !ok {
			return out
		}
		_, err = e.typed("newbie").Enroll(ctx, inv.Code, "newbie", e.signer("newbie"))
		if out, ok := requireIntermediate(1, false, 0, "", e.sdkStep(nil, err)); !ok {
			return out
		}
		return e.typedRawCall(e.signer(e.primaryName), client.ToolEnroll, map[string]any{
			"code":       inv.Code,
			"name":       "newbie2",
			"public_key": jack.EncodeBase64URL(e.signer(e.primaryName).PublicKey()),
		})
	},
	"rotate": func(e *env) stepResult {
		ctx := context.Background()
		_, err := e.typed(e.primaryName).RotateKey(ctx, e.signer("newbie"))
		if out, ok := requireIntermediate(0, false, 0, "", e.sdkStep(nil, err)); !ok {
			return out
		}
		// The old alice key must now be dead (unsigned 401 unknown_key).
		_, err = e.typed(e.primaryName).WhoAmI(ctx)
		if out, ok := requireIntermediate(1, true, http.StatusUnauthorized, "unknown_key", e.sdkStep(nil, err)); !ok {
			return out
		}
		return e.typedRawCall(e.signer("newbie"), client.ToolWhoAmI, nil)
	},
	"admin-create": func(e *env) stepResult {
		ctx := context.Background()
		inv, err := e.typed("root").AdminInviteCreate(ctx, client.InviteCreateParams{Scopes: []string{"read"}})
		if out, ok := requireIntermediate(0, false, 0, "", e.sdkStep(nil, err)); !ok {
			return out
		}
		_, err = e.typed("root").AdminUserCreate(ctx, client.UserCreateParams{
			Name:      "dave",
			PublicKey: jack.EncodeBase64URL(e.signer(e.primaryName).PublicKey()),
			Scopes:    []string{"read"},
		})
		if out, ok := requireIntermediate(1, false, 0, "", e.sdkStep(nil, err)); !ok {
			return out
		}
		_, err = e.typed("newbie").Enroll(ctx, inv.Code, "newbie", e.signer("newbie"))
		if out, ok := requireIntermediate(2, false, 0, "", e.sdkStep(nil, err)); !ok {
			return out
		}
		return e.typedRawCall(e.signer(e.primaryName), client.ToolWhoAmI, nil)
	},
	"revoke-key": func(e *env) stepResult {
		ctx := context.Background()
		_, err := e.typed("root").AdminUserRevoke(ctx, e.kid("bob"))
		if out, ok := requireIntermediate(0, false, 0, "", e.sdkStep(nil, err)); !ok {
			return out
		}
		return e.typedRawCall(e.signer(e.primaryName), client.ToolWhoAmI, nil)
	},
	"last-admin": func(e *env) stepResult {
		return e.typedRawCall(e.signer(e.primaryName), client.ToolAdminUserSetScopes, map[string]any{
			"kid":    e.primary.KID(),
			"scopes": []string{"read"},
		})
	},
}
