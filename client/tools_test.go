package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	spec "github.com/PHPCraftdream/mcp-jack/spec"
)

// adminCase finds the named case in the admin vectors.
func adminCase(t *testing.T, id string) spec.AdminCase {
	t.Helper()
	vec, err := spec.LoadAdminVectors()
	if err != nil {
		t.Fatalf("spec.LoadAdminVectors: %v", err)
	}
	for _, c := range vec.Cases {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("admin vectors have no case %q", id)
	return spec.AdminCase{}
}

// fixtureHeaderValue returns the named header value of a fixture request.
func fixtureHeaderValue(t *testing.T, req spec.FixtureRequest, name string) string {
	t.Helper()
	for _, h := range req.Headers {
		if h.Name == name {
			return h.Value
		}
	}
	t.Fatalf("fixture request has no %q header", name)
	return ""
}

// fixtureNonce extracts the base64url nonce from a fixture Jack-Auth header.
func fixtureNonce(t *testing.T, headerValue string) string {
	t.Helper()
	auth, err := jack.ParseRequestAuth([]string{headerValue})
	if err != nil {
		t.Fatalf("jack.ParseRequestAuth(%q): %v", headerValue, err)
	}
	return auth.Nonce
}

// fixtureBody decodes the exact request body bytes of a fixture step.
func fixtureBody(t *testing.T, step spec.Step) []byte {
	t.Helper()
	body, err := step.Request.Body()
	if err != nil {
		t.Fatalf("step.Request.Body(): %v", err)
	}
	return body
}

// newFixtureClient builds a Client pinned to srv with the given signer and
// one queued nonce per call (variadic: a test making N calls queues N
// nonces), clocked at fixtureNow.
func newFixtureClient(t *testing.T, srv *testServer, signer Signer, nonceB64 ...string) *Client {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	u.Path = "/mcp"
	c, err := NewClient(Config{
		BaseURL:   u.String(),
		Aud:       fixtureAud,
		Signer:    signer,
		ServerKey: srv.Pub,
		Now:       fixedClock(fixtureNow),
		Window:    30 * time.Second,
		Nonce:     queuedNonce(t, nonceB64...),
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

// assertFixtureRequest compares the captured request against the fixture:
// header byte-for-byte, method/target exactly, body decoded DeepEqual and
// (softly) byte-identical.
func assertFixtureRequest(t *testing.T, step spec.Step, gotHeader, gotMethod, gotTarget string, gotBody []byte) {
	t.Helper()
	wantHeader := fixtureHeaderValue(t, step.Request, "Jack-Auth")
	if gotHeader != wantHeader {
		t.Errorf("Jack-Auth header = %q, want fixture %q", gotHeader, wantHeader)
	}
	if gotMethod != step.Request.Method {
		t.Errorf("method = %q, want %q", gotMethod, step.Request.Method)
	}
	if gotTarget != step.Request.Target {
		t.Errorf("target = %q, want %q", gotTarget, step.Request.Target)
	}
	wantBody := fixtureBody(t, step)
	var gotAny, wantAny any
	if err := json.Unmarshal(gotBody, &gotAny); err != nil {
		t.Fatalf("captured body does not decode: %v", err)
	}
	if err := json.Unmarshal(wantBody, &wantAny); err != nil {
		t.Fatalf("fixture body does not decode: %v", err)
	}
	if !reflect.DeepEqual(gotAny, wantAny) {
		t.Errorf("decoded body mismatch:\n got  %s\n want %s", gotBody, wantBody)
	}
	if string(gotBody) != string(wantBody) {
		t.Errorf("body bytes differ from fixture bytes:\n got  %q\n want %q", gotBody, wantBody)
	}
}

func TestEnrollMatchesFixture(t *testing.T) {
	c := adminCase(t, "enroll-ok")
	if len(c.Steps) == 0 {
		t.Fatalf("case enroll-ok has no steps")
	}
	step := c.Steps[0]

	srv := newTestServer(t)
	wantStructured := step.Expect.Structured
	var gotHeader, gotMethod, gotTarget string
	var gotBody []byte
	srv.Handle = func(w http.ResponseWriter, auth jack.RequestAuth, body []byte) {
		gotHeader = jack.FormatRequestAuth(auth)
		gotMethod = "POST"
		gotTarget = "/mcp"
		gotBody = body
		srv.writeSignedJSON(w, auth, http.StatusOK, rpcResultBody(wantStructured))
	}

	headerValue := fixtureHeaderValue(t, step.Request, "Jack-Auth")
	client := newFixtureClient(t, srv, seedSignerByName(t, "newbie"), fixtureNonce(t, headerValue))

	res, err := client.Enroll(context.Background(),
		"NTpoPAFYwVkAdj8kps_x_Q_pgjkaWP-pvdbaV0eQau4", "newbie",
		seedSignerByName(t, "newbie"))
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	assertFixtureRequest(t, step, gotHeader, gotMethod, gotTarget, gotBody)

	want := EnrollResult{
		KID:   "imZX4AkHSrS_UT1wZ5oEPklelGqIooKk4TfK3ht5LYg",
		Name:  "newbie",
		Admin: false,
	}
	if !reflect.DeepEqual(res, want) {
		t.Errorf("EnrollResult = %+v, want %+v", res, want)
	}
}

func TestRotateMatchesFixture(t *testing.T) {
	c := adminCase(t, "rotate-ok")
	if len(c.Steps) == 0 {
		t.Fatalf("case rotate-ok has no steps")
	}
	step := c.Steps[0]

	srv := newTestServer(t)
	var gotHeader, gotMethod, gotTarget string
	var gotBody []byte
	srv.Handle = func(w http.ResponseWriter, auth jack.RequestAuth, body []byte) {
		gotHeader = jack.FormatRequestAuth(auth)
		gotMethod = "POST"
		gotTarget = "/mcp"
		gotBody = body
		srv.writeSignedJSON(w, auth, http.StatusOK, rpcResultBody(step.Expect.Structured))
	}

	headerValue := fixtureHeaderValue(t, step.Request, "Jack-Auth")
	aliceSigner := seedSignerByName(t, "alice")
	newbieSigner := seedSignerByName(t, "newbie")
	client := newFixtureClient(t, srv, aliceSigner, fixtureNonce(t, headerValue))

	res, err := client.RotateKey(context.Background(), newbieSigner)
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}

	assertFixtureRequest(t, step, gotHeader, gotMethod, gotTarget, gotBody)

	var req jsonrpcRequest
	if err := json.Unmarshal(gotBody, &req); err != nil {
		t.Fatalf("captured body does not decode as jsonrpc request: %v", err)
	}
	var args map[string]any
	if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
		t.Fatalf("arguments do not decode: %v", err)
	}
	if args["public_key"] != "71JMCNs18t7E5IysFMZEKsnlr9Cw0kahC_h5FkDWrdQ" {
		t.Errorf("arguments[public_key] = %v, want newbie public key", args["public_key"])
	}
	proof, ok := args["proof"].(string)
	if !ok {
		t.Fatalf("arguments[proof] = %v (%T), want a string", args["proof"], args["proof"])
	}

	// Independent re-derivation of the proof from the primitives
	// (spec 03 section 3.1): the client must have signed exactly
	// RotateProofString(aud, oldKid, newKid, fixtureNow).
	proofBytes, err := jack.DecodeBase64URLFixed(proof, 64)
	if err != nil {
		t.Fatalf("DecodeBase64URLFixed(proof): %v", err)
	}
	msg := []byte(jack.RotateProofString(fixtureAud, aliceSigner.KID(), newbieSigner.KID(), fixtureNow))
	if !jack.Verify(newbieSigner.PublicKey(), msg, proofBytes) {
		t.Errorf("rotate proof does not verify under the newbie key over %q", msg)
	}

	if res.KID != "imZX4AkHSrS_UT1wZ5oEPklelGqIooKk4TfK3ht5LYg" {
		t.Errorf("KidResult.KID = %q, want imZX4AkHSrS_UT1wZ5oEPklelGqIooKk4TfK3ht5LYg", res.KID)
	}
}

func TestWhoAmIDecodesResult(t *testing.T) {
	srv := newTestServer(t)
	srv.Handle = func(w http.ResponseWriter, auth jack.RequestAuth, _ []byte) {
		srv.writeSignedJSON(w, auth, http.StatusOK, rpcResultBody(json.RawMessage(
			`{"kid":"imZX4AkHSrS_UT1wZ5oEPklelGqIooKk4TfK3ht5LYg","name":"newbie","admin":false,"not_before":null,"not_after":null}`)))
	}

	client := newFixtureClient(t, srv, seedSignerByName(t, "newbie"), "assryd677-uYrqD4v-7HYw")
	res, err := client.WhoAmI(context.Background())
	if err != nil {
		t.Fatalf("WhoAmI: %v", err)
	}
	if res.KID != "imZX4AkHSrS_UT1wZ5oEPklelGqIooKk4TfK3ht5LYg" {
		t.Errorf("KID = %q, want imZX4AkHSrS_UT1wZ5oEPklelGqIooKk4TfK3ht5LYg", res.KID)
	}
	if res.Name != "newbie" {
		t.Errorf("Name = %q, want newbie", res.Name)
	}
	if res.Admin {
		t.Errorf("Admin = true, want false")
	}
	if res.NotBefore != nil {
		t.Errorf("NotBefore = %v, want nil", res.NotBefore)
	}
	if res.NotAfter != nil {
		t.Errorf("NotAfter = %v, want nil", res.NotAfter)
	}
}

func TestAdminListDecodesWrappers(t *testing.T) {
	srv := newTestServer(t)
	srv.Handle = func(w http.ResponseWriter, auth jack.RequestAuth, body []byte) {
		if strings.Contains(string(body), `"jack.admin.user.list"`) {
			srv.writeSignedJSON(w, auth, http.StatusOK, rpcResultBody(json.RawMessage(
				`{"users":[{"kid":"k1","public_key":"p1","name":"alice","admin":false,"not_before":null,"not_after":1750000000}]}`)))
			return
		}
		srv.writeSignedJSON(w, auth, http.StatusOK, rpcResultBody(json.RawMessage(
			`{"invites":[{"invite_id":"iv1","admin":false,"created_by":"k1","created_at":1767225500,"expires_at":1767228600}]}`)))
	}

	client := newFixtureClient(t, srv, seedSignerByName(t, "alice"), "assryd677-uYrqD4v-7HYw", "assryd677-uYrqD4v-7HYw")

	users, err := client.AdminUserList(context.Background())
	if err != nil {
		t.Fatalf("AdminUserList: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("len(users) = %d, want 1", len(users))
	}
	if users[0].Admin {
		t.Errorf("users[0].Admin = true, want false")
	}
	if users[0].NotAfter == nil || *users[0].NotAfter != 1750000000 {
		t.Errorf("users[0].NotAfter = %v, want 1750000000", users[0].NotAfter)
	}

	invites, err := client.AdminInviteList(context.Background())
	if err != nil {
		t.Fatalf("AdminInviteList: %v", err)
	}
	if len(invites) != 1 {
		t.Fatalf("len(invites) = %d, want 1", len(invites))
	}
	if invites[0].Admin {
		t.Errorf("invites[0].Admin = true, want false")
	}
	if invites[0].InviteID != "iv1" {
		t.Errorf("invites[0].InviteID = %q, want iv1", invites[0].InviteID)
	}
	if invites[0].ExpiresAt != 1767228600 {
		t.Errorf("invites[0].ExpiresAt = %d, want 1767228600", invites[0].ExpiresAt)
	}
}

func TestToolCallHTTPError(t *testing.T) {
	srv := newTestServer(t)
	srv.Handle = func(w http.ResponseWriter, auth jack.RequestAuth, _ []byte) {
		srv.writeSignedJSON(w, auth, http.StatusForbidden, []byte(`{"error":{"code":"admin_required","message":"no"}}`))
	}

	client := newFixtureClient(t, srv, seedSignerByName(t, "alice"), "assryd677-uYrqD4v-7HYw")
	_, err := client.AdminUserGet(context.Background(), "k1")
	if err == nil {
		t.Fatalf("AdminUserGet err = nil, want *HTTPError")
	}
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("err = %T (%v), want *HTTPError", err, err)
	}
	if httpErr.Status != http.StatusForbidden {
		t.Errorf("Status = %d, want 403", httpErr.Status)
	}
	if httpErr.Code != "admin_required" {
		t.Errorf("Code = %q, want admin_required", httpErr.Code)
	}
}

func TestToolCallToolError(t *testing.T) {
	srv := newTestServer(t)
	srv.Handle = func(w http.ResponseWriter, auth jack.RequestAuth, _ []byte) {
		body := []byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"boom"}],"isError":true}}`)
		srv.writeSignedJSON(w, auth, http.StatusOK, body)
	}

	client := newFixtureClient(t, srv, seedSignerByName(t, "alice"), "assryd677-uYrqD4v-7HYw")
	_, err := client.WhoAmI(context.Background())
	if err == nil {
		t.Fatalf("WhoAmI err = nil, want *ToolError")
	}
	var toolErr *ToolError
	if !errors.As(err, &toolErr) {
		t.Fatalf("err = %T (%v), want *ToolError", err, err)
	}
	if toolErr.Message != "boom" {
		t.Errorf("Message = %q, want boom", toolErr.Message)
	}
}

const callToolNonce = "assryd677-uYrqD4v-7HYw"

// callToolRecorder captures request bodies seen by a test server handler.
type callToolRecorder struct {
	mu     sync.Mutex
	hits   int32
	bodies [][]byte
}

func (r *callToolRecorder) add(body []byte) {
	atomic.AddInt32(&r.hits, 1)
	r.mu.Lock()
	r.bodies = append(r.bodies, append([]byte(nil), body...))
	r.mu.Unlock()
}

func (r *callToolRecorder) last() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.bodies) == 0 {
		return nil
	}
	return r.bodies[len(r.bodies)-1]
}

// callToolServer starts a test server whose handler records the request body
// and delegates the reply to reply.
func callToolServer(t *testing.T, reply func(s *testServer, w http.ResponseWriter, auth jack.RequestAuth)) (*testServer, *callToolRecorder) {
	t.Helper()
	srv := newTestServer(t)
	rec := &callToolRecorder{}
	srv.Handle = func(w http.ResponseWriter, auth jack.RequestAuth, body []byte) {
		rec.add(body)
		reply(srv, w, auth)
	}
	return srv, rec
}

// callToolClient builds a client with n copies of the fixed nonce queued.
func callToolClient(t *testing.T, srv *testServer, n int) *Client {
	t.Helper()
	nonces := make([]string, n)
	for i := range nonces {
		nonces[i] = callToolNonce
	}
	return newFixtureClient(t, srv, seedSignerByName(t, "alice"), nonces...)
}

type callToolRequest struct {
	Method string `json:"method"`
	Params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	} `json:"params"`
}

func callToolDecodeRequest(t *testing.T, body []byte) callToolRequest {
	t.Helper()
	var req callToolRequest
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("decode request body %q: %v", body, err)
	}
	return req
}

func callToolOK(structured string) func(s *testServer, w http.ResponseWriter, auth jack.RequestAuth) {
	return func(s *testServer, w http.ResponseWriter, auth jack.RequestAuth) {
		s.writeSignedJSON(w, auth, http.StatusOK, rpcResultBody(json.RawMessage(structured)))
	}
}

func TestCallToolRoundTrip(t *testing.T) {
	const structured = `{"status":"restarted","count":3,"note":"héllo 世界 🚀","nested":{"ids":[1,2]}}`
	args := map[string]any{
		"name": "héllo 世界 🚀",
		"opts": map[string]any{"retries": 3, "tags": []any{"a", "b"}},
	}
	type result struct {
		Status string `json:"status"`
		Count  int    `json:"count"`
		Note   string `json:"note"`
		Nested struct {
			IDs []int `json:"ids"`
		} `json:"nested"`
	}

	srv, rec := callToolServer(t, callToolOK(structured))
	c := callToolClient(t, srv, 2)

	t.Run("typed", func(t *testing.T) {
		var res result
		if err := c.CallTool(context.Background(), "svc.restart", args, &res); err != nil {
			t.Fatalf("CallTool: %v", err)
		}
		if res.Status != "restarted" || res.Count != 3 || res.Note != "héllo 世界 🚀" || !reflect.DeepEqual(res.Nested.IDs, []int{1, 2}) {
			t.Fatalf("decoded result = %+v", res)
		}
		req := callToolDecodeRequest(t, rec.last())
		if req.Method != "tools/call" || req.Params.Name != "svc.restart" {
			t.Fatalf("request method/name = %q/%q", req.Method, req.Params.Name)
		}
		var got, want any
		if err := json.Unmarshal(req.Params.Arguments, &got); err != nil {
			t.Fatalf("decode arguments: %v", err)
		}
		wantRaw, err := json.Marshal(args)
		if err != nil {
			t.Fatalf("marshal want: %v", err)
		}
		if err := json.Unmarshal(wantRaw, &want); err != nil {
			t.Fatalf("decode want: %v", err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("arguments = %v, want %v", got, want)
		}
	})

	t.Run("raw", func(t *testing.T) {
		var raw json.RawMessage
		if err := c.CallTool(context.Background(), "svc.restart", args, &raw); err != nil {
			t.Fatalf("CallTool: %v", err)
		}
		var gotBuf, wantBuf bytes.Buffer
		if err := json.Compact(&gotBuf, raw); err != nil {
			t.Fatalf("compact raw %q: %v", raw, err)
		}
		if err := json.Compact(&wantBuf, []byte(structured)); err != nil {
			t.Fatalf("compact want: %v", err)
		}
		if !bytes.Equal(gotBuf.Bytes(), wantBuf.Bytes()) {
			t.Fatalf("raw = %s, want %s", gotBuf.Bytes(), wantBuf.Bytes())
		}
	})
}

func TestCallToolNilArgumentsAndNilOut(t *testing.T) {
	cases := []struct {
		name       string
		reply      func(s *testServer, w http.ResponseWriter, auth jack.RequestAuth)
		wantErrSub string
	}{
		{"payload ignored", callToolOK(`{"status":"restarted"}`), ""},
		{"undecodable payload ignored", callToolOK(`[1,"x",{"a":null}]`), ""},
		{"missing structuredContent still errors", func(s *testServer, w http.ResponseWriter, auth jack.RequestAuth) {
			s.writeSignedJSON(w, auth, http.StatusOK, []byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}],"isError":false}}`))
		}, "missing structuredContent"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, rec := callToolServer(t, tc.reply)
			c := callToolClient(t, srv, 1)
			err := c.CallTool(context.Background(), "svc.restart", nil, nil)
			if tc.wantErrSub == "" {
				if err != nil {
					t.Fatalf("CallTool: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantErrSub) {
				t.Fatalf("err = %v, want containing %q", err, tc.wantErrSub)
			}
			req := callToolDecodeRequest(t, rec.last())
			if string(req.Params.Arguments) != "{}" {
				t.Fatalf("arguments = %s, want {}", req.Params.Arguments)
			}
		})
	}
}

// callToolTampered signs body A but sends body B.
func callToolTampered(s *testServer, w http.ResponseWriter, auth jack.RequestAuth) {
	signed := rpcResultBody(json.RawMessage(`{"status":"signed"}`))
	sent := rpcResultBody(json.RawMessage(`{"status":"tampered"}`))
	msg := []byte(jack.ResponseSigningString(http.StatusOK, auth.Sig, s.Kid, s.Now, signed))
	sig := ed25519.Sign(s.Key, msg)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Jack-Auth", jack.FormatResponseAuth(jack.ResponseAuth{Kid: s.Kid, TS: s.Now, Sig: jack.EncodeBase64URL(sig)}))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(sent)
}

func TestCallToolErrors(t *testing.T) {
	signedErr := func(status int, body string) func(s *testServer, w http.ResponseWriter, auth jack.RequestAuth) {
		return func(s *testServer, w http.ResponseWriter, auth jack.RequestAuth) {
			s.writeSignedJSON(w, auth, status, []byte(body))
		}
	}
	cases := []struct {
		name  string
		reply func(s *testServer, w http.ResponseWriter, auth jack.RequestAuth)
		check func(t *testing.T, err error)
	}{
		{"http 403", signedErr(http.StatusForbidden, `{"error":{"code":"admin_required","message":"no"}}`), func(t *testing.T, err error) {
			var he *HTTPError
			if !errors.As(err, &he) {
				t.Fatalf("err = %T (%v), want *HTTPError", err, err)
			}
			if he.Status != http.StatusForbidden || he.Code != "admin_required" {
				t.Fatalf("HTTPError = %+v", he)
			}
		}},
		{"http 500", signedErr(http.StatusInternalServerError, `{"error":{"code":"internal","message":"bad"}}`), func(t *testing.T, err error) {
			var he *HTTPError
			if !errors.As(err, &he) {
				t.Fatalf("err = %T (%v), want *HTTPError", err, err)
			}
			if he.Status != http.StatusInternalServerError || he.Code != "internal" {
				t.Fatalf("HTTPError = %+v", he)
			}
		}},
		{"rpc error", signedErr(http.StatusOK, `{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"bad params"}}`), func(t *testing.T, err error) {
			var re *RPCError
			if !errors.As(err, &re) {
				t.Fatalf("err = %T (%v), want *RPCError", err, err)
			}
			if re.Code != -32602 || re.Message != "bad params" {
				t.Fatalf("RPCError = %+v", re)
			}
		}},
		{"tool error", signedErr(http.StatusOK, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"boom"}],"isError":true,"structuredContent":{"why":"x"}}}`), func(t *testing.T, err error) {
			var te *ToolError
			if !errors.As(err, &te) {
				t.Fatalf("err = %T (%v), want *ToolError", err, err)
			}
			if te.Message != "boom" || string(te.Structured) != `{"why":"x"}` {
				t.Fatalf("ToolError = %+v (structured %s)", te, te.Structured)
			}
		}},
		{"unsigned 200 refused", func(s *testServer, w http.ResponseWriter, _ jack.RequestAuth) {
			s.writeUnsignedJSON(w, http.StatusOK, rpcResultBody(json.RawMessage(`{"status":"unsigned"}`)))
		}, func(t *testing.T, err error) {
			callToolWantJackCode(t, err, jack.CodeMissingAuth)
		}},
		{"tampered body refused", callToolTampered, func(t *testing.T, err error) {
			callToolWantJackCode(t, err, jack.CodeBadSignature)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := callToolServer(t, tc.reply)
			c := callToolClient(t, srv, 1)
			var out json.RawMessage
			err := c.CallTool(context.Background(), "svc.restart", map[string]any{"a": 1}, &out)
			if err == nil {
				t.Fatalf("CallTool succeeded with out=%s", out)
			}
			if len(out) != 0 {
				t.Fatalf("out touched on error: %s", out)
			}
			tc.check(t, err)
		})
	}
}

func callToolWantJackCode(t *testing.T, err error, code string) {
	t.Helper()
	var je *jack.Error
	if !errors.As(err, &je) {
		t.Fatalf("err = %T (%v), want *jack.Error %s", err, err, code)
	}
	if je.Code != code {
		t.Fatalf("jack code = %q, want %q", je.Code, code)
	}
	var he *HTTPError
	var re *RPCError
	var te *ToolError
	if errors.As(err, &he) || errors.As(err, &re) || errors.As(err, &te) {
		t.Fatalf("untrusted response surfaced as application error: %v", err)
	}
}

func TestCallToolLocalFailures(t *testing.T) {
	t.Run("marshal failure", func(t *testing.T) {
		cases := []struct {
			name string
			args any
		}{
			{"channel", map[string]any{"c": make(chan int)}},
			{"func", map[string]any{"f": func() {}}},
			{"NaN", map[string]any{"n": math.NaN()}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				srv, rec := callToolServer(t, callToolOK(`{}`))
				c := callToolClient(t, srv, 1)
				err := c.CallTool(context.Background(), "svc.restart", tc.args, nil)
				if err == nil || !strings.Contains(err.Error(), "marshal arguments") {
					t.Fatalf("err = %v, want marshal arguments error", err)
				}
				if n := atomic.LoadInt32(&rec.hits); n != 0 {
					t.Fatalf("server hit %d times, want 0", n)
				}
			})
		}
	})

	t.Run("decode failure", func(t *testing.T) {
		srv, _ := callToolServer(t, callToolOK(`{"a":1}`))
		c := callToolClient(t, srv, 1)
		var n int
		err := c.CallTool(context.Background(), "svc.restart", nil, &n)
		if err == nil {
			t.Fatal("decode into *int succeeded")
		}
		var ute *json.UnmarshalTypeError
		if !errors.As(err, &ute) {
			t.Fatalf("err = %T (%v), want *json.UnmarshalTypeError", err, err)
		}
		var he *HTTPError
		var te *ToolError
		if errors.As(err, &he) || errors.As(err, &te) {
			t.Fatalf("decode error surfaced as application error: %v", err)
		}
	})

	t.Run("canceled context", func(t *testing.T) {
		srv, rec := callToolServer(t, callToolOK(`{}`))
		c := callToolClient(t, srv, 1)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := c.CallTool(ctx, "svc.restart", nil, nil)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
		if n := atomic.LoadInt32(&rec.hits); n != 0 {
			t.Fatalf("server hit %d times, want 0", n)
		}
	})
}

// adminAPIRecorder records the bodies of native calls seen by the stub server.
type adminAPIRecorder struct {
	mu     sync.Mutex
	bodies [][]byte
}

func (r *adminAPIRecorder) add(body []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.bodies = append(r.bodies, append([]byte(nil), body...))
}

func (r *adminAPIRecorder) at(i int) []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	if i >= len(r.bodies) {
		return nil
	}
	return r.bodies[i]
}

// count returns the number of captured bodies under the recorder mutex.
func (r *adminAPIRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.bodies)
}

// decodeAdminArguments decodes the tools/call params of a captured request.
func decodeAdminArguments(t *testing.T, body []byte) (tool string, args map[string]json.RawMessage) {
	t.Helper()
	var req struct {
		Method string `json:"method"`
		Params struct {
			Name      string                     `json:"name"`
			Arguments map[string]json.RawMessage `json:"arguments"`
		} `json:"params"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("decode request body %q: %v", body, err)
	}
	return req.Params.Name, req.Params.Arguments
}

// adminArgIs asserts one argument member carries exactly the given JSON text.
func adminArgIs(t *testing.T, args map[string]json.RawMessage, key, want string) {
	t.Helper()
	raw, ok := args[key]
	if !ok {
		t.Fatalf("arguments lack %q, want %s", key, want)
	}
	if string(raw) != want {
		t.Fatalf("arguments[%q] = %s, want %s", key, raw, want)
	}
}

// adminArgAbsent asserts an optional argument member was NOT serialized.
func adminArgAbsent(t *testing.T, args map[string]json.RawMessage, key string) {
	t.Helper()
	if raw, ok := args[key]; ok {
		t.Fatalf("arguments carry %q = %s, want the member absent", key, raw)
	}
}

// TestAdminUserSetAdminWireAndDecode drives the migrated typed API: admin is
// REQUIRED on the wire, so an explicit false must serialize (an omitempty or
// drop-when-false implementation fails), the tool name must be
// jack.admin.user.set_admin, and the result admin flag must decode into
// Entry.Admin per call (a decoder that silently ignored the member would
// decode false), together with the other result fields.
func TestAdminUserSetAdminWireAndDecode(t *testing.T) {
	srv := newTestServer(t)
	rec := &adminAPIRecorder{}
	srv.Handle = func(w http.ResponseWriter, auth jack.RequestAuth, body []byte) {
		rec.add(body)
		var result string
		switch rec.count() {
		case 1:
			result = `{"kid":"k1","public_key":"p1","name":"alice","admin":false,"not_before":null,"not_after":null}`
		default:
			result = `{"kid":"k1","public_key":"p1","name":"alice","admin":true,"not_before":null,"not_after":null}`
		}
		srv.writeSignedJSON(w, auth, http.StatusOK, rpcResultBody(json.RawMessage(result)))
	}
	client := newFixtureClient(t, srv, seedSignerByName(t, "root"), callToolNonce, callToolNonce)

	entry, err := client.AdminUserSetAdmin(context.Background(), "k1", false)
	if err != nil {
		t.Fatalf("AdminUserSetAdmin(false): %v", err)
	}
	tool, args := decodeAdminArguments(t, rec.at(0))
	if tool != "jack.admin.user.set_admin" {
		t.Fatalf("tool = %q, want %q", tool, "jack.admin.user.set_admin")
	}
	adminArgIs(t, args, "kid", `"k1"`)
	adminArgIs(t, args, "admin", `false`)
	if entry.Admin {
		t.Fatalf("Entry.Admin = true, want false (the result carried admin false)")
	}
	if entry.KID != "k1" || entry.Name != "alice" {
		t.Fatalf("Entry = %+v, want kid k1 name alice", entry)
	}

	entry, err = client.AdminUserSetAdmin(context.Background(), "k1", true)
	if err != nil {
		t.Fatalf("AdminUserSetAdmin(true): %v", err)
	}
	_, args = decodeAdminArguments(t, rec.at(1))
	adminArgIs(t, args, "admin", `true`)
	if !entry.Admin {
		t.Fatalf("Entry.Admin = false, want true")
	}
	if entry.KID != "k1" || entry.Name != "alice" {
		t.Fatalf("Entry = %+v, want kid k1 name alice", entry)
	}
}

// TestAdminUserCreateAdminNilVsExplicitFalse discriminates the OPTIONAL admin
// argument of jack.admin.user.create: nil omits the member entirely, and an
// explicit &false serializes `"admin":false` (spec 03 section 3: present
// members are read by exact name; only an explicit member can be mistyped).
func TestAdminUserCreateAdminNilVsExplicitFalse(t *testing.T) {
	srv := newTestServer(t)
	rec := &adminAPIRecorder{}
	srv.Handle = func(w http.ResponseWriter, auth jack.RequestAuth, body []byte) {
		rec.add(body)
		kid := "new-kid"
		if rec.count() > 1 {
			kid = "new-kid-2"
		}
		srv.writeSignedJSON(w, auth, http.StatusOK, rpcResultBody(json.RawMessage(`{"kid":"`+kid+`"}`)))
	}
	client := newFixtureClient(t, srv, seedSignerByName(t, "root"), callToolNonce, callToolNonce)

	falseVal := false
	res, err := client.AdminUserCreate(context.Background(), UserCreateParams{Name: "newbie", PublicKey: "pk-new", Admin: &falseVal})
	if err != nil {
		t.Fatalf("AdminUserCreate(admin explicit false): %v", err)
	}
	if res.KID != "new-kid" {
		t.Fatalf("res.KID = %q, want %q", res.KID, "new-kid")
	}
	tool, args := decodeAdminArguments(t, rec.at(0))
	if tool != "jack.admin.user.create" {
		t.Fatalf("tool = %q, want %q", tool, "jack.admin.user.create")
	}
	adminArgIs(t, args, "name", `"newbie"`)
	adminArgIs(t, args, "public_key", `"pk-new"`)
	adminArgIs(t, args, "admin", `false`)

	res, err = client.AdminUserCreate(context.Background(), UserCreateParams{Name: "newbie2", PublicKey: "pk-new2"})
	if err != nil {
		t.Fatalf("AdminUserCreate(admin nil): %v", err)
	}
	if res.KID != "new-kid-2" {
		t.Fatalf("res.KID = %q, want %q", res.KID, "new-kid-2")
	}
	tool, args = decodeAdminArguments(t, rec.at(1))
	if tool != "jack.admin.user.create" {
		t.Fatalf("tool = %q, want %q", tool, "jack.admin.user.create")
	}
	adminArgAbsent(t, args, "admin")
	adminArgIs(t, args, "name", `"newbie2"`)
}

// TestAdminInviteCreateOptionalMembers discriminates the optional members of
// jack.admin.invite.create: an empty params object serializes no optional
// members, set pointers serialize their exact values, and an explicit
// &false admin serializes `"admin":false`. Every result is fully decoded and
// asserted.
func TestAdminInviteCreateOptionalMembers(t *testing.T) {
	srv := newTestServer(t)
	rec := &adminAPIRecorder{}
	srv.Handle = func(w http.ResponseWriter, auth jack.RequestAuth, body []byte) {
		rec.add(body)
		srv.writeSignedJSON(w, auth, http.StatusOK, rpcResultBody(json.RawMessage(
			`{"invite_id":"iv1","code":"c0de","expires_at":1767229200}`)))
	}
	client := newFixtureClient(t, srv, seedSignerByName(t, "root"), callToolNonce, callToolNonce, callToolNonce)

	wantResult := func(stage string, res InviteCreateResult) {
		t.Helper()
		if res.InviteID != "iv1" {
			t.Fatalf("%s: res.InviteID = %q, want %q", stage, res.InviteID, "iv1")
		}
		if res.Code != "c0de" {
			t.Fatalf("%s: res.Code = %q, want %q", stage, res.Code, "c0de")
		}
		if res.ExpiresAt != 1767229200 {
			t.Fatalf("%s: res.ExpiresAt = %d, want %d", stage, res.ExpiresAt, 1767229200)
		}
	}

	res, err := client.AdminInviteCreate(context.Background(), InviteCreateParams{})
	if err != nil {
		t.Fatalf("AdminInviteCreate(empty): %v", err)
	}
	wantResult("empty", res)
	tool, args := decodeAdminArguments(t, rec.at(0))
	if tool != "jack.admin.invite.create" {
		t.Fatalf("tool = %q, want %q", tool, "jack.admin.invite.create")
	}
	adminArgAbsent(t, args, "admin")
	adminArgAbsent(t, args, "ttl_seconds")
	adminArgAbsent(t, args, "key_ttl_seconds")

	adminTrue := true
	ttl := int64(3600)
	keyTTL := int64(60)
	res, err = client.AdminInviteCreate(context.Background(), InviteCreateParams{Admin: &adminTrue, TTLSeconds: &ttl, KeyTTLSeconds: &keyTTL})
	if err != nil {
		t.Fatalf("AdminInviteCreate(full): %v", err)
	}
	wantResult("full", res)
	_, args = decodeAdminArguments(t, rec.at(1))
	adminArgIs(t, args, "admin", `true`)
	adminArgIs(t, args, "ttl_seconds", `3600`)
	adminArgIs(t, args, "key_ttl_seconds", `60`)

	falseVal := false
	res, err = client.AdminInviteCreate(context.Background(), InviteCreateParams{Admin: &falseVal})
	if err != nil {
		t.Fatalf("AdminInviteCreate(admin explicit false): %v", err)
	}
	wantResult("explicit false", res)
	_, args = decodeAdminArguments(t, rec.at(2))
	adminArgIs(t, args, "admin", `false`)
	adminArgAbsent(t, args, "ttl_seconds")
	adminArgAbsent(t, args, "key_ttl_seconds")
}
