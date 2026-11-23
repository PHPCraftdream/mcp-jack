package transport

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"

	auditimpl "github.com/PHPCraftdream/mcp-jack/server/internal/audit"
	"github.com/PHPCraftdream/mcp-jack/server/internal/modern"
	nonceimpl "github.com/PHPCraftdream/mcp-jack/server/internal/nonce"
	verify "github.com/PHPCraftdream/mcp-jack/server/internal/verify"
	"github.com/PHPCraftdream/mcp-jack/spec"
)

// newProfileHarness is newHarness with a deployment profile and the wrapped
// handler answering okHandler. Everything else mirrors newHarness: the fixture
// registry and clock, the package fakeNative and a memory audit sink.
func newProfileHarness(t *testing.T, profile modern.Profile) *harness {
	t.Helper()
	return newProfileHarnessWith(t, profile, okHandler)
}

// newProfileHarnessWith is newProfileHarness with an explicit wrapped handler;
// the harness still records the forwarded body in seen and the call count.
func newProfileHarnessWith(t *testing.T, profile modern.Profile, wrap func(w http.ResponseWriter, r *http.Request)) *harness {
	t.Helper()
	registry, err := spec.LoadRegistry()
	if err != nil {
		t.Fatalf("LoadRegistry: %v", err)
	}
	h := &harness{next: new(atomic.Int32), seen: new([]byte), audit: auditimpl.NewMemoryAuditSink(), native: &fakeNative{}, server: testPrivateKey(t, "svc")}
	v, err := verify.NewVerifier(verify.Config{
		Aud: "https://svc.example.test", State: registryFromFixture(t, registry), Nonces: nonceimpl.NewNonceStore(),
		Audit: h.audit, Native: h.native,
		Now: func() int64 { return testNow },
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.next.Add(1)
		body := new(bytes.Buffer)
		_, _ = body.ReadFrom(r.Body)
		*h.seen = body.Bytes()
		wrap(w, r)
	})
	h.handler, err = NewHandler(HandlerConfig{Verifier: v, ServerKey: h.server, Profile: profile}, next)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	return h
}

// modernCallBody is an ordinary tools/call body carrying the signed _meta
// protocol version, so the client mirrors cannot fail on it.
func modernCallBody(name string) []byte {
	return []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + name + `","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`)
}

// addModernMirrors sets the three unsigned mirror headers after signing.
func addModernMirrors(req *http.Request, version, method, name string) {
	req.Header.Set("MCP-Protocol-Version", version)
	req.Header.Set("Mcp-Method", method)
	req.Header.Set("Mcp-Name", name)
}

// profileResult decodes the JSON-RPC result member of a response body.
func profileResult(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var env struct {
		Result map[string]any `json:"result"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("response body %q: %v", rec.Body.String(), err)
	}
	return env.Result
}

func TestModernExemptRulesNativeResultEraShape(t *testing.T) {
	t.Run("native_result_era_shape", func(t *testing.T) {
		// Legacy era: the 0.1.x CallToolResult shape, no resultType and no _meta.
		legacy := newProfileHarness(t, modern.ProfileLegacy)
		legacyBody := toolCallBody("jack.whoami")
		legacyReq, legacySig := signedRequest(t, testPrivateKey(t, "alice"), "POST", "/mcp", legacyBody)
		legacyRec := httptest.NewRecorder()
		legacy.handler.ServeHTTP(legacyRec, legacyReq)

		if legacyRec.Code != http.StatusOK {
			t.Fatalf("legacy status = %d, body %s", legacyRec.Code, legacyRec.Body.String())
		}
		assertSigned(t, legacyRec, legacy.server, legacySig)
		if legacy.next.Load() != 0 || legacy.native.calls.Load() != 1 {
			t.Fatalf("legacy next calls %d, native calls %d", legacy.next.Load(), legacy.native.calls.Load())
		}
		legacyResult := profileResult(t, legacyRec)
		for _, member := range []string{"resultType", "_meta"} {
			if _, ok := legacyResult[member]; ok {
				t.Fatalf("legacy result carries %q: %s", member, legacyRec.Body.String())
			}
		}

		// Both profile classifies the same legacy-era request as legacy, so the
		// response bytes must be identical to the legacy profile's bytes.
		both := newProfileHarness(t, modern.ProfileBoth)
		bothReq, bothSig := signedRequest(t, testPrivateKey(t, "alice"), "POST", "/mcp", legacyBody)
		bothRec := httptest.NewRecorder()
		both.handler.ServeHTTP(bothRec, bothReq)

		if bothRec.Code != http.StatusOK {
			t.Fatalf("both status = %d, body %s", bothRec.Code, bothRec.Body.String())
		}
		assertSigned(t, bothRec, both.server, bothSig)
		if !bytes.Equal(bothRec.Body.Bytes(), legacyRec.Body.Bytes()) {
			t.Fatalf("both body = %s, legacy body = %s", bothRec.Body.Bytes(), legacyRec.Body.Bytes())
		}

		// Modern era: resultType and Jack's serverInfo meta are added; the
		// CallToolResult payload members stay the legacy values.
		modernH := newProfileHarness(t, modern.ProfileModern)
		modernBody := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"jack.whoami","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`)
		modernReq, modernSig := signedRequest(t, testPrivateKey(t, "alice"), "POST", "/mcp", modernBody)
		addModernMirrors(modernReq, "2026-07-28", "tools/call", "jack.whoami")
		modernRec := httptest.NewRecorder()
		modernH.handler.ServeHTTP(modernRec, modernReq)

		if modernRec.Code != http.StatusOK {
			t.Fatalf("modern status = %d, body %s", modernRec.Code, modernRec.Body.String())
		}
		assertSigned(t, modernRec, modernH.server, modernSig)
		if modernH.next.Load() != 0 || modernH.native.calls.Load() != 1 {
			t.Fatalf("modern next calls %d, native calls %d", modernH.next.Load(), modernH.native.calls.Load())
		}
		modernResult := profileResult(t, modernRec)
		if modernResult["resultType"] != "complete" {
			t.Fatalf("modern resultType = %v, body %s", modernResult["resultType"], modernRec.Body.String())
		}
		meta, ok := modernResult["_meta"].(map[string]any)
		if !ok {
			t.Fatalf("modern result._meta = %v, body %s", modernResult["_meta"], modernRec.Body.String())
		}
		info, ok := meta["io.modelcontextprotocol/serverInfo"].(map[string]any)
		if !ok {
			t.Fatalf("serverInfo = %v, body %s", meta["io.modelcontextprotocol/serverInfo"], modernRec.Body.String())
		}
		if name, ok := info["name"].(string); !ok || name == "" {
			t.Fatalf("serverInfo.name = %v", info["name"])
		}
		if version, ok := info["version"].(string); !ok || version == "" {
			t.Fatalf("serverInfo.version = %v", info["version"])
		}
		for _, member := range []string{"content", "structuredContent", "isError"} {
			if !reflect.DeepEqual(modernResult[member], legacyResult[member]) {
				t.Fatalf("modern %s = %v, legacy %s = %v", member, modernResult[member], member, legacyResult[member])
			}
		}

		// A forwarded ordinary tools/call keeps the upstream body byte-exactly.
		forward := newProfileHarness(t, modern.ProfileModern)
		forwardBody := modernCallBody("svc.status")
		forwardReq, forwardSig := signedRequest(t, testPrivateKey(t, "alice"), "POST", "/mcp", forwardBody)
		addModernMirrors(forwardReq, "2026-07-28", "tools/call", "svc.status")
		forwardRec := httptest.NewRecorder()
		forward.handler.ServeHTTP(forwardRec, forwardReq)

		if forwardRec.Code != http.StatusOK {
			t.Fatalf("forward status = %d, body %s", forwardRec.Code, forwardRec.Body.String())
		}
		if got, want := forwardRec.Body.String(), `{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`; got != want {
			t.Fatalf("forwarded body = %s, want %s", got, want)
		}
		if forward.next.Load() != 1 {
			t.Fatalf("forwarded handler calls = %d, want 1", forward.next.Load())
		}
		if _, ok := profileResult(t, forwardRec)["resultType"]; ok {
			t.Fatal("a forwarded legacy result must not gain resultType")
		}
		assertSigned(t, forwardRec, forward.server, forwardSig)
	})
}

func TestModernMiddlewareEraDispatch(t *testing.T) {
	check405 := func(t *testing.T, method string) {
		t.Helper()
		h := newProfileHarness(t, modern.ProfileModern)
		req, sig := signedRequest(t, testPrivateKey(t, "alice"), method, "/mcp", nil)
		rec := httptest.NewRecorder()
		h.handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
		}
		if got := rec.Header().Get("Allow"); got != "POST" {
			t.Fatalf("Allow = %q", got)
		}
		if got, want := rec.Body.String(), `{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"HTTP method not allowed"}}`; got != want {
			t.Fatalf("body = %s, want %s", got, want)
		}
		assertSigned(t, rec, h.server, sig)
		if h.next.Load() != 0 {
			t.Fatalf("the wrapped handler was reached %d times", h.next.Load())
		}
	}

	t.Run("modern GET is a signed 405", func(t *testing.T) { check405(t, "GET") })
	t.Run("modern DELETE is a signed 405", func(t *testing.T) { check405(t, "DELETE") })

	t.Run("missing version header is refused", func(t *testing.T) {
		h := newProfileHarness(t, modern.ProfileModern)
		body := toolCallBody("svc.status")
		req, sig := signedRequest(t, testPrivateKey(t, "alice"), "POST", "/mcp", body)
		rec := httptest.NewRecorder()
		h.handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
		}
		var env struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      json.RawMessage `json:"id"`
			Error   struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Fatalf("response body %q: %v", rec.Body.String(), err)
		}
		if env.JSONRPC != "2.0" || string(env.ID) != "1" || env.Error.Code != -32020 || env.Error.Message != "Header mismatch: MCP-Protocol-Version is missing" {
			t.Fatalf("refusal = %+v, body %s", env, rec.Body.String())
		}
		assertSigned(t, rec, h.server, sig)
		if h.next.Load() != 0 {
			t.Fatalf("the wrapped handler was reached %d times", h.next.Load())
		}
	})

	t.Run("classification refusal keeps its fixed message", func(t *testing.T) {
		h := newProfileHarness(t, modern.ProfileModern)
		body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":7}}`)
		req, sig := signedRequest(t, testPrivateKey(t, "alice"), "POST", "/mcp", body)
		rec := httptest.NewRecorder()
		h.handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
		}
		var members map[string]json.RawMessage
		if err := json.Unmarshal(rec.Body.Bytes(), &members); err != nil {
			t.Fatalf("response body %q: %v", rec.Body.String(), err)
		}
		for _, member := range []string{"jsonrpc", "id"} {
			if _, ok := members[member]; ok {
				t.Fatalf("classification refusal carries %q: %s", member, rec.Body.String())
			}
		}
		var got map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("response body %q: %v", rec.Body.String(), err)
		}
		want := map[string]any{"error": map[string]any{
			"code":    "invalid_request",
			"message": "tools/call requires a string params.name",
		}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("refusal = %s, want %v", rec.Body.String(), want)
		}
		assertSigned(t, rec, h.server, sig)
		if h.next.Load() != 0 {
			t.Fatalf("the wrapped handler was reached %d times", h.next.Load())
		}
	})

	t.Run("forwarded headers and body in the modern era", func(t *testing.T) {
		var seen http.Header
		h := newProfileHarnessWith(t, modern.ProfileModern, func(w http.ResponseWriter, r *http.Request) {
			seen = r.Header.Clone()
			okHandler(w, r)
		})
		body := modernCallBody("svc.status")
		req, _ := signedRequest(t, testPrivateKey(t, "alice"), "POST", "/mcp", body)
		addModernMirrors(req, "2026-07-28", "tools/call", "svc.status")
		// Added after signing: they are not part of the signed request.
		req.Header.Set("Mcp-Session-Id", "sess-1")
		req.Header.Set("Last-Event-ID", "7")
		req.Header.Set("Mcp-Param-Region", "us\twest")
		rec := httptest.NewRecorder()
		h.handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
		}
		if h.next.Load() != 1 {
			t.Fatalf("the wrapped handler was called %d times, want 1", h.next.Load())
		}
		if seen == nil {
			t.Fatal("the wrapped handler did not receive the request")
		}
		if got := seen.Values("Mcp-Session-Id"); len(got) != 0 {
			t.Fatalf("Mcp-Session-Id was forwarded: %q", got)
		}
		if got := seen.Values("Last-Event-ID"); len(got) != 0 {
			t.Fatalf("Last-Event-ID was forwarded: %q", got)
		}
		if got, want := seen.Values("Mcp-Param-Region"), []string{"us\twest"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("Mcp-Param-Region = %q, want %q", got, want)
		}
		if !bytes.Equal(*h.seen, body) {
			t.Fatalf("the handler read %q, want the signed body %q", *h.seen, body)
		}
	})

	t.Run("both profile legacy GET is forwarded", func(t *testing.T) {
		h := newProfileHarness(t, modern.ProfileBoth)
		req, sig := signedRequest(t, testPrivateKey(t, "alice"), "GET", "/mcp", nil)
		rec := httptest.NewRecorder()
		h.handler.ServeHTTP(rec, req)

		if h.next.Load() != 1 {
			t.Fatalf("the wrapped handler was called %d times, want 1", h.next.Load())
		}
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
		}
		assertSigned(t, rec, h.server, sig)
	})

	t.Run("both profile legacy POST is forwarded", func(t *testing.T) {
		h := newProfileHarness(t, modern.ProfileBoth)
		body := toolCallBody("svc.status")
		req, sig := signedRequest(t, testPrivateKey(t, "alice"), "POST", "/mcp", body)
		rec := httptest.NewRecorder()
		h.handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
		}
		if h.next.Load() != 1 {
			t.Fatalf("the wrapped handler was called %d times, want 1", h.next.Load())
		}
		if !bytes.Equal(*h.seen, body) {
			t.Fatalf("the handler read %q, want the signed body %q", *h.seen, body)
		}
		assertSigned(t, rec, h.server, sig)
	})

	t.Run("modern mirror refusal does not run the native tool", func(t *testing.T) {
		h := newProfileHarness(t, modern.ProfileModern)
		body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"jack.whoami","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`)
		req, sig := signedRequest(t, testPrivateKey(t, "alice"), "POST", "/mcp", body)
		addModernMirrors(req, "2026-07-28", "tools/call", "someone-else")
		rec := httptest.NewRecorder()
		h.handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
		}
		var env struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      json.RawMessage `json:"id"`
			Error   struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Fatalf("response body %q: %v", rec.Body.String(), err)
		}
		if env.JSONRPC != "2.0" || string(env.ID) != "1" || env.Error.Code != -32020 || env.Error.Message != "Header mismatch: Mcp-Name does not match the body value" {
			t.Fatalf("refusal = %+v, body %s", env, rec.Body.String())
		}
		assertSigned(t, rec, h.server, sig)
		if h.native.calls.Load() != 0 {
			t.Fatalf("a refused request ran the native tool %d times", h.native.calls.Load())
		}
		if h.next.Load() != 0 {
			t.Fatalf("a refused request reached the wrapped handler %d times", h.next.Load())
		}
		if events := h.audit.Events(); len(events) != 0 {
			t.Fatalf("a refused request wrote audit events: %+v", events)
		}
	})

	t.Run("both profile legacy DELETE keeps the legacy 405", func(t *testing.T) {
		h := newProfileHarness(t, modern.ProfileBoth)
		req, _ := signedRequest(t, testPrivateKey(t, "alice"), "DELETE", "/mcp", nil)
		rec := httptest.NewRecorder()
		h.handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
		}
		if got, want := rec.Body.String(), `{"error":{"code":"method_not_allowed","message":"only GET and POST are defined"}}`; got != want {
			t.Fatalf("body = %s, want %s", got, want)
		}
		if got := rec.Header().Get("Jack-Auth"); got != "" {
			t.Fatalf("the legacy path answered signed: Jack-Auth = %q", got)
		}
		if h.next.Load() != 0 {
			t.Fatalf("the wrapped handler was reached %d times", h.next.Load())
		}
	})

	t.Run("legacy profile forwards untouched", func(t *testing.T) {
		var retained []string
		h := newProfileHarnessWith(t, "", func(w http.ResponseWriter, r *http.Request) {
			retained = r.Header.Values("Mcp-Session-Id")
			okHandler(w, r)
		})
		body := toolCallBody("svc.status")
		req, sig := signedRequest(t, testPrivateKey(t, "alice"), "POST", "/mcp", body)
		req.Header.Set("Mcp-Name", "not-the-tool")
		req.Header.Set("Mcp-Session-Id", "sess-legacy")
		rec := httptest.NewRecorder()
		h.handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
		}
		if h.next.Load() != 1 {
			t.Fatalf("the wrapped handler was called %d times, want 1", h.next.Load())
		}
		if !reflect.DeepEqual(retained, []string{"sess-legacy"}) {
			t.Fatalf("the handler saw Mcp-Session-Id %q, want it retained", retained)
		}
		assertSigned(t, rec, h.server, sig)
	})

	t.Run("invalid profile is rejected", func(t *testing.T) {
		registry, err := spec.LoadRegistry()
		if err != nil {
			t.Fatalf("LoadRegistry: %v", err)
		}
		v, err := verify.NewVerifier(verify.Config{
			Aud: "https://svc.example.test", State: registryFromFixture(t, registry), Nonces: nonceimpl.NewNonceStore(),
			Now: func() int64 { return testNow },
		})
		if err != nil {
			t.Fatalf("NewVerifier: %v", err)
		}
		handler, err := NewHandler(HandlerConfig{Verifier: v, ServerKey: testPrivateKey(t, "svc"), Profile: modern.Profile("bogus")},
			http.HandlerFunc(okHandler))
		if err == nil {
			t.Fatal("NewHandler accepted an invalid profile")
		}
		if handler != nil {
			t.Fatal("NewHandler returned a handler together with an error")
		}
	})
}
