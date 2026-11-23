package client_test

// Tests for the spec 04 section 8 exemption rows carried by SDK tests:
//
//	C8  cache binding and privacy                     (client_cache_private_only)
//	C10 tools/list refetch, re-projection, retry once (client_header_resync)
//	C12 events/list refetch, re-projection, retry once (client_events_resync)
//
// The tests use only the public client and client/modern API. The server side
// is a local httptest harness that signs every answer over the answering
// request's signature (spec 01 section 5), so every response the client sees
// is a verified one.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/client"
	"github.com/PHPCraftdream/mcp-jack/client/modern"
)

// modernAud is the audience both the client and the harness use.
const modernAud = "https://svc.example.test"

// modernProtocolVersion is MODERN-MIN, the version string of every request of
// the projected flow (tools.go always speaks modern.ModernMin).
const modernProtocolVersion = "2026-07-28"

// modernRecordedHeaders are the C2 mirror headers, the Mcp-Param-* headers of
// the two scenarios and the Mcp-Session-Id the legacy handshake can carry,
// recorded per request.
var modernRecordedHeaders = []string{
	"MCP-Protocol-Version",
	"Mcp-Method",
	"Mcp-Name",
	"Mcp-Param-Region",
	"Mcp-Param-Zone",
	"Mcp-Param-Tenant",
	"Mcp-Param-TenantId",
	"Mcp-Session-Id",
}

// modernScriptAnswer is one scripted server answer.
type modernScriptAnswer struct {
	status int
	body   string
	// headers are extra response headers of this answer, for example the
	// Mcp-Session-Id a legacy server assigns on initialize.
	headers map[string]string
}

// modernRequestRecord is one request the harness saw: its JSON-RPC method and
// the interesting header values, captured before the answer is written.
type modernRequestRecord struct {
	Method  string
	Headers map[string][]string
}

// header returns the first value of name and whether it was present.
func (r modernRequestRecord) header(name string) (string, bool) {
	values := r.Headers[name]
	if len(values) == 0 {
		return "", false
	}
	return values[0], true
}

// modernRequestLog records requests under the server goroutine and hands out
// copies after the client call has returned.
type modernRequestLog struct {
	mu      sync.Mutex
	records []modernRequestRecord
	next    int
}

// add appends rec and returns its zero-based position in request order.
func (l *modernRequestLog) add(rec modernRequestRecord) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.records = append(l.records, rec)
	idx := l.next
	l.next++
	return idx
}

// snapshot returns a copy of the recorded requests in request order.
func (l *modernRequestLog) snapshot() []modernRequestRecord {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]modernRequestRecord, len(l.records))
	copy(out, l.records)
	return out
}

// count returns the number of requests recorded so far.
func (l *modernRequestLog) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.records)
}

// newModernSignedServer starts a harness that answers the idx-th request with
// answers[idx] and signs every answer over that request's Jack-Auth sig
// (spec 01 section 5). A request past the end of the script is answered with a
// signed 500 so an extra attempt shows up as a recorded request and a clear
// failure, never as a panic.
func newModernSignedServer(t *testing.T, priv ed25519.PrivateKey, pub ed25519.PublicKey, answers []modernScriptAnswer, log *modernRequestLog) *httptest.Server {
	t.Helper()
	kid := jack.KeyID(pub)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("harness: reading request body: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		var wire struct {
			Method string          `json:"method"`
			ID     json.RawMessage `json:"id"`
			Params json.RawMessage `json:"params"`
		}
		if err := json.Unmarshal(raw, &wire); err != nil {
			t.Errorf("harness: decoding request body %q: %v", raw, err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		rec := modernRequestRecord{Method: wire.Method, Headers: map[string][]string{}}
		for _, name := range modernRecordedHeaders {
			if values := r.Header.Values(name); len(values) > 0 {
				rec.Headers[name] = append([]string(nil), values...)
			}
		}
		idx := log.add(rec)

		requestAuth, err := jack.ParseRequestAuth(r.Header.Values("Jack-Auth"))
		if err != nil {
			t.Errorf("harness: request %d: parsing Jack-Auth: %v", idx+1, err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		answer := modernScriptAnswer{
			status: http.StatusInternalServerError,
			body:   `{"jsonrpc":"2.0","id":0,"error":{"code":-32603,"message":"unscripted request"}}`,
		}
		if idx < len(answers) {
			answer = answers[idx]
		}

		body := []byte(answer.body)
		for name, value := range answer.headers {
			w.Header().Set(name, value)
		}
		ts := time.Now().Unix()
		sig := ed25519.Sign(priv, []byte(jack.ResponseSigningString(answer.status, requestAuth.Sig, kid, ts, body)))
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Jack-Auth", jack.FormatResponseAuth(jack.ResponseAuth{
			Kid: kid,
			TS:  ts,
			Sig: jack.EncodeBase64URL(sig),
		}))
		w.WriteHeader(answer.status)
		if _, err := w.Write(body); err != nil {
			t.Errorf("harness: writing response: %v", err)
		}
	})
	return httptest.NewServer(handler)
}

// modernTestClient builds the client of the harness server for era: a
// deterministic in-memory signer and the pinned harness public key.
func modernTestClient(t *testing.T, baseURL string, pub ed25519.PublicKey, era client.Era) *client.Client {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	signer, err := client.NewInMemorySigner(seed)
	if err != nil {
		t.Fatalf("NewInMemorySigner: %v", err)
	}
	c, err := client.NewClient(client.Config{
		BaseURL:   baseURL,
		Aud:       modernAud,
		Signer:    signer,
		ServerKey: pub,
		Era:       era,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

// newModernHarness starts one signed server with the given script, pins its
// key in a fresh modern-era client, and returns the client and the request
// log.
func newModernHarness(t *testing.T, answers []modernScriptAnswer) (*client.Client, *modernRequestLog) {
	t.Helper()
	return newModernHarnessWithEra(t, client.EraModern, answers)
}

// newModernHarnessWithEra starts one signed server with the given script,
// pins its key in a fresh client configured for era, and returns the client
// and the request log.
func newModernHarnessWithEra(t *testing.T, era client.Era, answers []modernScriptAnswer) (*client.Client, *modernRequestLog) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating harness key: %v", err)
	}
	log := &modernRequestLog{}
	srv := newModernSignedServer(t, priv, pub, answers, log)
	t.Cleanup(srv.Close)
	return modernTestClient(t, srv.URL, pub, era), log
}

// wantModernMethodOrder asserts the exact request count and method order.
func wantModernMethodOrder(t *testing.T, recs []modernRequestRecord, want ...string) {
	t.Helper()
	if len(recs) != len(want) {
		t.Fatalf("harness saw %d requests, want %d", len(recs), len(want))
	}
	for i := range want {
		if recs[i].Method != want[i] {
			t.Fatalf("request %d method = %q, want %q", i+1, recs[i].Method, want[i])
		}
	}
}

// wantModernHeader asserts that one recorded request carries name: want.
func wantModernHeader(t *testing.T, rec modernRequestRecord, name, want string) {
	t.Helper()
	got, ok := rec.header(name)
	if !ok {
		t.Fatalf("%s request: header %q is absent, want %q", rec.Method, name, want)
	}
	if got != want {
		t.Fatalf("%s request: header %q = %q, want %q", rec.Method, name, got, want)
	}
}

// wantModernNoHeader asserts that one recorded request does not carry name.
func wantModernNoHeader(t *testing.T, rec modernRequestRecord, name string) {
	t.Helper()
	if values, ok := rec.Headers[name]; ok {
		t.Fatalf("%s request: header %q = %v, want it absent", rec.Method, name, values)
	}
}

// wantModernCallMirrors asserts the C2 mirrors Mcp-Method and Mcp-Name of a
// projected tools/call or events/poll request.
func wantModernCallMirrors(t *testing.T, rec modernRequestRecord, method, name string) {
	t.Helper()
	wantModernHeader(t, rec, "MCP-Protocol-Version", modernProtocolVersion)
	wantModernHeader(t, rec, "Mcp-Method", method)
	wantModernHeader(t, rec, "Mcp-Name", name)
}

// wantModernListMirrors asserts the C2 mirrors of a tools/list or events/list
// request: no S6 name source, so no Mcp-Name.
func wantModernListMirrors(t *testing.T, rec modernRequestRecord, method string) {
	t.Helper()
	wantModernHeader(t, rec, "MCP-Protocol-Version", modernProtocolVersion)
	wantModernHeader(t, rec, "Mcp-Method", method)
	wantModernNoHeader(t, rec, "Mcp-Name")
}

// TestModernExemptRulesClientCachePrivateOnly carries C8 (spec 04 section 8):
// the private cache is keyed by the exact request, bounded by ttlMs, copies
// its values, has no shared state, and the by-reference `cache-replay` rule
// holds because a response is bound to the answering request's signature.
func TestModernExemptRulesClientCachePrivateOnly(t *testing.T) {
	t.Run("client_cache_private_only", func(t *testing.T) {
		now := time.Unix(1767225600, 0)
		data := []byte(`{"ok":true}`)
		key := modern.CacheKey{
			Method: "tools/call",
			Params: `{"name":"execute_sql"}`,
			Era:    "modern",
		}

		cache := modern.NewResultCache()
		cache.Put(key, data, 60000, now)

		got, ok := cache.Get(key, now)
		if !ok {
			t.Fatalf("Get after Put missed")
		}
		if string(got) != string(data) {
			t.Fatalf("Get = %q, want %q", got, data)
		}

		// The cache stores copies, not aliases: mutating a returned slice
		// cannot change the cached bytes.
		got[0] = 'X'
		again, ok := cache.Get(key, now)
		if !ok {
			t.Fatalf("second Get missed")
		}
		if string(again) != string(data) {
			t.Fatalf("Get after mutating a returned slice = %q, want %q (the cache aliased its value)", again, data)
		}

		// The key is the exact request: any other method, params or era is a
		// different request and must miss.
		otherKeys := []struct {
			label string
			key   modern.CacheKey
		}{
			{"method", modern.CacheKey{Method: "tools/list", Params: key.Params, Era: key.Era}},
			{"params", modern.CacheKey{Method: key.Method, Params: `{"name":"other_tool"}`, Era: key.Era}},
			{"era", modern.CacheKey{Method: key.Method, Params: key.Params, Era: "legacy"}},
		}
		for _, other := range otherKeys {
			if _, ok := cache.Get(other.key, now); ok {
				t.Fatalf("a key with a different %s hit, want a miss", other.label)
			}
		}

		// ttlMs 0 means the result MUST NOT be reused: nothing is stored and
		// the existing entry is dropped.
		cache.Put(key, data, 0, now)
		if _, ok := cache.Get(key, now); ok {
			t.Fatalf("Get after a ttlMs 0 Put hit, want a miss")
		}
		empty := modern.NewResultCache()
		empty.Put(key, data, 0, now)
		if _, ok := empty.Get(key, now); ok {
			t.Fatalf("a ttlMs 0 Put stored an entry, want nothing stored")
		}

		// An entry is live strictly before its deadline.
		cache.Put(key, data, 1000, now)
		if _, ok := cache.Get(key, now.Add(999*time.Millisecond)); !ok {
			t.Fatalf("Get at now+999ms missed, want a hit")
		}
		if _, ok := cache.Get(key, now.Add(1000*time.Millisecond)); ok {
			t.Fatalf("Get at now+1000ms hit, want a miss at the deadline")
		}

		// The cache is private and holds no shared state: a second instance
		// never sees the first one's entry.
		cache.Put(key, data, 60000, now)
		second := modern.NewResultCache()
		if _, ok := second.Get(key, now); ok {
			t.Fatalf("a second cache instance saw another instance's entry, want a miss")
		}

		// The by-reference `cache-replay` rule: a Jack response is signed over
		// the answering request's signature, so a verified response bound to
		// request A is refused as the answer to request B.
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generating response key: %v", err)
		}
		body := []byte(`{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`)
		ts := int64(1767225600)
		serverKID := jack.KeyID(pub)
		sig := ed25519.Sign(priv, []byte(jack.ResponseSigningString(http.StatusOK, "sig-a", serverKID, ts, body)))
		header := jack.FormatResponseAuth(jack.ResponseAuth{
			Kid: serverKID,
			TS:  ts,
			Sig: jack.EncodeBase64URL(sig),
		})

		// A response bound to its own request verifies.
		if err := client.VerifyResponse(pub, http.StatusOK, []string{header}, "sig-a", body, now, 30*time.Second); err != nil {
			t.Fatalf("response bound to its request did not verify: %v", err)
		}

		// The same bytes presented for another request do not.
		err = client.VerifyResponse(pub, http.StatusOK, []string{header}, "sig-b", body, now, 30*time.Second)
		if err == nil {
			t.Fatalf("response bound to another request verified, want a refusal")
		}
		var jackErr *jack.Error
		if !errors.As(err, &jackErr) {
			t.Fatalf("response binding refusal = %v, want a *jack.Error", err)
		}
		if jackErr.Code != jack.CodeBadSignature {
			t.Fatalf("response binding refusal code = %q, want %q", jackErr.Code, jack.CodeBadSignature)
		}
		// The mismatching result therefore cannot be reused for another
		// request: replaying the cached bytes as the answer to a request with a
		// different signature is refused by the request-sig binding before any
		// cache could serve it, which is why no shared cache may exist.
	})
}

const (
	// modernToolsListRegion is the first tools/list answer: region is
	// annotated Region.
	modernToolsListRegion = `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"execute_sql","inputSchema":{"type":"object","properties":{"region":{"type":"string","x-mcp-header":"Region"}}}}]}}`
	// modernToolsListZone is the refetched tools/list answer: the schema
	// annotates the same region argument with the new header name Zone, so the
	// client re-projects that same argument under the new name.
	modernToolsListZone = `{"jsonrpc":"2.0","id":3,"result":{"tools":[{"name":"execute_sql","inputSchema":{"type":"object","properties":{"region":{"type":"string","x-mcp-header":"Zone"}}}}]}}`
	// modernHeaderMismatch is the signed -32020 refusal of a projected call.
	modernHeaderMismatch = `{"jsonrpc":"2.0","id":2,"error":{"code":-32020,"message":"Header mismatch"}}`
	// modernToolOK is the successful tools/call answer.
	modernToolOK = `{"jsonrpc":"2.0","id":4,"result":{"structuredContent":{"ok":true}}}`
)

// TestModernExemptRulesClientHeaderResync carries C10 (spec 04 section 8): after
// a -32020 refusal the client refetches tools/list, re-projects against the new
// inputSchema and retries exactly once.
func TestModernExemptRulesClientHeaderResync(t *testing.T) {
	t.Run("client_header_resync", func(t *testing.T) {
		c, log := newModernHarness(t, []modernScriptAnswer{
			{status: http.StatusOK, body: modernToolsListRegion},
			{status: http.StatusBadRequest, body: modernHeaderMismatch},
			{status: http.StatusOK, body: modernToolsListZone},
			{status: http.StatusOK, body: modernToolOK},
		})

		var out struct {
			OK bool `json:"ok"`
		}
		if err := c.CallModernTool(context.Background(), "execute_sql", json.RawMessage(`{"region":"eu-west"}`), &out); err != nil {
			t.Fatalf("CallModernTool: %v", err)
		}
		if !out.OK {
			t.Fatalf("out = %+v, want {ok:true}", out)
		}

		recs := log.snapshot()
		wantModernMethodOrder(t, recs, "tools/list", "tools/call", "tools/list", "tools/call")

		// The refusal came from the stale schema: the first call projected
		// Region, the retry projected the refetched Zone.
		wantModernHeader(t, recs[1], "Mcp-Param-Region", "eu-west")
		wantModernNoHeader(t, recs[1], "Mcp-Param-Zone")
		wantModernHeader(t, recs[3], "Mcp-Param-Zone", "eu-west")
		wantModernNoHeader(t, recs[3], "Mcp-Param-Region")

		wantModernCallMirrors(t, recs[1], "tools/call", "execute_sql")
		wantModernCallMirrors(t, recs[3], "tools/call", "execute_sql")
		wantModernListMirrors(t, recs[0], "tools/list")
		wantModernListMirrors(t, recs[2], "tools/list")
	})

	t.Run("one retry only", func(t *testing.T) {
		c, log := newModernHarness(t, []modernScriptAnswer{
			{status: http.StatusOK, body: modernToolsListRegion},
			{status: http.StatusBadRequest, body: modernHeaderMismatch},
			{status: http.StatusOK, body: modernToolsListZone},
			{status: http.StatusBadRequest, body: modernHeaderMismatch},
		})

		err := c.CallModernTool(context.Background(), "execute_sql", json.RawMessage(`{"region":"eu-west"}`), nil)
		if err == nil {
			t.Fatalf("CallModernTool with a second -32020 refusal returned nil error, want a failure")
		}
		var httpErr *client.HTTPError
		if !errors.As(err, &httpErr) {
			t.Fatalf("CallModernTool error = %v, want a *client.HTTPError", err)
		}
		if httpErr.Status != http.StatusBadRequest {
			t.Fatalf("HTTPError.Status = %d, want %d", httpErr.Status, http.StatusBadRequest)
		}
		// The retry happens once: a second -32020 is answered normally and is
		// never retried again, so the server sees exactly four requests.
		if got := log.count(); got != 4 {
			t.Fatalf("harness saw %d requests, want 4 (a second attempt was made)", got)
		}
	})
}

const (
	// modernEventsListTenant is the first events/list answer: tenant is
	// annotated Tenant.
	modernEventsListTenant = `{"jsonrpc":"2.0","id":1,"result":{"events":[{"name":"incident.created","inputSchema":{"type":"object","properties":{"tenant":{"type":"string","x-mcp-header":"Tenant"}}}}]}}`
	// modernEventsListTenantID is the refetched events/list answer: the schema
	// annotates the same tenant argument with the new header name TenantId.
	modernEventsListTenantID = `{"jsonrpc":"2.0","id":3,"result":{"events":[{"name":"incident.created","inputSchema":{"type":"object","properties":{"tenant":{"type":"string","x-mcp-header":"TenantId"}}}}]}}`
	// modernEventsPollOK is the successful events/poll answer.
	modernEventsPollOK = `{"jsonrpc":"2.0","id":4,"result":{"structuredContent":{"events":[]}}}`
)

// TestModernExemptRulesClientEventsResync carries C12 (spec 04 section 8): after
// a -32020 refusal for an events method the client refetches events/list,
// re-projects and retries exactly once, and a method outside the four events
// methods fails locally without any HTTP request.
func TestModernExemptRulesClientEventsResync(t *testing.T) {
	t.Run("client_events_resync", func(t *testing.T) {
		c, log := newModernHarness(t, []modernScriptAnswer{
			{status: http.StatusOK, body: modernEventsListTenant},
			{status: http.StatusBadRequest, body: modernHeaderMismatch},
			{status: http.StatusOK, body: modernEventsListTenantID},
			{status: http.StatusOK, body: modernEventsPollOK},
		})

		var out struct {
			Events []json.RawMessage `json:"events"`
		}
		if err := c.CallModernEvent(context.Background(), "events/poll", "incident.created", json.RawMessage(`{"tenant":"acme"}`), &out); err != nil {
			t.Fatalf("CallModernEvent: %v", err)
		}
		if len(out.Events) != 0 {
			t.Fatalf("out.Events = %v, want the empty events array of the answer", out.Events)
		}

		recs := log.snapshot()
		wantModernMethodOrder(t, recs, "events/list", "events/poll", "events/list", "events/poll")

		// The first poll projected the stale Tenant annotation; the retry
		// projects the refetched TenantId annotation and not the old one.
		wantModernHeader(t, recs[1], "Mcp-Param-Tenant", "acme")
		wantModernNoHeader(t, recs[1], "Mcp-Param-TenantId")
		wantModernHeader(t, recs[3], "Mcp-Param-TenantId", "acme")
		wantModernNoHeader(t, recs[3], "Mcp-Param-Tenant")

		wantModernCallMirrors(t, recs[1], "events/poll", "incident.created")
		wantModernCallMirrors(t, recs[3], "events/poll", "incident.created")
		wantModernListMirrors(t, recs[0], "events/list")
		wantModernListMirrors(t, recs[2], "events/list")

		// A method outside the four events methods is rejected locally: no
		// request reaches the server.
		before := log.count()
		if err := c.CallModernEvent(context.Background(), "events/unknown", "incident.created", nil, nil); err == nil {
			t.Fatalf("CallModernEvent with events/unknown returned nil error, want a local failure")
		}
		if after := log.count(); after != before {
			t.Fatalf("events/unknown made %d HTTP requests, want 0", after-before)
		}
	})
}

const (
	// modernDiscoverOK is the successful server/discover probe: the modern
	// era signal of C9.
	modernDiscoverOK = `{"jsonrpc":"2.0","id":1,"result":{}}`
	// modernAutoToolsList is the tools/list answer of the modern probe path.
	modernAutoToolsList = `{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"execute_sql","inputSchema":{"properties":{"region":{"type":"string","x-mcp-header":"Region"}}}}]}}`
	// modernAutoToolOK is the successful tools/call answer of the auto flow.
	modernAutoToolOK = `{"jsonrpc":"2.0","id":3,"result":{"structuredContent":{"ok":true}}}`
	// modernDiscoverJackEnvelope is the signed 400 Jack envelope: a legacy
	// signal with reason jack_envelope.
	modernDiscoverJackEnvelope = `{"error":{"code":"invalid_request","message":"bad request"}}`
	// modernInitializeOK is the legacy initialize answer: it negotiates the
	// legacy protocol version 2025-11-25.
	modernInitializeOK = `{"jsonrpc":"2.0","id":2,"result":{"protocolVersion":"2025-11-25"}}`
	// modernInitializedOK is the legacy notifications/initialized answer.
	modernInitializedOK = `{}`
	// modernLegacyToolOK is the legacy tools/call answer.
	modernLegacyToolOK = `{"jsonrpc":"2.0","id":4,"result":{"structuredContent":{"ok":true}}}`
	// modernDiscoverUnsupportedLegacy offers only the legacy version
	// 2025-11-25, so the C9 retry selects the legacy handshake.
	modernDiscoverUnsupportedLegacy = `{"jsonrpc":"2.0","id":1,"error":{"code":-32022,"message":"Unsupported protocol version","data":{"supported":["2025-11-25"]}}}`
)

// TestModernAutoNegotiation carries the C9 EraAuto probe (spec 04 section 6):
// the first request is a server/discover probe, never the user operation, and
// only its verified answer selects the era.
func TestModernAutoNegotiation(t *testing.T) {
	t.Run("modern probe then projected call", func(t *testing.T) {
		c, log := newModernHarnessWithEra(t, client.EraAuto, []modernScriptAnswer{
			{status: http.StatusOK, body: modernDiscoverOK},
			{status: http.StatusOK, body: modernAutoToolsList},
			{status: http.StatusOK, body: modernAutoToolOK},
		})

		var out struct {
			OK bool `json:"ok"`
		}
		if err := c.CallTool(context.Background(), "execute_sql", map[string]any{"region": "eu"}, &out); err != nil {
			t.Fatalf("CallTool: %v", err)
		}
		if !out.OK {
			t.Fatalf("out = %+v, want {ok:true}", out)
		}

		recs := log.snapshot()
		wantModernMethodOrder(t, recs, "server/discover", "tools/list", "tools/call")

		// The probe carries the C2 mirrors of server/discover and no Mcp-Name.
		wantModernListMirrors(t, recs[0], "server/discover")

		// The projected operation still projects the annotated argument.
		wantModernListMirrors(t, recs[1], "tools/list")
		wantModernCallMirrors(t, recs[2], "tools/call", "execute_sql")
		wantModernHeader(t, recs[2], "Mcp-Param-Region", "eu")
	})

	t.Run("legacy fallback runs initialize first", func(t *testing.T) {
		c, log := newModernHarnessWithEra(t, client.EraAuto, []modernScriptAnswer{
			{status: http.StatusBadRequest, body: modernDiscoverJackEnvelope},
			{status: http.StatusOK, body: modernInitializeOK},
			{status: http.StatusOK, body: modernInitializedOK},
			{status: http.StatusOK, body: modernLegacyToolOK},
		})

		var out struct {
			OK bool `json:"ok"`
		}
		if err := c.CallTool(context.Background(), "execute_sql", map[string]any{"region": "eu"}, &out); err != nil {
			t.Fatalf("CallTool: %v", err)
		}
		if !out.OK {
			t.Fatalf("out = %+v, want {ok:true}", out)
		}

		recs := log.snapshot()
		wantModernMethodOrder(t, recs, "server/discover", "initialize", "notifications/initialized", "tools/call")

		// initialize is the first request of a session: no transport headers.
		wantModernNoHeader(t, recs[1], "MCP-Protocol-Version")
		wantModernNoHeader(t, recs[1], "Mcp-Session-Id")
		// The negotiated version is carried on notifications/initialized and on
		// the legacy operation, which is still the 0.1.x body without mirrors.
		wantModernHeader(t, recs[2], "MCP-Protocol-Version", "2025-11-25")
		wantModernHeader(t, recs[3], "MCP-Protocol-Version", "2025-11-25")
		wantModernNoHeader(t, recs[3], "Mcp-Session-Id")
		wantModernNoHeader(t, recs[3], "Mcp-Method")
		wantModernNoHeader(t, recs[3], "Mcp-Name")
		wantModernNoHeader(t, recs[3], "Mcp-Param-Region")
	})

	t.Run("supported legacy version retries the handshake", func(t *testing.T) {
		c, log := newModernHarnessWithEra(t, client.EraAuto, []modernScriptAnswer{
			{status: http.StatusBadRequest, body: modernDiscoverUnsupportedLegacy},
			{status: http.StatusOK, body: modernInitializeOK},
			{status: http.StatusOK, body: modernInitializedOK},
			{status: http.StatusOK, body: modernLegacyToolOK},
		})

		var out struct {
			OK bool `json:"ok"`
		}
		if err := c.CallTool(context.Background(), "execute_sql", map[string]any{"region": "eu"}, &out); err != nil {
			t.Fatalf("CallTool: %v", err)
		}
		if !out.OK {
			t.Fatalf("out = %+v, want {ok:true}", out)
		}

		recs := log.snapshot()
		wantModernMethodOrder(t, recs, "server/discover", "initialize", "notifications/initialized", "tools/call")
		wantModernHeader(t, recs[3], "MCP-Protocol-Version", "2025-11-25")
	})

	t.Run("initialize error reply fails the fallback", func(t *testing.T) {
		c, log := newModernHarnessWithEra(t, client.EraAuto, []modernScriptAnswer{
			{status: http.StatusBadRequest, body: modernDiscoverJackEnvelope},
			{status: http.StatusOK, body: `{"jsonrpc":"2.0","id":2,"error":{"code":-32602,"message":"bad initialize"}}`},
		})

		err := c.CallTool(context.Background(), "execute_sql", map[string]any{"region": "eu"}, nil)
		if err == nil || !strings.Contains(err.Error(), "legacy initialize failed") {
			t.Fatalf("CallTool error = %v, want a legacy initialize failure", err)
		}
		if got := log.count(); got != 2 {
			t.Fatalf("harness saw %d requests, want 2 (no notifications/initialized, no tools/call)", got)
		}
	})

	t.Run("assigned session id and negotiated version carry forward", func(t *testing.T) {
		c, log := newModernHarnessWithEra(t, client.EraAuto, []modernScriptAnswer{
			{status: http.StatusBadRequest, body: modernDiscoverJackEnvelope},
			{status: http.StatusOK, body: modernInitializeOK, headers: map[string]string{"Mcp-Session-Id": "sess-42"}},
			{status: http.StatusOK, body: modernInitializedOK},
			{status: http.StatusOK, body: modernLegacyToolOK},
		})

		var out struct {
			OK bool `json:"ok"`
		}
		if err := c.CallTool(context.Background(), "execute_sql", map[string]any{"region": "eu"}, &out); err != nil {
			t.Fatalf("CallTool: %v", err)
		}
		if !out.OK {
			t.Fatalf("out = %+v, want {ok:true}", out)
		}

		recs := log.snapshot()
		wantModernMethodOrder(t, recs, "server/discover", "initialize", "notifications/initialized", "tools/call")
		wantModernNoHeader(t, recs[1], "Mcp-Session-Id")
		for _, rec := range recs[2:] {
			wantModernHeader(t, rec, "MCP-Protocol-Version", "2025-11-25")
			wantModernHeader(t, rec, "Mcp-Session-Id", "sess-42")
		}
	})

	t.Run("404 on a known session re-runs the handshake once", func(t *testing.T) {
		const sessionGone = `{"jsonrpc":"2.0","id":3,"error":{"code":-32601,"message":"session not found"}}`
		c, log := newModernHarnessWithEra(t, client.EraAuto, []modernScriptAnswer{
			{status: http.StatusBadRequest, body: modernDiscoverJackEnvelope},
			{status: http.StatusOK, body: modernInitializeOK, headers: map[string]string{"Mcp-Session-Id": "sess-1"}},
			{status: http.StatusOK, body: modernInitializedOK},
			{status: http.StatusNotFound, body: sessionGone},
			{status: http.StatusOK, body: modernInitializeOK, headers: map[string]string{"Mcp-Session-Id": "sess-2"}},
			{status: http.StatusOK, body: modernInitializedOK},
		})

		err := c.CallTool(context.Background(), "execute_sql", map[string]any{"region": "eu"}, nil)
		var httpErr *client.HTTPError
		if !errors.As(err, &httpErr) || httpErr.Status != http.StatusNotFound {
			t.Fatalf("CallTool error = %v, want a *client.HTTPError with status 404", err)
		}

		recs := log.snapshot()
		wantModernMethodOrder(t, recs,
			"server/discover", "initialize", "notifications/initialized", "tools/call", "initialize", "notifications/initialized")
		// The dead session id is not presented again and the operation is not
		// replayed; the fresh handshake assigns a new session.
		wantModernHeader(t, recs[3], "Mcp-Session-Id", "sess-1")
		wantModernNoHeader(t, recs[4], "Mcp-Session-Id")
		wantModernHeader(t, recs[5], "Mcp-Session-Id", "sess-2")
	})
}
