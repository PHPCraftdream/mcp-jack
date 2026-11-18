//go:build linux

package rotationserver_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	rotationclient "github.com/PHPCraftdream/mcp-jack/client/rotation"
	"github.com/PHPCraftdream/mcp-jack/durable"
	"github.com/PHPCraftdream/mcp-jack/rotation"
	"github.com/PHPCraftdream/mcp-jack/server"
	rotationserver "github.com/PHPCraftdream/mcp-jack/server/rotation"
)

type nativeFunc func(*server.NativeCall) (server.NativeResult, *jack.Error)

func (call nativeFunc) Call(input *server.NativeCall) (server.NativeResult, *jack.Error) {
	return call(input)
}

func nativeHTTP(t *testing.T, f fixture, provider *rotationserver.Provider, native server.NativeTools) (func(string) *httptest.ResponseRecorder, *int) {
	t.Helper()
	caller := makeSigner(35)
	kid := jack.KeyID(caller.PublicKey())
	state := server.NewMemoryState()
	if err := state.Update(func(edit *server.StateEdit) error {
		edit.PutKey(server.RegistryEntry{Kid: kid, PublicKey: jack.EncodeBase64URL(caller.PublicKey()), Name: "caller"})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	ordinaryNativeCalls := 0
	verifier, err := server.NewVerifier(server.Config{Aud: "provider-test", State: state, Nonces: server.NewNonceStore(), Now: f.now.Load, ServerKeys: native, Native: nativeFunc(func(*server.NativeCall) (server.NativeResult, *jack.Error) {
		ordinaryNativeCalls++
		return server.NativeResult{}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	forwarded := 0
	handler, err := server.NewHandler(server.HandlerConfig{Verifier: verifier, ResponseKeys: provider}, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { forwarded++ }))
	if err != nil {
		t.Fatal(err)
	}
	sequence := byte(0)
	return func(arguments string) *httptest.ResponseRecorder {
		sequence++
		body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"jack.server.key","arguments":` + arguments + `}}`)
		auth := jack.RequestAuth{Kid: kid, TS: f.now.Load(), Nonce: jack.EncodeBase64URL(bytes.Repeat([]byte{sequence}, 16))}
		auth.Sig = jack.EncodeBase64URL(ed25519.Sign(caller.key, []byte(jack.RequestSigningString("POST", "/mcp", "provider-test", kid, auth.TS, auth.Nonce, body))))
		request := httptest.NewRequest("POST", "/mcp", bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Jack-Auth", jack.FormatRequestAuth(auth))
		output := httptest.NewRecorder()
		handler.ServeHTTP(output, request)
		if ordinaryNativeCalls != 0 {
			t.Fatal("candidate route reached ordinary native implementation")
		}
		if output.Header().Get("Jack-Auth") != "" {
			response, err := jack.ParseResponseAuth(output.Header().Values("Jack-Auth"))
			if err != nil {
				t.Fatal(err)
			}
			var public []byte
			for _, key := range f.keys {
				if jack.KeyID(key.PublicKey()) == response.Kid {
					public = key.PublicKey()
				}
			}
			signature, err := jack.DecodeBase64URL(response.Sig)
			if err != nil || len(public) == 0 || !jack.Verify(public, []byte(jack.ResponseSigningString(output.Code, auth.Sig, response.Kid, response.TS, output.Body.Bytes())), signature) {
				t.Fatal("native carrier signature invalid")
			}
		}
		return output
	}, &forwarded
}

func TestNativeServerKeyExplicitDispatchStrictArgumentsAndImmutablePage(t *testing.T) {
	f := setup(t)
	provider, err := rotationserver.New(f.store, f.inventory)
	if err != nil {
		t.Fatal(err)
	}
	first, err := provider.Announce("next", jack.KeyID(f.keys[1].PublicKey()))
	if err != nil {
		t.Fatal(err)
	}
	if server.IsNativeTool(server.ToolServerKey) {
		t.Fatal("default v1 allowlist expanded")
	}
	fixedVerifier, err := server.NewVerifier(server.Config{Aud: "provider-test", State: server.NewMemoryState(), Nonces: server.NewNonceStore(), ServerKeys: provider})
	if err != nil {
		t.Fatal(err)
	}
	if handler, err := server.NewHandler(server.HandlerConfig{Verifier: fixedVerifier, ServerKey: f.keys[0].key}, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})); err == nil || handler != nil {
		t.Fatal("candidate native accepted without ResponseKeys profile")
	}
	closed, forwarded := nativeHTTP(t, f, provider, nil)
	if output := closed(`{"after_ordinal":0,"after_hash":"-"}`); output.Code != 403 || *forwarded != 0 {
		t.Fatal("candidate route enabled by ordinary Native")
	}
	call, forwarded := nativeHTTP(t, f, provider, provider)
	output := call(`{"after_ordinal":0,"after_hash":"-"}`)
	if output.Code != 200 || output.Header().Get("Jack-Auth") == "" {
		t.Fatal("valid native request refused", output.Code)
	}
	page, err := rotation.DecodeResult(output.Body.Bytes(), json.RawMessage(`1`))
	if err != nil || page.Current.KID != jack.KeyID(f.keys[0].PublicKey()) || len(page.Records) != 1 || page.Records[0] != first.Record.Wire || page.Head.Ordinal != 1 || !page.Complete {
		t.Fatal("native page not one exact committed snapshot", err)
	}
	empty := call(`{"after_ordinal":1,"after_hash":"` + first.Record.Hash + `"}`)
	page, err = rotation.DecodeResult(empty.Body.Bytes(), json.RawMessage(`1`))
	if empty.Code != 200 || err != nil || len(page.Records) != 0 || !page.Complete {
		t.Fatal("head cursor did not yield empty complete page")
	}
	for _, arguments := range []string{
		`null`, `{}`, `{"after_ordinal":0,"after_hash":"-","extra":true}`,
		`{"after_ordinal":7,"after_ordinal":0,"after_hash":"-"}`,
		`{"after_ordinal":0,"after_hash":"-","after_hash":"-"}`,
	} {
		if output := call(arguments); output.Code != 400 || output.Header().Get("Jack-Auth") == "" {
			t.Fatal("strict authenticated native refusal missing", output.Code)
		}
	}
	unknown := call(`{"after_ordinal":1,"after_hash":"` + strings.Repeat("A", 43) + `"}`)
	if unknown.Code != 409 || unknown.Header().Get("Jack-Auth") == "" {
		t.Fatal("unavailable cursor not signed409")
	}
	if *forwarded != 0 {
		t.Fatal("candidate native forwarded upstream")
	}
}

func TestNativeServerKeyPageLimitAndExplicitNextCursor(t *testing.T) {
	f := setup(t)
	for index := len(f.keys); index < 18; index++ {
		key := makeSigner(byte(31 + index))
		f.keys = append(f.keys, key)
		f.inventory = append(f.inventory, rotationserver.Key{Reference: "future/" + jack.KeyID(key.PublicKey()), Signer: key})
	}
	provider, err := rotationserver.New(f.store, f.inventory)
	if err != nil {
		t.Fatal(err)
	}
	var records []rotation.Record
	for index := 1; index < len(f.keys); index++ {
		publication, err := provider.Announce(f.inventory[index].Reference, jack.KeyID(f.keys[index].PublicKey()))
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, publication.Record)
	}
	call, forwarded := nativeHTTP(t, f, provider, provider)
	first := call(`{"after_ordinal":0,"after_hash":"-"}`)
	page, err := rotation.DecodeResult(first.Body.Bytes(), json.RawMessage(`1`))
	if first.Code != 200 || err != nil || len(page.Records) != 16 || page.Complete || page.Head.Ordinal != 17 {
		t.Fatal("first native page violated16 record bound", err)
	}
	second := call(`{"after_ordinal":16,"after_hash":"` + records[15].Hash + `"}`)
	page, err = rotation.DecodeResult(second.Body.Bytes(), json.RawMessage(`1`))
	if second.Code != 200 || err != nil || len(page.Records) != 1 || page.Records[0] != records[16].Wire || !page.Complete || *forwarded != 0 {
		t.Fatal("explicit second page did not advance exactly", err)
	}
}

func TestNativeServerKeySigningTimeRejectsChangedHeadOrCurrent(t *testing.T) {
	for _, change := range []string{"head", "current"} {
		t.Run(change, func(t *testing.T) {
			f := setup(t)
			provider, err := rotationserver.New(f.store, f.inventory)
			if err != nil {
				t.Fatal(err)
			}
			first, err := provider.Announce("next", jack.KeyID(f.keys[1].PublicKey()))
			if err != nil {
				t.Fatal(err)
			}
			native := nativeFunc(func(input *server.NativeCall) (server.NativeResult, *jack.Error) {
				result, refusal := provider.Call(input)
				if refusal != nil {
					return result, refusal
				}
				if change == "head" {
					if _, err := provider.Announce("tail", jack.KeyID(f.keys[2].PublicKey())); err != nil {
						t.Fatal(err)
					}
				} else {
					f.now.Store(first.Record.ActivatesAt)
				}
				return result, nil
			})
			call, forwarded := nativeHTTP(t, f, provider, native)
			output := call(`{"after_ordinal":0,"after_hash":"-"}`)
			if output.Code != 503 || output.Header().Get("Jack-Auth") != "" || bytes.Contains(output.Body.Bytes(), []byte("structuredContent")) || *forwarded != 0 {
				t.Fatal("mixed signing-time native snapshot exposed")
			}
		})
	}
}

func nativeResultEnvelope(t *testing.T, payload []byte) []byte {
	t.Helper()
	var envelope struct {
		JSONRPC string `json:"jsonrpc"`
		ID      int    `json:"id"`
		Result  struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
			Structured json.RawMessage `json:"structuredContent"`
			IsError    bool            `json:"isError"`
		} `json:"result"`
	}
	envelope.JSONRPC = "2.0"
	envelope.ID = 1
	envelope.Result.Content = []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}{{Type: "text", Text: string(payload)}}
	envelope.Result.Structured = append(json.RawMessage(nil), payload...)
	body, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestNativeServerKeyCallRejectsRoutesCursorsAndClockFailures(t *testing.T) {
	f := setup(t)
	provider, err := rotationserver.New(f.store, f.inventory)
	if err != nil {
		t.Fatal(err)
	}
	caller := server.RegistryEntry{Kid: "authenticated caller"}
	valid := func(arguments, audience string) *jack.Error {
		_, refusal := provider.Call(&server.NativeCall{Tool: server.ToolServerKey, Arguments: json.RawMessage(arguments), Caller: &caller, Aud: audience})
		return refusal
	}

	// Provider.Call's route guard rejects missing explicit inputs with the exact operation_denied protocol refusal.
	for _, call := range []*server.NativeCall{
		nil,
		{Tool: "other", Caller: &caller},
		{Tool: server.ToolServerKey},
	} {
		_, refusal := provider.Call(call)
		if refusal == nil || refusal.HTTPStatus != 403 || refusal.Code != jack.CodeOperationDenied {
			t.Fatalf("invalid route was not denied: call=%+v refusal=%+v", call, refusal)
		}
	}
	var nilProvider *rotationserver.Provider
	if _, refusal := nilProvider.Call(&server.NativeCall{Tool: server.ToolServerKey, Caller: &caller}); refusal == nil || refusal.HTTPStatus != 403 || refusal.Code != jack.CodeOperationDenied {
		t.Fatalf("nil provider route was not denied: %+v", refusal)
	}
	if refusal := valid(`{}`, "provider-test"); refusal == nil || refusal.HTTPStatus != 400 || refusal.Code != jack.CodeInvalidParams {
		t.Fatalf("invalid arguments refusal = %+v", refusal)
	}
	if refusal := valid(`{"after_ordinal":0,"after_hash":"-"}`, "wrong-audience"); refusal == nil || refusal.HTTPStatus != 503 || refusal.Code != "rotation_state_unavailable" {
		t.Fatalf("wrong audience refusal = %+v", refusal)
	}
	if refusal := valid(`{"after_ordinal":1,"after_hash":"`+strings.Repeat("A", 43)+`"}`, "provider-test"); refusal == nil || refusal.HTTPStatus != 409 || refusal.Code != "rotation_checkpoint_unavailable" {
		t.Fatalf("cursor beyond head refusal = %+v", refusal)
	}
	// rotation/arguments.go:DecodeServerKeyArguments requires the literal "-" hash for ordinal 0, so this cursor is malformed before any checkpoint lookup.
	if refusal := valid(`{"after_ordinal":0,"after_hash":"`+strings.Repeat("A", 43)+`"}`, "provider-test"); refusal == nil || refusal.HTTPStatus != 400 || refusal.Code != jack.CodeInvalidParams {
		t.Fatalf("genesis cursor with a non-dash hash refusal = %+v", refusal)
	}
	if err := f.store.Close(); err != nil {
		t.Fatal("close before post-close route check:", err)
	}
	if refusal := valid(`{"after_ordinal":0,"after_hash":"-"}`, "provider-test"); refusal == nil || refusal.HTTPStatus != 503 || refusal.Code != "rotation_state_unavailable" {
		t.Fatalf("closed store route refusal = %+v", refusal)
	}
}

func TestNativeServerKeyCallRefusesSignerMissingFromInventory(t *testing.T) {
	f := setup(t)
	incomplete, err := rotationserver.New(f.store, f.inventory[:1])
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := rotationserver.New(f.store, f.inventory)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Announce("next", jack.KeyID(f.keys[1].PublicKey())); err != nil {
		t.Fatal(err)
	}
	_, refusal := incomplete.Call(&server.NativeCall{
		Tool: server.ToolServerKey, Arguments: json.RawMessage(`{"after_ordinal":0,"after_hash":"-"}`),
		Caller: &server.RegistryEntry{Kid: "caller"}, Aud: "provider-test",
	})
	// rotation/server_state.go:ValidateServerSnapshot requires one signer reference per verified ring key, so the missing pending handle fails closed.
	if refusal == nil || refusal.HTTPStatus != 503 || refusal.Code != "rotation_state_unavailable" {
		t.Fatalf("missing pending signer refusal = %+v", refusal)
	}
}

func TestNativeResponseParsingAndSnapshotParityAreAuthoritative(t *testing.T) {
	f := setup(t)
	provider, err := rotationserver.New(f.store, f.inventory)
	if err != nil {
		t.Fatal(err)
	}
	first, err := provider.Announce("next", jack.KeyID(f.keys[1].PublicKey()))
	if err != nil {
		t.Fatal(err)
	}
	second, err := provider.Announce("tail", jack.KeyID(f.keys[2].PublicKey()))
	if err != nil {
		t.Fatal(err)
	}
	call := &server.NativeCall{Tool: server.ToolServerKey, Arguments: json.RawMessage(`{"after_ordinal":0,"after_hash":"-"}`), Caller: &server.RegistryEntry{Kid: "caller"}, Aud: "provider-test"}
	result, refusal := provider.Call(call)
	if refusal != nil {
		t.Fatal(refusal)
	}
	payload, err := json.Marshal(result.Structured)
	if err != nil {
		t.Fatal(err)
	}
	validBody := nativeResultEnvelope(t, payload)

	// Non-key and non-200 bodies are not decoded as native pages; signer selection remains tied to the verified store snapshot.
	for name, input := range map[string]server.ResponseKeyRequest{
		"wrong-tool":         {Tool: "not-a-key-tool", Status: 200, Body: validBody},
		"non-success-status": {Tool: server.ToolServerKey, Status: 503, Body: validBody},
	} {
		authorization, err := provider.AuthorizeResponse(input)
		if err != nil || authorization.Signer == nil || authorization.Timestamp != 1000 {
			t.Fatalf("%s carrier affected key selection: %+v err=%v", name, authorization, err)
		}
		authorization.Release()
	}
	for name, input := range map[string]server.ResponseKeyRequest{
		"oversized":        {Tool: server.ToolServerKey, Status: 200, Body: bytes.Repeat([]byte{' '}, rotation.MaxResultBodyBytes+1)},
		"malformed-json":   {Tool: server.ToolServerKey, Status: 200, Body: []byte("{")},
		"invalid-envelope": {Tool: server.ToolServerKey, Status: 200, Body: []byte(`{"jsonrpc":"2.0","id":1,"result":{}}`)},
	} {
		if _, err := provider.AuthorizeResponse(input); !errors.Is(err, rotationserver.ErrUnavailable) {
			t.Errorf("%s response error = %v, want ErrUnavailable", name, err)
		}
	}

	var decoded map[string]any
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if err := decoder.Decode(&decoded); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(map[string]any){
		"wrong-current-kid": func(value map[string]any) { value["current"].(map[string]any)["kid"] = "other" },
		"wrong-current-key": func(value map[string]any) {
			value["current"].(map[string]any)["kid"] = jack.KeyID(f.keys[1].PublicKey())
			value["current"].(map[string]any)["public_key"] = jack.EncodeBase64URL(f.keys[1].PublicKey())
		},
		"wrong-head":         func(value map[string]any) { value["head"].(map[string]any)["hash"] = strings.Repeat("A", 43) },
		"wrong-completeness": func(value map[string]any) { value["complete"] = false },
		"wrong-sequence": func(value map[string]any) {
			value["records"].([]any)[1] = "different second record"
		},
		"empty-incomplete": func(value map[string]any) { value["records"] = []any{}; value["complete"] = false },
	}
	// native.go:matchesNativeResponse rejects a returned page whose first record does not start in the committed history.
	// The result chain is the committed store snapshot; the page-start loop must refuse a wire absent from that history.
	cases["no-matching-record"] = func(value map[string]any) {
		value["records"].([]any)[0] = "record not in committed history"
	}
	// native.go:matchesNativeResponse refuses a record suffix that extends beyond the committed record slice.
	cases["page-past-history-end"] = func(value map[string]any) {
		value["records"] = append(value["records"].([]any), "extra record")
		value["complete"] = false
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			candidate := make(map[string]any, len(decoded))
			for key, value := range decoded {
				candidate[key] = value
			}
			candidate["current"] = cloneNativeObject(decoded["current"].(map[string]any))
			candidate["head"] = cloneNativeObject(decoded["head"].(map[string]any))
			candidate["records"] = append([]any(nil), decoded["records"].([]any)...)
			mutate(candidate)
			badPayload, err := json.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			// native.go:decodeNativeResponse maps malformed, oversized, or schema-invalid successful carriers to ErrUnavailable.
			if _, err := provider.AuthorizeResponse(server.ResponseKeyRequest{Tool: server.ToolServerKey, Status: 200, Body: nativeResultEnvelope(t, badPayload)}); !errors.Is(err, rotationserver.ErrUnavailable) {
				t.Fatalf("response inconsistency error = %v, want ErrUnavailable", err)
			}
		})
	}

	// native.go:matchesNativeResponse uses the returned identity, head, page bounds, and exact committed record order as its oracle.
	// The payload is JSON, so record LFs appear as escapes: compare the decoded records, in committed order.
	pageRecords, _ := decoded["records"].([]any)
	firstAt, secondAt := -1, -1
	for i, record := range pageRecords {
		switch record {
		case first.Record.Wire:
			firstAt = i
		case second.Record.Wire:
			secondAt = i
		}
	}
	if firstAt < 0 || secondAt != firstAt+1 {
		t.Fatalf("valid page does not contain the committed publication chain in order: first at %d, second at %d", firstAt, secondAt)
	}
	if authorization, err := provider.AuthorizeResponse(server.ResponseKeyRequest{Tool: server.ToolServerKey, Status: 200, Body: validBody}); err != nil {
		t.Fatalf("exact committed page refused: %v", err)
	} else {
		authorization.Release()
	}
	// server/native.go:Call converts the CheckSnapshotClock failure into rotation_state_unavailable without returning a page.
	f.now.Store(-1)
	if _, refusal := provider.Call(call); refusal == nil || refusal.HTTPStatus != 503 || refusal.Code != "rotation_state_unavailable" {
		t.Fatalf("unsafe authoritative clock refusal = %+v", refusal)
	}
}

func cloneNativeObject(input map[string]any) map[string]any {
	out := make(map[string]any, len(input))
	for key, value := range input {
		out[key] = value
	}
	return out
}

func TestConcreteProviderThroughMiddlewareFinalBeforeWireAndConsumedReplay(t *testing.T) {
	for _, late := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "late-final"}[late], func(t *testing.T) {
			f := setup(t)
			signs := 0
			f.inventory[0].Signer = signingHook{testSigner: f.keys[0], onSign: func() {
				signs++
				if late {
					f.now.Store(1031)
				}
			}}
			provider, err := rotationserver.New(f.store, f.inventory)
			if err != nil {
				t.Fatal(err)
			}
			caller := makeSigner(34)
			kid := jack.KeyID(caller.PublicKey())
			state := server.NewMemoryState()
			if err := state.Update(func(edit *server.StateEdit) error {
				edit.PutKey(server.RegistryEntry{Kid: kid, PublicKey: jack.EncodeBase64URL(caller.PublicKey()), Name: "caller"})
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			nonces := server.NewNonceStore()
			verifier, err := server.NewVerifier(server.Config{Aud: "provider-test", State: state, Nonces: nonces, Now: func() int64 { return 1000 }})
			if err != nil {
				t.Fatal(err)
			}
			applications := 0
			handler, err := server.NewHandler(server.HandlerConfig{Verifier: verifier, ResponseKeys: provider}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				applications++
				w.Header().Set("X-Private-App", "not-on-refusal")
				_, _ = w.Write([]byte("exact application body"))
			}))
			if err != nil {
				t.Fatal(err)
			}
			body := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
			auth := jack.RequestAuth{Kid: kid, TS: 1000, Nonce: jack.EncodeBase64URL(bytes.Repeat([]byte{18}, 16))}
			message := jack.RequestSigningString("POST", "/mcp", "provider-test", kid, auth.TS, auth.Nonce, body)
			auth.Sig = jack.EncodeBase64URL(ed25519.Sign(caller.key, []byte(message)))
			request := func() *http.Request {
				r := httptest.NewRequest("POST", "/mcp", bytes.NewReader(body))
				r.Header.Set("Jack-Auth", jack.FormatRequestAuth(auth))
				r.Header.Set("Content-Type", "application/json")
				return r
			}
			output := httptest.NewRecorder()
			handler.ServeHTTP(output, request())
			if signs != 1 || applications != 1 || nonces.Len() != 1 {
				t.Fatal("wrong sign/dispatch/reservation count")
			}
			if late {
				if output.Code != 503 || output.Header().Get("Jack-Auth") != "" || output.Header().Get("X-Private-App") != "" || bytes.Contains(output.Body.Bytes(), []byte("exact application body")) {
					t.Fatal("late final leaked signed/application output")
				}
			} else {
				if output.Code != 200 || output.Body.String() != "exact application body" {
					t.Fatal("valid response lost")
				}
				response, err := jack.ParseResponseAuth(output.Header().Values("Jack-Auth"))
				if err != nil || response.Kid != jack.KeyID(f.keys[0].PublicKey()) || response.TS != 1000 {
					t.Fatal("wrong pinned wire identity/time")
				}
				signature, err := jack.DecodeBase64URL(response.Sig)
				if err != nil || !jack.Verify(f.keys[0].PublicKey(), []byte(jack.ResponseSigningString(200, auth.Sig, response.Kid, response.TS, output.Body.Bytes())), signature) {
					t.Fatal("wire response signature invalid")
				}
			}
			replay := httptest.NewRecorder()
			handler.ServeHTTP(replay, request())
			if replay.Code != 401 || signs != 1 || applications != 1 {
				t.Fatal("consumed request redelivered or signed again")
			}
			if err := f.store.Close(); err != nil {
				t.Fatal("middleware leaked serving lease", err)
			}
		})
	}
}

type requestSigner struct{ testSigner }

func (key requestSigner) KID() string { return jack.KeyID(key.PublicKey()) }

type handlerSlot struct{ handler http.Handler }
type capturedRequest struct {
	body   []byte
	auth   []string
	target string
}

func integrationDirectory(t *testing.T) string {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func TestNativeRefreshActualHTTPDurableNonceAndClientRestart(t *testing.T) {
	var active atomic.Value
	captured := make(chan capturedRequest, 1)
	var requests, nativeCalls, appCalls atomic.Int32
	httpServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		body, err := io.ReadAll(r.Body)
		_ = r.Body.Close()
		if err != nil {
			t.Error(err)
			http.Error(w, "fixture request unavailable", 500)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		select {
		case captured <- capturedRequest{body: append([]byte{}, body...), auth: append([]string{}, r.Header.Values("Jack-Auth")...), target: r.URL.RequestURI()}:
		default:
		}
		active.Load().(handlerSlot).handler.ServeHTTP(w, r)
	}))
	defer httpServer.Close()
	endpoint := "http://" + httpServer.Listener.Addr().String() + "/mcp"
	f := setupWithEndpoint(t, endpoint, nil)
	provider, err := rotationserver.New(f.store, f.inventory)
	if err != nil {
		t.Fatal(err)
	}
	first, err := provider.Announce("next", jack.KeyID(f.keys[1].PublicKey()))
	if err != nil {
		t.Fatal(err)
	}
	second, err := provider.Announce("tail", jack.KeyID(f.keys[2].PublicKey()))
	if err != nil {
		t.Fatal(err)
	}
	caller := requestSigner{makeSigner(88)}
	state := server.NewMemoryState()
	if err := state.Update(func(edit *server.StateEdit) error {
		edit.PutKey(server.RegistryEntry{Kid: caller.KID(), PublicKey: jack.EncodeBase64URL(caller.PublicKey()), Name: "durable-refresh-caller"})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	noncePath := filepath.Join(integrationDirectory(t), "nonce.db")
	nonceOptions := durable.Options{DeploymentID: "native-refresh-e2e", Window: 30, Now: f.now.Load}
	if err := durable.InitializeUnused(noncePath, nonceOptions); err != nil {
		t.Fatal(err)
	}
	nonces, err := durable.Open(noncePath, nonceOptions)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if nonces != nil {
			_ = nonces.Close()
		}
	}()
	wrap := func(owner *durable.Store) http.Handler {
		verifier, err := server.NewVerifier(server.Config{Aud: "provider-test", State: state, DurableNonces: owner, Now: f.now.Load, ServerKeys: nativeFunc(func(call *server.NativeCall) (server.NativeResult, *jack.Error) {
			nativeCalls.Add(1)
			return provider.Call(call)
		})})
		if err != nil {
			t.Fatal(err)
		}
		handler, err := server.NewHandler(server.HandlerConfig{Verifier: verifier, ResponseKeys: provider}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { appCalls.Add(1); _, _ = w.Write([]byte(`{"ok":true}`)) }))
		if err != nil {
			t.Fatal(err)
		}
		return handler
	}
	active.Store(handlerSlot{handler: wrap(nonces)})
	httpServer.Start()
	checkpoint := rotation.Checkpoint{Hash: "-", KID: jack.KeyID(f.keys[0].PublicKey())}
	copy(checkpoint.PublicKey[:], f.keys[0].PublicKey())
	trustOptions := durable.TrustOptions{Binding: rotation.Binding{Endpoint: endpoint, Audience: "provider-test"}, Window: 30, Checkpoint: checkpoint, Now: f.now.Load}
	trustPath := filepath.Join(integrationDirectory(t), "trust.db")
	if err := durable.InitializeTrustUnused(trustPath, trustOptions); err != nil {
		t.Fatal(err)
	}
	trust, err := durable.OpenTrust(trustPath, trustOptions)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if trust != nil {
			_ = trust.Close()
		}
	}()
	sender, err := rotationclient.NewHTTP(trust, caller, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ack, err := sender.Refresh(ctx)
	if err != nil || !ack.Committed || !ack.Complete || ack.Terminal.Ordinal != 2 || ack.Terminal.Hash != second.Record.Hash || ack.Revision != 2 {
		t.Fatal("actual native refresh did not ACK exact two-record page", err)
	}
	var replay capturedRequest
	select {
	case replay = <-captured:
	case <-ctx.Done():
		t.Fatal("request capture missing")
	}
	if replay.target != "/mcp" {
		t.Fatal("wrong captured signed target")
	}
	duplicate, err := sender.Refresh(ctx)
	if err != nil || duplicate.Committed || duplicate.Revision != 2 || requests.Load() != 2 || nativeCalls.Load() != 2 || appCalls.Load() != 0 {
		t.Fatal("duplicate refresh mutated trust, retried or forwarded", err)
	}
	if err := nonces.Close(); err != nil {
		t.Fatal(err)
	}
	nonces, err = durable.Open(noncePath, nonceOptions)
	if err != nil {
		t.Fatal(err)
	}
	active.Store(handlerSlot{handler: wrap(nonces)})
	request, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(replay.body))
	if err != nil {
		t.Fatal(err)
	}
	request.GetBody = nil
	request.Header.Set("Content-Type", "application/json")
	for _, value := range replay.auth {
		request.Header.Add("Jack-Auth", value)
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport, Timeout: 5 * time.Second}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	refusal, readErr := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || response.StatusCode != 401 || response.Header.Get("Jack-Auth") != "" || !bytes.Contains(refusal, []byte("replayed_nonce")) || nativeCalls.Load() != 2 || appCalls.Load() != 0 {
		t.Fatal("exact native request replay admitted after durable nonce restart")
	}
	if err := trust.Close(); err != nil {
		t.Fatal(err)
	}
	trust, err = durable.OpenTrust(trustPath, trustOptions)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, _, err := trust.Snapshot()
	if err != nil || snapshot.Revision != 2 || snapshot.Head != ack.Terminal || len(snapshot.Records) != 2 {
		t.Fatal("client restart lost confirmed trust")
	}
	sender, err = rotationclient.NewHTTP(trust, caller, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	f.now.Store(first.Record.ActivatesAt)
	reply, err := sender.Call(ctx, []byte(`{"jsonrpc":"2.0","id":9,"method":"ping"}`))
	if err != nil || reply.Status != 200 || string(reply.Body) != `{"ok":true}` || appCalls.Load() != 1 || nativeCalls.Load() != 2 || requests.Load() != 4 {
		t.Fatal("restarted client failed new signer or performed hidden refresh", err)
	}
	final, err := sender.Refresh(ctx)
	if err != nil || final.Committed || final.Revision != 2 || final.Terminal != ack.Terminal || nativeCalls.Load() != 3 || appCalls.Load() != 1 || requests.Load() != 5 {
		t.Fatal("explicit post-activation duplicate refresh changed ACK or retried", err)
	}
}
