//go:build linux

package rotationserver_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/rotation"
	"github.com/PHPCraftdream/mcp-jack/server"
	rotationserver "github.com/PHPCraftdream/mcp-jack/server/rotation"
)

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
