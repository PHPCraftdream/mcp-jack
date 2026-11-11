//go:build linux

package rotationserver_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
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
