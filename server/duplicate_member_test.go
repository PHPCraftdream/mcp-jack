package server

import (
	"crypto/ed25519"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
)

// TestClassifyBodyDuplicateMembers pins that a repeated member name at any
// depth makes the body unacceptable, while equal names in different objects
// are fine.
func TestClassifyBodyDuplicateMembers(t *testing.T) {
	cases := []struct {
		name string
		body string
		ok   bool
	}{
		{"top level", `{"jsonrpc":"2.0","id":1,"id":2,"method":"ping"}`, false},
		{"nested in params", `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"a":1,"a":2}}`, false},
		{"object inside an array", `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":[{"k":1},{"k":1,"k":2}]}}`, false},
		{"free-form tool arguments", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t","arguments":{"q":{"z":1,"z":1}}}}`, false},
		{"escaped name", `{"jsonrpc":"2.0","id":1,"meth\u006fd":"ping","method":"ping"}`, false},
		{"same names in different objects", `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"a":{"k":1},"b":{"k":2},"c":[{"k":3},{"k":4}]}}`, true},
		{"name equal to a string value", `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"a":"a","b":"a"}}`, true},
		{"case differs", `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"a":1,"A":2}}`, true},
		// A huge number literal must not abort the duplicate scan: without
		// UseNumber the token decoder errors on 1e999 and a duplicate after
		// it would be missed.
		{"1e999 then duplicate", `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":1e999,"x":2}}`, false},
		{"1e999 without duplicates", `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":1e999,"y":2}}`, true},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			if _, ok := classifyBody([]byte(c.body)); ok != c.ok {
				t.Fatalf("ok = %v, want %v", ok, c.ok)
			}
		})
	}
}

// TestDuplicateMemberIsInvalidRequestAfterAuth checks the rejection happens
// after authentication: the nonce is consumed.
func TestDuplicateMemberIsInvalidRequestAfterAuth(t *testing.T) {
	st, nonces := NewMemoryState(), NewNonceStore()
	key := testPrivateKey(t, "newbie")
	pub := key.Public().(ed25519.PublicKey)
	kid := jack.KeyID(pub)
	if err := st.Update(func(e *StateEdit) error {
		e.PutKey(RegistryEntry{Kid: kid, PublicKey: jack.EncodeBase64URL(pub), Name: "dup"})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping","method":"ping"}`)
	nonce := jack.EncodeBase64URL(make([]byte, 16))
	signing := jack.RequestSigningString("POST", "/mcp", gateAud, kid, testNow, nonce, body)
	sig := jack.EncodeBase64URL(ed25519.Sign(key, []byte(signing)))
	header := jack.FormatRequestAuth(jack.RequestAuth{Kid: kid, TS: testNow, Nonce: nonce, Sig: sig})
	res := gateVerifier(t, st, nonces, testNow).Verify(Request{Method: "POST", Target: "/mcp", AuthValues: []string{header}, Body: body})
	if res.Accepted || res.HTTPStatus != 400 || res.Code != jack.CodeInvalidRequest || !res.NonceRecorded || nonces.Len() != 1 {
		t.Fatalf("result = %+v, want 400 invalid_request with the nonce consumed", res)
	}
}
