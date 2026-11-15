package server

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
)

const gateAud = "gate-aud"

// gateEnrollRequest builds a signed jack.enroll request for an unregistered
// key; code is the raw JSON text of the code argument.
func gateEnrollRequest(t *testing.T, codeJSON string) Request {
	t.Helper()
	key := testPrivateKey(t, "newbie")
	pub := key.Public().(ed25519.PublicKey)
	kid := jack.KeyID(pub)
	body := []byte(fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"jack.enroll","arguments":{"code":%s,"name":"fresh","public_key":%q}}}`,
		codeJSON, jack.EncodeBase64URL(pub)))
	nonce := jack.EncodeBase64URL(make([]byte, 16))
	signing := jack.RequestSigningString("POST", "/mcp", gateAud, kid, testNow, nonce, body)
	sig := jack.EncodeBase64URL(ed25519.Sign(key, []byte(signing)))
	header := jack.FormatRequestAuth(jack.RequestAuth{Kid: kid, TS: testNow, Nonce: nonce, Sig: sig})
	return Request{Method: "POST", Target: "/mcp", AuthValues: []string{header}, Body: body}
}

func gateVerifier(t *testing.T, st StateStore, nonces *NonceStore, now int64) *Verifier {
	t.Helper()
	v, err := NewVerifier(Config{
		Aud: gateAud, State: st, Nonces: nonces,
		Native: NewNativeTools(NativeOptions{}), Now: func() int64 { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func gateInvite(t *testing.T, st *MemoryState, rawCode []byte, expiresAt int64) {
	t.Helper()
	invite := InviteRecord{InviteID: inviteIDOf(rawCode), CreatedBy: "admin", CreatedAt: testNow - 10, ExpiresAt: expiresAt}
	if err := st.Update(func(e *StateEdit) error { e.PutInvite(invite); return nil }); err != nil {
		t.Fatal(err)
	}
}

func gateCode() ([]byte, string) {
	raw := sha256.Sum256([]byte("gate invite"))
	return raw[:], `"` + jack.EncodeBase64URL(raw[:]) + `"`
}

func assertUnknownKey(t *testing.T, res Result, nonces *NonceStore) {
	t.Helper()
	if res.Accepted || res.HTTPStatus != 401 || res.Code != jack.CodeUnknownKey {
		t.Fatalf("result = %+v, want 401 unknown_key", res)
	}
	if res.NonceRecorded || res.RequestSig != "" || res.Audit != nil || nonces.Len() != 0 {
		t.Fatalf("rejection must be unsigned, unaudited and leave the nonce store untouched: %+v, nonces=%d", res, nonces.Len())
	}
}

func TestEnrollmentRequiresLiveInvite(t *testing.T) {
	raw, codeJSON := gateCode()
	const expires = testNow + 600

	t.Run("no invite", func(t *testing.T) {
		nonces := NewNonceStore()
		res := gateVerifier(t, NewMemoryState(), nonces, testNow).Verify(gateEnrollRequest(t, codeJSON))
		assertUnknownKey(t, res, nonces)
	})
	t.Run("expired exactly now", func(t *testing.T) {
		st, nonces := NewMemoryState(), NewNonceStore()
		gateInvite(t, st, raw, testNow)
		res := gateVerifier(t, st, nonces, testNow).Verify(gateEnrollRequest(t, codeJSON))
		assertUnknownKey(t, res, nonces)
	})
	t.Run("non-canonical code", func(t *testing.T) {
		st, nonces := NewMemoryState(), NewNonceStore()
		gateInvite(t, st, raw, expires)
		for _, bad := range []string{`"` + jack.EncodeBase64URL(raw) + `="`, `"short"`, `42`, `null`} {
			res := gateVerifier(t, st, nonces, testNow).Verify(gateEnrollRequest(t, bad))
			assertUnknownKey(t, res, nonces)
		}
	})
	t.Run("live invite enrolls", func(t *testing.T) {
		st, nonces := NewMemoryState(), NewNonceStore()
		gateInvite(t, st, raw, expires)
		res := gateVerifier(t, st, nonces, testNow).Verify(gateEnrollRequest(t, codeJSON))
		if !res.Accepted || !res.NonceRecorded || nonces.Len() != 1 {
			t.Fatalf("result = %+v, want accepted enrollment", res)
		}
		if _, ok := st.Lookup(res.Kid); !ok {
			t.Fatal("key was not enrolled")
		}
	})
}

func TestLookupInviteReturnsCopy(t *testing.T) {
	st := NewMemoryState()
	raw, _ := gateCode()
	gateInvite(t, st, raw, testNow+5)
	ttl := int64(7)
	if err := st.Update(func(e *StateEdit) error {
		inv, _ := e.Invite(inviteIDOf(raw))
		inv.KeyTTLSeconds = &ttl
		e.PutInvite(inv)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	got, ok := st.LookupInvite(inviteIDOf(raw))
	if !ok || got.KeyTTLSeconds == nil {
		t.Fatalf("LookupInvite = %+v, %v", got, ok)
	}
	*got.KeyTTLSeconds = 99
	again, _ := st.LookupInvite(inviteIDOf(raw))
	if *again.KeyTTLSeconds != 7 {
		t.Fatal("LookupInvite aliased the stored invite")
	}
	if _, ok := st.LookupInvite("missing"); ok {
		t.Fatal("unknown invite found")
	}
}
