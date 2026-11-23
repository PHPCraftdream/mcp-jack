package server

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/spec"
)

// TestRequestVectors runs every single-request fixture case through the
// verifier, protocol-native tools included.
func TestRequestVectors(t *testing.T) {
	vectors, err := spec.LoadRequestVectors()
	if err != nil {
		t.Fatalf("LoadRequestVectors: %v", err)
	}
	registry, err := spec.LoadRegistry()
	if err != nil {
		t.Fatalf("LoadRegistry: %v", err)
	}
	if len(vectors.Cases) == 0 {
		t.Fatal("no request vectors")
	}

	for _, c := range vectors.Cases {
		c := c
		t.Run(c.ID, func(t *testing.T) {
			body, err := c.Request.Body()
			if err != nil {
				t.Fatalf("Body: %v", err)
			}
			st := registryFromFixture(t, registry)
			nonces := NewNonceStore()
			for _, n := range c.State.NonceCache {
				nonces.CheckAndRecord(n.Kid, n.Nonce, 0, n.RetainUntil)
			}
			now := c.State.Now
			v, err := NewVerifier(Config{
				Aud: c.State.Aud, State: st, Nonces: nonces,
				Native: NewNativeTools(NativeOptions{}),
				Window: int64(c.State.WindowSeconds), Now: func() int64 { return now },
			})
			if err != nil {
				t.Fatalf("NewVerifier: %v", err)
			}
			res := v.Verify(Request{
				Method: c.Request.Method, Target: c.Request.Target,
				AuthValues: jackAuthValues(c.Request.Headers), Body: body,
			})
			checkOutcome(t, c.ID, res, c.Expect)
			if c.Expect.Identity != nil {
				id, ok := identityFromWrappedHandler(t, c, body, st, now)
				if !ok {
					t.Fatalf("%s: the wrapped handler saw no identity", c.ID)
				}
				if id.Kid() != c.Expect.Identity.Kid || id.Name() != c.Expect.Identity.Name || id.Admin() != c.Expect.Identity.Admin {
					t.Fatalf("%s: wrapped-handler identity = %s/%s/%v, want %s/%s/%v", c.ID,
						id.Kid(), id.Name(), id.Admin(), c.Expect.Identity.Kid, c.Expect.Identity.Name, c.Expect.Identity.Admin)
				}
			}
		})
	}
}

// TestAdminSequences replays the state-changing sequences: enrollment, key
// rotation, user and invite administration. Each step runs against the state
// left by the previous one and is compared with its expectation and with the
// state summary recorded after it.
func TestAdminSequences(t *testing.T) {
	vectors, err := spec.LoadAdminVectors()
	if err != nil {
		t.Fatalf("LoadAdminVectors: %v", err)
	}
	if len(vectors.Cases) == 0 {
		t.Fatal("no admin vectors")
	}

	for _, c := range vectors.Cases {
		c := c
		t.Run(c.ID, func(t *testing.T) {
			st := stateFromEntries(t, c.State.Registry)
			if err := st.Update(func(e *StateEdit) error {
				for _, i := range c.State.Invites {
					e.PutInvite(inviteFromFixture(i))
				}
				return nil
			}); err != nil {
				t.Fatalf("seed invites: %v", err)
			}
			nonces := NewNonceStore()
			for _, n := range c.State.NonceCache {
				nonces.CheckAndRecord(n.Kid, n.Nonce, 0, n.RetainUntil)
			}
			now := c.State.Now
			v, err := NewVerifier(Config{
				Aud: c.State.Aud, State: st, Nonces: nonces,
				Native: NewNativeTools(NativeOptions{}), Window: int64(c.State.WindowSeconds),
				Now: func() int64 { return now },
			})
			if err != nil {
				t.Fatalf("NewVerifier: %v", err)
			}

			for i, step := range c.Steps {
				body, err := step.Request.Body()
				if err != nil {
					t.Fatalf("step %d: Body: %v", i, err)
				}
				label := fmt.Sprintf("%s step %d", c.ID, i)
				res := v.Verify(Request{
					Method: step.Request.Method, Target: step.Request.Target,
					AuthValues: jackAuthValues(step.Request.Headers), Body: body,
				})
				checkOutcome(t, label, res, step.Expect)
				if step.Expect.After != nil {
					afterMatches(t, label, *step.Expect.After, st, now)
				}
			}
		})
	}
}

func TestClockStepBackDoesNotReviveExpiredEnrollmentInvite(t *testing.T) {
	rawCode, codeJSON := gateCode()
	high := testNow + 10
	state, nonces := NewMemoryState(), NewNonceStore()
	gateInvite(t, state, rawCode, high)
	clock := high
	v, err := NewVerifier(Config{
		Aud: gateAud, State: state, Nonces: nonces, Native: NewNativeTools(NativeOptions{}),
		Now: func() int64 { return clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	request := gateEnrollRequest(t, codeJSON)
	// This valid timestamp is within the window at both samples; invite liveness is decisive.
	request = signedVerifierRequest(t, testPrivateKey(t, "newbie"), gateAud, "POST", "/mcp", high, 1, request.Body)
	first := v.Verify(request)
	if first.Accepted || first.Code != jack.CodeUnknownKey {
		t.Fatalf("high-time enrollment = %+v, want unknown_key", first)
	}
	clock = testNow
	// Task 165 / spec 01 section 4 Request time: step 4 must use effective time, not revive or consume this invite at the lower sample.
	request = signedVerifierRequest(t, testPrivateKey(t, "newbie"), gateAud, "POST", "/mcp", testNow, 2, request.Body)
	lower := v.Verify(request)
	if lower.Accepted || lower.Code != jack.CodeUnknownKey {
		t.Fatalf("lower-time enrollment = %+v, want unknown_key", lower)
	}
	if _, ok := state.LookupInvite(inviteIDOf(rawCode)); !ok || nonces.Len() != 0 {
		t.Fatalf("expired invite was consumed or nonce recorded: invite remains=%v, nonces=%d", ok, nonces.Len())
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

// TestAdminSequencesFileStatePersistence replays every admin sequence against
// a real file-backed store: every accepted step must survive a serialized
// reopen with an identical state view, and every rejected step must leave the
// raw state file byte-identical. The durable state is checked raw, not only
// through the normalized view (spec 03 sections 9 and 10).
func TestAdminSequencesFileStatePersistence(t *testing.T) {
	vectors, err := spec.LoadAdminVectors()
	if err != nil {
		t.Fatalf("spec.LoadAdminVectors: %v", err)
	}
	if len(vectors.Cases) == 0 {
		t.Fatal("no admin vectors")
	}

	for _, c := range vectors.Cases {
		c := c
		t.Run(c.ID, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.json")
			st, err := OpenFileState(path)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			if err := st.Update(func(e *StateEdit) error {
				for _, entry := range c.State.Registry {
					// The fixture registry omits admin for non-admin keys,
					// so a nil pointer is false.
					e.PutKey(RegistryEntry{
						Kid: entry.Kid, PublicKey: entry.PublicKey, Name: entry.Name,
						Admin:     entry.Admin != nil && *entry.Admin,
						NotBefore: entry.NotBefore, NotAfter: entry.NotAfter,
					})
				}
				for _, i := range c.State.Invites {
					e.PutInvite(inviteFromFixture(i))
				}
				return nil
			}); err != nil {
				t.Fatalf("seed: %v", err)
			}

			nonces := NewNonceStore()
			for _, n := range c.State.NonceCache {
				nonces.CheckAndRecord(n.Kid, n.Nonce, 0, n.RetainUntil)
			}
			now := c.State.Now
			v, err := NewVerifier(Config{
				Aud: c.State.Aud, State: st, Nonces: nonces,
				Native: NewNativeTools(NativeOptions{}), Window: int64(c.State.WindowSeconds),
				Now: func() int64 { return now },
			})
			if err != nil {
				t.Fatalf("NewVerifier: %v", err)
			}

			for i, step := range c.Steps {
				body, err := step.Request.Body()
				if err != nil {
					t.Fatalf("step %d: Body: %v", i, err)
				}
				label := fmt.Sprintf("%s step %d (file state)", c.ID, i)
				before, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("step %d: read state file: %v", i, err)
				}
				res := v.Verify(Request{
					Method: step.Request.Method, Target: step.Request.Target,
					AuthValues: jackAuthValues(step.Request.Headers), Body: body,
				})
				checkOutcome(t, label, res, step.Expect)
				if step.Expect.After != nil {
					afterMatches(t, label, *step.Expect.After, st, now)
				}
				if res.Accepted {
					reopened, err := OpenFileState(path)
					if err != nil {
						t.Fatalf("step %d: reopen: %v", i, err)
					}
					if !reflect.DeepEqual(reopened.View(), st.View()) {
						t.Fatalf("%s: the committed state did not round trip through the state file", label)
					}
				} else {
					after, err := os.ReadFile(path)
					if err != nil {
						t.Fatalf("step %d: read state file: %v", i, err)
					}
					if !bytes.Equal(before, after) {
						t.Fatalf("%s: a rejected step rewrote the raw state file", label)
					}
				}
			}
		})
	}
}

func TestWebhookKeyNativeDispatchOptIn(t *testing.T) {
	const toolName = "jack.server.webhook_key"
	if ToolWebhookKey != toolName {
		t.Fatalf("ToolWebhookKey = %q, want %q", ToolWebhookKey, toolName)
	}
	if IsNativeTool(toolName) {
		t.Fatalf("%q must not be in the default native allowlist", toolName)
	}

	caller := testPrivateKey(t, "alice")
	callerPub := caller.Public().(ed25519.PublicKey)
	callerKID := jack.KeyID(callerPub)
	st := stateFromEntries(t, []spec.RegistryEntry{{
		Kid: callerKID, PublicKey: jack.EncodeBase64URL(callerPub), Name: "alice",
	}})
	webhookPub := testPrivateKey(t, "newbie").Public().(ed25519.PublicKey)
	webhookKey := WebhookKey{KID: jack.KeyID(webhookPub), PublicKey: jack.EncodeBase64URL(webhookPub)}
	tool, err := NewWebhookKeyTool(WebhookKeyConfig{Keys: []WebhookKey{webhookKey}})
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		Aud: gateAud, State: st, Nonces: NewNonceStore(), WebhookKeys: tool,
		Now: func() int64 { return testNow },
	}
	v, err := NewVerifier(cfg)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + toolName + `"}}`)
	req := signedVerifierRequest(t, caller, gateAud, "POST", "/mcp", testNow, 1, body)
	res := v.Verify(req)
	if !res.Accepted || res.Code != "" || !res.Native || res.Tool != toolName {
		t.Fatalf("with WebhookKeys: result = %+v, want accepted native %s with no error code", res, toolName)
	}
	checkOutcome(t, "with WebhookKeys", res, spec.Expect{
		Result: "accept", Kid: callerKID, NonceRecorded: true,
		Structured: []byte(fmt.Sprintf(`{"webhook_key":{"signing_keys":{"keys":[{"kty":"OKP","crv":"Ed25519","x":%q,"kid":%q}]},"egress_ip_ranges":[]}}`, webhookKey.PublicKey, webhookKey.KID)),
	})

	// Reuse the exact signed request, but not the nonce store.
	cfg.WebhookKeys, cfg.Nonces = nil, NewNonceStore()
	v, err = NewVerifier(cfg)
	if err != nil {
		t.Fatal(err)
	}
	res = v.Verify(req)
	if res.Accepted || res.HTTPStatus != 403 || res.Code != jack.CodeOperationDenied {
		t.Fatalf("without WebhookKeys: result = %+v, want 403 operation_denied", res)
	}
}
