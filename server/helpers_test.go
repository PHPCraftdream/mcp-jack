package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/server/internal/testfixture"
	"github.com/PHPCraftdream/mcp-jack/spec"
)

// testNow is the fixed fixture clock used by the remaining root tests.
const testNow = testfixture.Now

func testPrivateKey(t *testing.T, name string) ed25519.PrivateKey {
	return testfixture.PrivateKey(t, name)
}

// registryFromFixture loads the default fixture registry into a MemoryState.
func registryFromFixture(t *testing.T, doc spec.RegistryDocument) *MemoryState {
	t.Helper()
	return stateFromEntries(t, doc.Keys)
}

func stateFromEntries(t *testing.T, entries []spec.RegistryEntry) *MemoryState {
	t.Helper()
	st := NewMemoryState()
	err := st.Update(func(e *StateEdit) error {
		for _, entry := range entries {
			// The fixture registry omits admin for non-admin keys, so a nil
			// pointer is false.
			e.PutKey(RegistryEntry{
				Kid: entry.Kid, PublicKey: entry.PublicKey, Name: entry.Name,
				Admin:     entry.Admin != nil && *entry.Admin,
				NotBefore: entry.NotBefore, NotAfter: entry.NotAfter,
			})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("seed registry: %v", err)
	}
	return st
}

func jackAuthValues(headers []spec.HeaderPair) []string {
	var values []string
	for _, h := range headers {
		if strings.EqualFold(h.Name, "Jack-Auth") {
			values = append(values, h.Value)
		}
	}
	return values
}

// matchValue compares decoded JSON values; the string "<b64u43>" in want
// matches any canonical base64url encoding of 32 bytes (invite codes and ids
// are random in real servers, so fixtures cannot contain them).
func matchValue(want, got any) bool {
	switch w := want.(type) {
	case string:
		g, ok := got.(string)
		if !ok {
			return false
		}
		if w == "<b64u43>" {
			_, err := jack.DecodeBase64URLFixed(g, 32)
			return err == nil
		}
		return w == g
	case []any:
		g, ok := got.([]any)
		if !ok || len(g) != len(w) {
			return false
		}
		for i := range w {
			if !matchValue(w[i], g[i]) {
				return false
			}
		}
		return true
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok || len(g) != len(w) {
			return false
		}
		for k, wv := range w {
			gv, present := g[k]
			if !present || !matchValue(wv, gv) {
				return false
			}
		}
		return true
	default:
		return reflect.DeepEqual(want, got)
	}
}

// checkOutcome compares a verifier result with a fixture expectation.
func checkOutcome(t *testing.T, label string, res Result, want spec.Expect) {
	t.Helper()
	if (want.Result == "accept") != res.Accepted {
		t.Fatalf("%s: Accepted = %v (%d %s), want result %q", label, res.Accepted, res.HTTPStatus, res.Code, want.Result)
	}
	if res.Accepted {
		if res.Kid != want.Kid {
			t.Fatalf("%s: Kid = %q, want %q", label, res.Kid, want.Kid)
		}
	} else if res.HTTPStatus != want.HTTPStatus || res.Code != want.Code {
		t.Fatalf("%s: rejection = %d %s, want %d %s", label, res.HTTPStatus, res.Code, want.HTTPStatus, want.Code)
	}
	if res.NonceRecorded != want.NonceRecorded {
		t.Fatalf("%s: NonceRecorded = %v, want %v", label, res.NonceRecorded, want.NonceRecorded)
	}

	switch {
	case want.Audit == nil && res.Audit != nil:
		t.Fatalf("%s: unexpected audit event %+v", label, *res.Audit)
	case want.Audit != nil && res.Audit == nil:
		t.Fatalf("%s: missing audit event, want %+v", label, *want.Audit)
	case want.Audit != nil:
		wantCode := ""
		if want.Audit.Code != nil {
			wantCode = *want.Audit.Code
		}
		a := res.Audit
		if a.Tool != want.Audit.Tool || a.Outcome != want.Audit.Outcome || a.Code != wantCode || a.ActorKid != want.Audit.ActorKid {
			t.Fatalf("%s: audit = %+v, want %+v (code %q)", label, *a, *want.Audit, wantCode)
		}
	}

	if want.Identity != nil {
		if res.Identity == nil || res.Identity.Kid() != want.Identity.Kid || res.Identity.Name() != want.Identity.Name || res.Identity.Admin() != want.Identity.Admin {
			t.Fatalf("%s: identity = %+v, want %s/%s/%v", label, res.Identity, want.Identity.Kid, want.Identity.Name, want.Identity.Admin)
		}
	}

	if len(want.Structured) > 0 {
		gotJSON, err := json.Marshal(res.Structured)
		if err != nil {
			t.Fatalf("%s: marshal structured result: %v", label, err)
		}
		var wantValue, gotValue any
		if err := json.Unmarshal(want.Structured, &wantValue); err != nil {
			t.Fatalf("%s: decode expected structured result: %v", label, err)
		}
		if err := json.Unmarshal(gotJSON, &gotValue); err != nil {
			t.Fatalf("%s: decode structured result: %v", label, err)
		}
		if !matchValue(wantValue, gotValue) {
			t.Fatalf("%s: structured result\n got %s\nwant %s", label, gotJSON, want.Structured)
		}
	}
}

// summarize mirrors the "after" expectation of the sequence vectors. Users
// are sorted by name; invites are every stored invite — durable state, not
// the live listing — sorted by invite id, ties by created_at.
func summarize(st StateStore, now int64) spec.AfterState {
	view := st.View()
	keys := append([]RegistryEntry(nil), view.Keys...)
	sort.Slice(keys, func(i, j int) bool { return keys[i].Name < keys[j].Name })
	users := make([]spec.UserSummary, 0, len(keys))
	for _, k := range keys {
		users = append(users, spec.UserSummary{
			Kid: k.Kid, PublicKey: k.PublicKey, Name: k.Name, Admin: k.Admin,
			NotBefore: k.NotBefore, NotAfter: k.NotAfter,
		})
	}
	invites := append([]InviteRecord(nil), view.Invites...)
	sort.Slice(invites, func(i, j int) bool {
		if invites[i].InviteID != invites[j].InviteID {
			return invites[i].InviteID < invites[j].InviteID
		}
		return invites[i].CreatedAt < invites[j].CreatedAt
	})
	summaries := make([]spec.InviteSummary, 0, len(invites))
	for _, inv := range invites {
		summaries = append(summaries, spec.InviteSummary{
			InviteID: inv.InviteID, Admin: inv.Admin, CreatedBy: inv.CreatedBy,
			CreatedAt: inv.CreatedAt, ExpiresAt: inv.ExpiresAt, KeyTTLSeconds: inv.KeyTTLSeconds,
		})
	}
	return spec.AfterState{Users: users, Invites: summaries}
}

// afterMatches compares the post-step state with the fixture expectation,
// "<b64u43>" wildcards included. Users are matched positionally (sorted by
// name on both sides); invites are matched as an unordered multiset because
// an implementation-created invite id sorts by an unknown text.
func afterMatches(t *testing.T, label string, want spec.AfterState, st StateStore, now int64) bool {
	t.Helper()
	got := summarize(st, now)
	if len(got.Users) != len(want.Users) {
		t.Fatalf("%s: users after the step: %d entries, want %d\n got %+v\nwant %+v", label, len(got.Users), len(want.Users), got.Users, want.Users)
	}
	for i := range want.Users {
		gotJSON, err := json.Marshal(got.Users[i])
		if err != nil {
			t.Fatalf("%s: marshal user: %v", label, err)
		}
		wantJSON, err := json.Marshal(want.Users[i])
		if err != nil {
			t.Fatalf("%s: marshal expected user: %v", label, err)
		}
		var gotVal, wantVal any
		if err := json.Unmarshal(gotJSON, &gotVal); err != nil {
			t.Fatalf("%s: decode user: %v", label, err)
		}
		if err := json.Unmarshal(wantJSON, &wantVal); err != nil {
			t.Fatalf("%s: decode expected user: %v", label, err)
		}
		if !matchValue(wantVal, gotVal) {
			t.Fatalf("%s: user %d after the step\n got %s\nwant %s", label, i, gotJSON, wantJSON)
		}
	}
	if len(got.Invites) != len(want.Invites) {
		t.Fatalf("%s: invites after the step: %d records, want %d\n got %+v\nwant %+v", label, len(got.Invites), len(want.Invites), got.Invites, want.Invites)
	}
	consumed := make([]bool, len(got.Invites))
	for _, w := range want.Invites {
		wantJSON, err := json.Marshal(w)
		if err != nil {
			t.Fatalf("%s: marshal expected invite: %v", label, err)
		}
		var wantVal any
		if err := json.Unmarshal(wantJSON, &wantVal); err != nil {
			t.Fatalf("%s: decode expected invite: %v", label, err)
		}
		found := false
		for i, g := range got.Invites {
			if consumed[i] {
				continue
			}
			gotJSON, err := json.Marshal(g)
			if err != nil {
				t.Fatalf("%s: marshal invite: %v", label, err)
			}
			var gotVal any
			if err := json.Unmarshal(gotJSON, &gotVal); err != nil {
				t.Fatalf("%s: decode invite: %v", label, err)
			}
			if matchValue(wantVal, gotVal) {
				consumed[i] = true
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("%s: no stored invite matches %+v\n got %+v", label, w, got.Invites)
		}
	}
	return true
}

// identityFromWrappedHandler runs an accepted fixture case through the real
// middleware stack in front of a probe and returns the identity the wrapped
// handler read from its request context. The plain Verify comparison proves
// the verifier computes the identity; this proves the middleware injects that
// snapshot into the forwarded request (spec 02 section 3).
func identityFromWrappedHandler(t *testing.T, c spec.RequestCase, body []byte, st StateStore, now int64) (Identity, bool) {
	t.Helper()
	nonces := NewNonceStore()
	for _, n := range c.State.NonceCache {
		nonces.CheckAndRecord(n.Kid, n.Nonce, 0, n.RetainUntil)
	}
	v, err := NewVerifier(Config{
		Aud: c.State.Aud, State: st, Nonces: nonces,
		Native: NewNativeTools(NativeOptions{}),
		Window: int64(c.State.WindowSeconds), Now: func() int64 { return now },
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	var captured Identity
	var ok bool
	probe := func(w http.ResponseWriter, r *http.Request) {
		captured, ok = IdentityFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{}"))
	}
	h, err := NewHandler(HandlerConfig{Verifier: v, ServerKey: testPrivateKey(t, "svc")}, http.HandlerFunc(probe))
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	req := httptest.NewRequest(c.Request.Method, c.Request.Target, bytes.NewReader(body))
	for _, hd := range c.Request.Headers {
		req.Header.Add(hd.Name, hd.Value)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("wrapped-handler run: status = %d, body %s, want a forwarded accept", rec.Code, rec.Body.String())
	}
	return captured, ok
}

func inviteFromFixture(i spec.InviteRecord) InviteRecord {
	return InviteRecord{
		InviteID: i.InviteID, Admin: i.Admin != nil && *i.Admin, CreatedBy: i.CreatedBy,
		CreatedAt: i.CreatedAt, ExpiresAt: i.ExpiresAt, KeyTTLSeconds: i.KeyTTLSeconds,
	}
}

func signedVerifierRequest(t *testing.T, key ed25519.PrivateKey, aud, method, target string, ts int64, nonceByte byte, body []byte) Request {
	t.Helper()
	kid := jack.KeyID(key.Public().(ed25519.PublicKey))
	nonce := jack.EncodeBase64URL(bytes.Repeat([]byte{nonceByte}, 16))
	signing := jack.RequestSigningString(method, target, aud, kid, ts, nonce, body)
	sig := jack.EncodeBase64URL(ed25519.Sign(key, []byte(signing)))
	auth := jack.RequestAuth{Kid: kid, TS: ts, Nonce: nonce, Sig: sig}
	return Request{Method: method, Target: target, AuthValues: []string{jack.FormatRequestAuth(auth)}, Body: body}
}

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
