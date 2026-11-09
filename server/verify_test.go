package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/spec"
)

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

func inviteFromFixture(i spec.InviteRecord) InviteRecord {
	return InviteRecord{
		InviteID: i.InviteID, Admin: i.Admin != nil && *i.Admin, CreatedBy: i.CreatedBy,
		CreatedAt: i.CreatedAt, ExpiresAt: i.ExpiresAt, KeyTTLSeconds: i.KeyTTLSeconds,
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
