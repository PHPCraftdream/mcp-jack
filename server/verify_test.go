package server

import (
	"encoding/json"
	"fmt"
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
			kind := KindHuman
			if entry.Kind != nil {
				kind = *entry.Kind
			}
			e.PutKey(RegistryEntry{
				Kid: entry.Kid, PublicKey: entry.PublicKey, Name: entry.Name, Kind: kind,
				Scopes: entry.Scopes, NotBefore: entry.NotBefore, NotAfter: entry.NotAfter,
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

// policyFiles maps the policy names used by the vectors to fixture files.
var policyFiles = map[string]string{"default": "policy.json", "wildcard": "policy-wildcard.json"}

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

// summarize mirrors the "after" expectation of the sequence vectors.
func summarize(st StateStore, now int64) spec.AfterState {
	view := st.View()
	keys := append([]RegistryEntry(nil), view.Keys...)
	sort.Slice(keys, func(i, j int) bool { return keys[i].Name < keys[j].Name })
	users := make([]spec.UserSummary, 0, len(keys))
	for _, k := range keys {
		scopes := make([]string, len(k.Scopes))
		copy(scopes, k.Scopes)
		sort.Strings(scopes)
		users = append(users, spec.UserSummary{
			Name: k.Name, Kid: k.Kid, Kind: kindOrHuman(k.Kind), Scopes: scopes,
			NotBefore: k.NotBefore, NotAfter: k.NotAfter,
		})
	}
	live := 0
	for _, i := range view.Invites {
		if now < i.ExpiresAt {
			live++
		}
	}
	return spec.AfterState{Users: users, Invites: live}
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
			policyFile, ok := vectors.Policies[c.State.Policy]
			if !ok {
				t.Fatalf("unknown policy %q", c.State.Policy)
			}
			nonces := NewNonceStore()
			for _, n := range c.State.NonceCache {
				nonces.CheckAndRecord(n.Kid, n.Nonce, 0, n.RetainUntil)
			}
			now := c.State.Now
			v, err := NewVerifier(Config{
				Aud: c.State.Aud, State: registryFromFixture(t, registry), Nonces: nonces,
				Policy: loadTestPolicy(t, policyFile), Native: NewNativeTools(NativeOptions{}),
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
		})
	}
}

func inviteFromFixture(i spec.InviteRecord) InviteRecord {
	kind := KindHuman
	if i.Kind != nil {
		kind = *i.Kind
	}
	return InviteRecord{
		InviteID: i.InviteID, Scopes: i.Scopes, Kind: kind, CreatedBy: i.CreatedBy,
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
				Aud: c.State.Aud, State: st, Nonces: nonces, Policy: loadTestPolicy(t, policyFiles[c.State.Policy]),
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
					if got := summarize(st, now); !reflect.DeepEqual(got, *step.Expect.After) {
						t.Fatalf("%s: state after the step\n got %+v\nwant %+v", label, got, *step.Expect.After)
					}
				}
			}
		})
	}
}
