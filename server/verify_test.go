package server

import (
	"strings"
	"testing"

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

// TestRequestVectors runs every single-request fixture case through the
// verifier. Cases that reach a protocol-native tool are skipped here: they
// need the native tool implementation and run in its own tests.
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

	ran := 0
	for _, c := range vectors.Cases {
		c := c
		t.Run(c.ID, func(t *testing.T) {
			body, err := c.Request.Body()
			if err != nil {
				t.Fatalf("Body: %v", err)
			}
			if msg, ok := classifyBody(body); ok && c.Expect.NonceRecorded && msg.hasTool && strings.HasPrefix(msg.tool, "jack.") {
				t.Skip("protocol-native tool: covered by the native implementation tests")
			}
			ran++

			policyFile, ok := vectors.Policies[c.State.Policy]
			if !ok {
				t.Fatalf("unknown policy %q", c.State.Policy)
			}
			policyData, err := spec.Fixture(policyFile)
			if err != nil {
				t.Fatalf("Fixture: %v", err)
			}
			policy, err := ParsePolicy(policyData)
			if err != nil {
				t.Fatalf("ParsePolicy: %v", err)
			}

			nonces := NewNonceStore()
			for _, n := range c.State.NonceCache {
				nonces.CheckAndRecord(n.Kid, n.Nonce, 0, n.RetainUntil)
			}
			now := c.State.Now
			v, err := NewVerifier(Config{
				Aud: c.State.Aud, State: registryFromFixture(t, registry), Nonces: nonces, Policy: policy,
				Window: int64(c.State.WindowSeconds), Now: func() int64 { return now },
			})
			if err != nil {
				t.Fatalf("NewVerifier: %v", err)
			}

			res := v.Verify(Request{
				Method: c.Request.Method, Target: c.Request.Target,
				AuthValues: jackAuthValues(c.Request.Headers), Body: body,
			})

			if (c.Expect.Result == "accept") != res.Accepted {
				t.Fatalf("Accepted = %v (%d %s), want result %q", res.Accepted, res.HTTPStatus, res.Code, c.Expect.Result)
			}
			if res.Accepted {
				if res.Kid != c.Expect.Kid {
					t.Fatalf("Kid = %q, want %q", res.Kid, c.Expect.Kid)
				}
			} else if res.HTTPStatus != c.Expect.HTTPStatus || res.Code != c.Expect.Code {
				t.Fatalf("rejection = %d %s, want %d %s", res.HTTPStatus, res.Code, c.Expect.HTTPStatus, c.Expect.Code)
			}
			if res.NonceRecorded != c.Expect.NonceRecorded {
				t.Fatalf("NonceRecorded = %v, want %v", res.NonceRecorded, c.Expect.NonceRecorded)
			}
		})
	}
	if ran == 0 {
		t.Fatal("every case was skipped")
	}
}
