package server

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/spec"
)

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
