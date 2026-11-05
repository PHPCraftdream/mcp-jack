package server

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"sync"
	"testing"
)

// stateTestKey builds a registry entry with a real Ed25519 public key derived
// from id, and kid = base64url(SHA-256(public_key)), so state seeded with it
// passes the strict file-load validation (which includes the curve checks of
// spec 03 section 2). Keep ids unique within a test.
func stateTestKey(id, name string) RegistryEntry {
	seed := sha256.Sum256([]byte(id))
	pub := ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
	sum := sha256.Sum256(pub)
	return RegistryEntry{
		Kid:       base64.RawURLEncoding.EncodeToString(sum[:]),
		PublicKey: base64.RawURLEncoding.EncodeToString(pub),
		Name:      name,
		Kind:      KindHuman,
		Scopes:    []string{"read"},
	}
}

// stateTestIntPtr returns a pointer to v.
func stateTestIntPtr(v int64) *int64 { return &v }

// TestRegistryEntryAndInviteJSON pins the on-disk JSON shape of the records.
func TestRegistryEntryAndInviteJSON(t *testing.T) {
	t.Run("registry entry with nil pointers", func(t *testing.T) {
		entry := RegistryEntry{Kid: "k1", PublicKey: "pk", Name: "alice", Kind: KindHuman, Scopes: []string{"read"}}
		data, err := json.Marshal(entry)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		want := `{"kid":"k1","public_key":"pk","name":"alice","kind":"human","scopes":["read"],"not_before":null,"not_after":null}`
		if string(data) != want {
			t.Fatalf("got %s\nwant %s", data, want)
		}
	})

	t.Run("invite record with nil key ttl", func(t *testing.T) {
		inv := InviteRecord{
			InviteID:  "i1",
			Scopes:    []string{"read"},
			Kind:      "human",
			CreatedBy: "root",
			CreatedAt: 1767225500,
			ExpiresAt: 1767228600,
		}
		data, err := json.Marshal(inv)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		want := `{"invite_id":"i1","scopes":["read"],"kind":"human","created_by":"root","created_at":1767225500,"expires_at":1767228600,"key_ttl_seconds":null}`
		if string(data) != want {
			t.Fatalf("got %s\nwant %s", data, want)
		}
	})

	t.Run("set pointers marshal as numbers", func(t *testing.T) {
		nb := int64(1767225500)
		na := int64(1767229200)
		ttl := int64(3600)
		entry := RegistryEntry{Kid: "k1", PublicKey: "pk", Name: "alice", Kind: KindHuman, Scopes: []string{"read"}, NotBefore: &nb, NotAfter: &na}
		data, err := json.Marshal(entry)
		if err != nil {
			t.Fatalf("marshal entry: %v", err)
		}
		want := `{"kid":"k1","public_key":"pk","name":"alice","kind":"human","scopes":["read"],"not_before":1767225500,"not_after":1767229200}`
		if string(data) != want {
			t.Fatalf("got %s\nwant %s", data, want)
		}
		inv := InviteRecord{
			InviteID:      "i1",
			Scopes:        []string{"read"},
			Kind:          "human",
			CreatedBy:     "root",
			CreatedAt:     1767225500,
			ExpiresAt:     1767228600,
			KeyTTLSeconds: &ttl,
		}
		data, err = json.Marshal(inv)
		if err != nil {
			t.Fatalf("marshal invite: %v", err)
		}
		want = `{"invite_id":"i1","scopes":["read"],"kind":"human","created_by":"root","created_at":1767225500,"expires_at":1767228600,"key_ttl_seconds":3600}`
		if string(data) != want {
			t.Fatalf("got %s\nwant %s", data, want)
		}
	})

	t.Run("nil scopes normalized through PutKey", func(t *testing.T) {
		store := NewMemoryState()
		entry := stateTestKey("k1", "alice")
		entry.Scopes = nil
		if err := store.Update(func(e *StateEdit) error { e.PutKey(entry); return nil }); err != nil {
			t.Fatalf("update: %v", err)
		}
		got := store.View().Keys[0]
		if got.Scopes == nil {
			t.Fatal("Scopes is nil, want non-nil empty slice")
		}
		if len(got.Scopes) != 0 {
			t.Fatalf("Scopes = %v, want empty", got.Scopes)
		}
		data, _ := json.Marshal(got.Scopes)
		if string(data) != "[]" {
			t.Fatalf("Scopes marshaled as %s, want []", data)
		}
	})
}

// TestStateEditBasics covers put/get/remove, ordering and getter deep copies.
func TestStateEditBasics(t *testing.T) {
	t.Run("put and get by kid and by name", func(t *testing.T) {
		store := NewMemoryState()
		k := stateTestKey("k1", "alice")
		if err := store.Update(func(e *StateEdit) error {
			e.PutKey(k)
			return nil
		}); err != nil {
			t.Fatalf("update: %v", err)
		}
		if err := store.Update(func(e *StateEdit) error {
			got, ok := e.Key(k.Kid)
			if !ok || got.Name != "alice" {
				t.Fatalf("Key(kid) = %v, %v", got, ok)
			}
			got, ok = e.KeyByName("alice")
			if !ok || got.Kid != k.Kid {
				t.Fatalf("KeyByName(alice) = %v, %v", got, ok)
			}
			if _, ok := e.Key("missing"); ok {
				t.Fatal("Key(missing) reported present")
			}
			if _, ok := e.KeyByName("nobody"); ok {
				t.Fatal("KeyByName(nobody) reported present")
			}
			return nil
		}); err != nil {
			t.Fatalf("update: %v", err)
		}
	})

	t.Run("putkey replaces on same kid", func(t *testing.T) {
		store := NewMemoryState()
		entry := stateTestKey("k1", "alice")
		replaced := entry
		replaced.Name = "alice2"
		replaced.Scopes = []string{"read", "write"}
		if err := store.Update(func(e *StateEdit) error {
			e.PutKey(entry)
			e.PutKey(replaced)
			return nil
		}); err != nil {
			t.Fatalf("update: %v", err)
		}
		view := store.View()
		if len(view.Keys) != 1 {
			t.Fatalf("len(keys) = %d, want 1", len(view.Keys))
		}
		if view.Keys[0].Name != "alice2" || len(view.Keys[0].Scopes) != 2 {
			t.Fatalf("entry not replaced: %+v", view.Keys[0])
		}
	})

	t.Run("remove returns false when absent", func(t *testing.T) {
		store := NewMemoryState()
		err := store.Update(func(e *StateEdit) error {
			if e.RemoveKey("ghost") {
				t.Error("RemoveKey(ghost) returned true")
			}
			if e.RemoveInvite("ghost-invite") {
				t.Error("RemoveInvite(ghost-invite) returned true")
			}
			return nil
		})
		if err != nil {
			t.Fatalf("update: %v", err)
		}
	})

	t.Run("keys sorted by kid, invites sorted by invite id", func(t *testing.T) {
		store := NewMemoryState()
		kz := stateTestKey("zz", "zoe")
		ka := stateTestKey("aa", "ann")
		km := stateTestKey("mm", "mel")
		if err := store.Update(func(e *StateEdit) error {
			e.PutKey(kz)
			e.PutKey(ka)
			e.PutKey(km)
			e.PutInvite(InviteRecord{InviteID: "i9", CreatedBy: "root"})
			e.PutInvite(InviteRecord{InviteID: "i2", CreatedBy: "root"})
			e.PutInvite(InviteRecord{InviteID: "i5", CreatedBy: "root"})
			return nil
		}); err != nil {
			t.Fatalf("update: %v", err)
		}
		want := []string{ka.Kid, km.Kid, kz.Kid}
		sort.Strings(want)
		if err := store.Update(func(e *StateEdit) error {
			keys := e.Keys()
			for i, k := range keys {
				if k.Kid != want[i] {
					t.Errorf("keys[%d].Kid = %s, want %s", i, k.Kid, want[i])
				}
			}
			invites := e.Invites()
			wantIDs := []string{"i2", "i5", "i9"}
			for i, inv := range invites {
				if inv.InviteID != wantIDs[i] {
					t.Errorf("invites[%d].InviteID = %s, want %s", i, inv.InviteID, wantIDs[i])
				}
			}
			return nil
		}); err != nil {
			t.Fatalf("update: %v", err)
		}
	})

	t.Run("edit getters are deep copies", func(t *testing.T) {
		store := NewMemoryState()
		k := stateTestKey("k1", "alice")
		if err := store.Update(func(e *StateEdit) error {
			e.PutKey(k)
			return nil
		}); err != nil {
			t.Fatalf("update: %v", err)
		}
		// Mutate a getter-returned entry's Scopes inside another update.
		if err := store.Update(func(e *StateEdit) error {
			got, ok := e.Key(k.Kid)
			if !ok {
				t.Fatal("Key(kid) not found")
			}
			got.Scopes[0] = "MUTATED"
			got.Name = "MUTATED"
			return nil
		}); err != nil {
			t.Fatalf("update: %v", err)
		}
		view := store.View()
		if view.Keys[0].Name != "alice" {
			t.Fatalf("Name = %s, want alice", view.Keys[0].Name)
		}
		if view.Keys[0].Scopes[0] != "read" {
			t.Fatalf("Scopes[0] = %s, want read", view.Keys[0].Scopes[0])
		}
	})
}

// TestEnrollFlow checks one atomic update consumes an invite and adds a key.
func TestEnrollFlow(t *testing.T) {
	store := NewMemoryState()
	if err := store.Update(func(e *StateEdit) error {
		e.PutInvite(InviteRecord{InviteID: "i1", Scopes: []string{"read"}, CreatedBy: "root"})
		e.PutKey(stateTestKey("admin", "root"))
		return nil
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	enrolled := stateTestKey("k-new", "bob")
	if err := store.Update(func(e *StateEdit) error {
		inv, ok := e.Invite("i1")
		if !ok {
			return errors.New("invite missing")
		}
		e.RemoveInvite("i1")
		entry := enrolled
		entry.Scopes = inv.Scopes
		e.PutKey(entry)
		return nil
	}); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	view := store.View()
	if len(view.Keys) != 2 {
		t.Fatalf("len(keys) = %d, want 2", len(view.Keys))
	}
	found := false
	for _, k := range view.Keys {
		if k.Kid == enrolled.Kid {
			found = true
		}
	}
	if !found {
		t.Fatal("enrolled key missing from view")
	}
	if len(view.Invites) != 0 {
		t.Fatalf("len(invites) = %d, want 0", len(view.Invites))
	}
}

// TestRollbackOnError checks failed updates leave state untouched, in memory
// and on disk.
func TestRollbackOnError(t *testing.T) {
	boom := errors.New("boom")

	t.Run("memory state", func(t *testing.T) {
		store := NewMemoryState()
		if err := store.Update(func(e *StateEdit) error {
			e.PutKey(stateTestKey("k1", "alice"))
			e.PutInvite(InviteRecord{InviteID: "i1", CreatedBy: "root"})
			return nil
		}); err != nil {
			t.Fatalf("seed: %v", err)
		}
		before := store.View()
		got := store.Update(func(e *StateEdit) error {
			e.PutKey(stateTestKey("k2", "mallory"))
			e.RemoveInvite("i1")
			return boom
		})
		if got != boom {
			t.Fatalf("Update error = %v, want %v", got, boom)
		}
		after := store.View()
		if fmt.Sprint(after) != fmt.Sprint(before) {
			t.Fatalf("state changed after rollback:\nbefore %+v\nafter  %+v", before, after)
		}
	})

	t.Run("file state rolls back memory and disk", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "state.json")
		store, err := OpenFileState(path)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		if err := store.Update(func(e *StateEdit) error {
			e.PutKey(stateTestKey("k1", "alice"))
			e.PutInvite(InviteRecord{InviteID: "i1", CreatedBy: "root"})
			return nil
		}); err != nil {
			t.Fatalf("seed: %v", err)
		}
		beforeBytes := fileTestRead(t, path)
		before := store.View()
		got := store.Update(func(e *StateEdit) error {
			e.PutKey(stateTestKey("k2", "mallory"))
			e.RemoveInvite("i1")
			return boom
		})
		if got != boom {
			t.Fatalf("Update error = %v, want %v", got, boom)
		}
		after := store.View()
		if fmt.Sprint(after) != fmt.Sprint(before) {
			t.Fatalf("memory state changed after rollback")
		}
		if string(fileTestRead(t, path)) != string(beforeBytes) {
			t.Fatal("file bytes changed after rollback")
		}
	})
}

// TestViewIsCopy checks mutations of a returned view never reach the store.
func TestViewIsCopy(t *testing.T) {
	store := NewMemoryState()
	if err := store.Update(func(e *StateEdit) error {
		e.PutKey(stateTestKey("k1", "alice"))
		return nil
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	view := store.View()
	view.Keys[0].Name = "MUTATED"
	view.Keys[0].Scopes[0] = "MUTATED"
	view.Keys = append(view.Keys, stateTestKey("k2", "mallory"))
	view.Invites = append(view.Invites, InviteRecord{InviteID: "i1"})

	after := store.View()
	if len(after.Keys) != 1 {
		t.Fatalf("len(keys) = %d, want 1", len(after.Keys))
	}
	if after.Keys[0].Name != "alice" || after.Keys[0].Scopes[0] != "read" {
		t.Fatalf("store entry mutated: %+v", after.Keys[0])
	}
	if len(after.Invites) != 0 {
		t.Fatalf("len(invites) = %d, want 0", len(after.Invites))
	}
}

// TestStateConcurrency exercises concurrent updates under -race.
func TestStateConcurrency(t *testing.T) {
	t.Run("successful and failing updates interleave", func(t *testing.T) {
		store := NewMemoryState()
		const writers = 32
		var wg sync.WaitGroup
		errCh := make(chan error, writers*2)
		for i := 0; i < writers; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				errCh <- store.Update(func(e *StateEdit) error {
					e.PutKey(stateTestKey(fmt.Sprintf("k-%d", idx), fmt.Sprintf("user-%d", idx)))
					return nil
				})
			}(i)
			wg.Add(1)
			go func() {
				defer wg.Done()
				errCh <- store.Update(func(e *StateEdit) error {
					return errors.New("boom")
				})
			}()
		}
		wg.Wait()
		close(errCh)
		failures := 0
		for err := range errCh {
			if err != nil {
				failures++
			}
		}
		if failures != writers {
			t.Fatalf("got %d failures, want %d", failures, writers)
		}
		view := store.View()
		if len(view.Keys) != writers {
			t.Fatalf("len(keys) = %d, want %d", len(view.Keys), writers)
		}
	})

	t.Run("serialized toggles keep parity", func(t *testing.T) {
		store := NewMemoryState()
		const togglers = 16
		shared := stateTestKey("shared", "shared")
		var wg sync.WaitGroup
		for i := 0; i < togglers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				store.Update(func(e *StateEdit) error {
					if _, ok := e.Key(shared.Kid); ok {
						e.RemoveKey(shared.Kid)
					} else {
						e.PutKey(shared)
					}
					return nil
				})
			}()
		}
		wg.Wait()
		view := store.View()
		// 16 sequential toggles from absent ends absent; a lost update
		// breaks the parity.
		if len(view.Keys) != 0 {
			t.Fatalf("len(keys) = %d, want 0 (toggles lost parity)", len(view.Keys))
		}
	})
}

// TestViewPointeeIsolation checks the view deep-copies timestamp pointees.
func TestViewPointeeIsolation(t *testing.T) {
	store := NewMemoryState()
	entry := stateTestKey("k1", "alice")
	entry.NotAfter = stateTestIntPtr(123)
	if err := store.Update(func(e *StateEdit) error { e.PutKey(entry); return nil }); err != nil {
		t.Fatalf("update: %v", err)
	}
	view := store.View()
	if view.Keys[0].NotAfter == nil || *view.Keys[0].NotAfter != 123 {
		t.Fatalf("NotAfter = %v, want 123", view.Keys[0].NotAfter)
	}
	*view.Keys[0].NotAfter = 999
	fresh := store.View()
	if fresh.Keys[0].NotAfter == nil || *fresh.Keys[0].NotAfter != 123 {
		t.Fatalf("fresh View NotAfter = %v, want 123", fresh.Keys[0].NotAfter)
	}
}

// TestPutKeyInputIsolation checks PutKey clones the caller's slices and
// pointees at commit time.
func TestPutKeyInputIsolation(t *testing.T) {
	t.Run("putkey", func(t *testing.T) {
		store := NewMemoryState()
		entry := stateTestKey("k1", "alice")
		entry.Scopes = []string{"read"}
		entry.NotBefore = stateTestIntPtr(5)
		if err := store.Update(func(e *StateEdit) error { e.PutKey(entry); return nil }); err != nil {
			t.Fatalf("update: %v", err)
		}
		entry.Scopes[0] = "admin"
		entry.Scopes = append(entry.Scopes, "extra")
		*entry.NotBefore = 0
		got := store.View().Keys[0]
		if len(got.Scopes) != 1 || got.Scopes[0] != "read" {
			t.Fatalf("Scopes = %v, want [read]", got.Scopes)
		}
		if got.NotBefore == nil || *got.NotBefore != 5 {
			t.Fatalf("NotBefore = %v, want 5", got.NotBefore)
		}
	})

	t.Run("putinvite", func(t *testing.T) {
		store := NewMemoryState()
		inv := InviteRecord{InviteID: "i1", Scopes: []string{"read"}, CreatedBy: "root", KeyTTLSeconds: stateTestIntPtr(3600)}
		if err := store.Update(func(e *StateEdit) error { e.PutInvite(inv); return nil }); err != nil {
			t.Fatalf("update: %v", err)
		}
		inv.Scopes[0] = "admin"
		inv.Scopes = append(inv.Scopes, "extra")
		*inv.KeyTTLSeconds = 0
		got := store.View().Invites[0]
		if len(got.Scopes) != 1 || got.Scopes[0] != "read" {
			t.Fatalf("Scopes = %v, want [read]", got.Scopes)
		}
		if got.KeyTTLSeconds == nil || *got.KeyTTLSeconds != 3600 {
			t.Fatalf("KeyTTLSeconds = %v, want 3600", got.KeyTTLSeconds)
		}
	})
}

// TestRollbackSharedPointee checks rollback discards edits even when the
// caller keeps mutating the pointees it handed in.
func TestRollbackSharedPointee(t *testing.T) {
	t.Run("failed update discards edit", func(t *testing.T) {
		store := NewMemoryState()
		p := stateTestIntPtr(7)
		entry := stateTestKey("k1", "alice")
		entry.NotBefore = p
		boom := errors.New("boom")
		got := store.Update(func(e *StateEdit) error {
			e.PutKey(entry)
			return boom
		})
		if got != boom {
			t.Fatalf("Update error = %v, want %v", got, boom)
		}
		if view := store.View(); len(view.Keys) != 0 {
			t.Fatalf("len(keys) = %d, want 0", len(view.Keys))
		}
		if *p != 7 {
			t.Fatalf("*p = %d, want 7", *p)
		}
	})

	t.Run("caller mutation after commit does not leak", func(t *testing.T) {
		store := NewMemoryState()
		p := stateTestIntPtr(7)
		entry := stateTestKey("k1", "alice")
		entry.NotBefore = p
		if err := store.Update(func(e *StateEdit) error {
			e.PutKey(entry)
			*p = 999
			return nil
		}); err != nil {
			t.Fatalf("update: %v", err)
		}
		view := store.View()
		if view.Keys[0].NotBefore == nil || *view.Keys[0].NotBefore != 7 {
			t.Fatalf("NotBefore = %v, want 7", view.Keys[0].NotBefore)
		}
	})
}

// TestRetainedEditCannotCorrupt checks a *StateEdit retained past Update
// cannot affect committed state.
func TestRetainedEditCannotCorrupt(t *testing.T) {
	store := NewMemoryState()
	var kept *StateEdit
	if err := store.Update(func(e *StateEdit) error {
		e.PutKey(stateTestKey("k1", "alice"))
		kept = e
		return nil
	}); err != nil {
		t.Fatalf("update: %v", err)
	}
	kept.keys[0].Name = "hacked"
	kept.keys = append(kept.keys, stateTestKey("k2", "mallory"))

	view := store.View()
	if len(view.Keys) != 1 {
		t.Fatalf("len(keys) = %d, want 1", len(view.Keys))
	}
	if view.Keys[0].Name != "alice" {
		t.Fatalf("Name = %s, want alice", view.Keys[0].Name)
	}
}
