package state

import "testing"

// TestRetainedEditCannotCorrupt checks a *StateEdit retained past Update
// cannot affect committed state. Moved verbatim from the server package's
// state_test.go: it mutates the unexported StateEdit fields, which are only
// visible inside this package.
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
