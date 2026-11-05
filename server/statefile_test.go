package server

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// fileTestRead reads a file, failing the test on error. Defined once for the
// package (also used by state_test.go).
func fileTestRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

// fileTestCorrupt opens a corrupt file and asserts the contract.
func fileTestCorrupt(t *testing.T, dir, name, content string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	store, err := OpenFileState(path)
	if store != nil {
		t.Fatalf("OpenFileState returned non-nil store for %s", name)
	}
	if err == nil || !errors.Is(err, ErrStateCorrupt) {
		t.Fatalf("error = %v, want errors.Is(err, ErrStateCorrupt)", err)
	}
	if !strings.Contains(err.Error(), name) {
		t.Fatalf("error %q does not mention file name %q", err.Error(), name)
	}
}

// TestFileStateMissingFileStartsEmpty checks a missing file yields an empty
// store and the first update creates the file with the expected document.
func TestFileStateMissingFileStartsEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	store, err := OpenFileState(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	view := store.View()
	if len(view.Keys) != 0 || len(view.Invites) != 0 {
		t.Fatalf("fresh store not empty: %+v", view)
	}
	if err := store.Update(func(e *StateEdit) error {
		e.PutKey(stateTestKey("k1", "alice"))
		e.PutInvite(InviteRecord{InviteID: "i1", CreatedBy: "root"})
		return nil
	}); err != nil {
		t.Fatalf("update: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(fileTestRead(t, path), &doc); err != nil {
		t.Fatalf("unmarshal state file: %v", err)
	}
	if v, ok := doc["version"].(float64); !ok || v != 1 {
		t.Fatalf("version = %v, want 1", doc["version"])
	}
	keys, ok := doc["keys"].([]any)
	if !ok || len(keys) != 1 {
		t.Fatalf("keys = %v, want one entry", doc["keys"])
	}
	invites, ok := doc["invites"].([]any)
	if !ok || len(invites) != 1 {
		t.Fatalf("invites = %v, want one entry", doc["invites"])
	}
}

// TestFileStateRoundTrip checks reopening preserves state and the file is
// sorted, indented JSON with a trailing newline.
func TestFileStateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	store, err := OpenFileState(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// Deliberately insert out of sort order.
	kzz := stateTestKey("zz", "zoe")
	kaa := stateTestKey("aa", "ann")
	if err := store.Update(func(e *StateEdit) error {
		e.PutKey(kzz)
		e.PutKey(kaa)
		e.PutInvite(InviteRecord{InviteID: "i9", CreatedBy: "root"})
		e.PutInvite(InviteRecord{InviteID: "i2", CreatedBy: "root"})
		return nil
	}); err != nil {
		t.Fatalf("update: %v", err)
	}
	want := store.View()

	reopened, err := OpenFileState(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	got := reopened.View()
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("round trip mismatch:\nwant %+v\ngot  %+v", want, got)
	}

	data := string(fileTestRead(t, path))
	if !strings.HasSuffix(data, "\n") {
		t.Fatal("file does not end with newline")
	}
	if !strings.Contains(data, "\n  \"") {
		t.Fatal("file is not indented JSON")
	}
	// Kids are hashes, so derive the expected order from the actual values.
	firstKey, secondKey := kzz, kaa
	if kaa.Kid < kzz.Kid {
		firstKey, secondKey = kaa, kzz
	}
	firstIdx := strings.Index(data, "\"kid\": \""+firstKey.Kid+"\"")
	secondIdx := strings.Index(data, "\"kid\": \""+secondKey.Kid+"\"")
	if firstIdx == -1 || secondIdx == -1 || firstIdx > secondIdx {
		t.Fatal("keys in file are not sorted by kid")
	}
	i9Idx := strings.Index(data, "\"invite_id\": \"i9\"")
	i2Idx := strings.Index(data, "\"invite_id\": \"i2\"")
	if i9Idx == -1 || i2Idx == -1 || i2Idx > i9Idx {
		t.Fatal("invites in file are not sorted by invite id")
	}
}

// fileTestLoad writes doc as the state file and asserts OpenFileState rejects
// it as corrupt.
func fileTestLoad(t *testing.T, doc string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	store, err := OpenFileState(path)
	if store != nil {
		t.Fatal("OpenFileState returned a non-nil store for an invalid document")
	}
	if err == nil || !errors.Is(err, ErrStateCorrupt) {
		t.Fatalf("error = %v, want errors.Is(err, ErrStateCorrupt)", err)
	}
}

// fileTestDoc wraps marshaled key entries as a full state document.
func fileTestDoc(entries ...RegistryEntry) string {
	parts := make([]string, len(entries))
	for i, e := range entries {
		b, err := json.Marshal(e)
		if err != nil {
			panic(err)
		}
		parts[i] = string(b)
	}
	return `{"version":1,"keys":[` + strings.Join(parts, ",") + `],"invites":[]}`
}

// TestFileStateLoadValidation checks decodeState runs validateKeys on load:
// a valid document loads, every invalid entry is rejected as corrupt.
func TestFileStateLoadValidation(t *testing.T) {
	t.Run("valid document loads", func(t *testing.T) {
		entry := stateTestKey("k1", "alice")
		path := filepath.Join(t.TempDir(), "state.json")
		if err := os.WriteFile(path, []byte(fileTestDoc(entry)), 0o600); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		store, err := OpenFileState(path)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		view := store.View()
		if len(view.Keys) != 1 || view.Keys[0].Kid != entry.Kid {
			t.Fatalf("view keys = %+v, want exactly %s", view.Keys, entry.Kid)
		}
	})
	t.Run("kid mismatch", func(t *testing.T) {
		entry := stateTestKey("k1", "alice")
		doc := fileTestDoc(entry)
		fileTestLoad(t, strings.ReplaceAll(doc, entry.Kid, stateTestKey("other", "x").Kid))
	})
	t.Run("public key wrong length", func(t *testing.T) {
		entry := stateTestKey("k1", "alice")
		doc := fileTestDoc(entry)
		fileTestLoad(t, strings.ReplaceAll(doc, entry.PublicKey, base64.RawURLEncoding.EncodeToString(make([]byte, 16))))
	})
	t.Run("invalid name with space", func(t *testing.T) {
		entry := stateTestKey("k1", "alice")
		entry.Name = "bad name!"
		fileTestLoad(t, fileTestDoc(entry))
	})
	t.Run("name too long", func(t *testing.T) {
		entry := stateTestKey("k1", "alice")
		entry.Name = strings.Repeat("a", 65)
		fileTestLoad(t, fileTestDoc(entry))
	})
	t.Run("duplicate name", func(t *testing.T) {
		fileTestLoad(t, fileTestDoc(stateTestKey("k1", "same"), stateTestKey("k2", "same")))
	})
	t.Run("invalid kind", func(t *testing.T) {
		entry := stateTestKey("k1", "alice")
		entry.Kind = "robot"
		fileTestLoad(t, fileTestDoc(entry))
	})
	t.Run("invalid scope uppercase", func(t *testing.T) {
		entry := stateTestKey("k1", "alice")
		entry.Scopes = []string{"Read"}
		fileTestLoad(t, fileTestDoc(entry))
	})
	t.Run("invalid scope empty segment", func(t *testing.T) {
		entry := stateTestKey("k1", "alice")
		entry.Scopes = []string{"a::b"}
		fileTestLoad(t, fileTestDoc(entry))
	})
	t.Run("duplicate scopes", func(t *testing.T) {
		entry := stateTestKey("k1", "alice")
		entry.Scopes = []string{"read", "read"}
		fileTestLoad(t, fileTestDoc(entry))
	})
	t.Run("identity public key with a matching kid", func(t *testing.T) {
		entry := stateTestKey("k1", "alice")
		identity := make([]byte, 32)
		identity[0] = 1 // the encoding of the neutral point
		sum := sha256.Sum256(identity)
		entry.PublicKey = base64.RawURLEncoding.EncodeToString(identity)
		entry.Kid = base64.RawURLEncoding.EncodeToString(sum[:])
		fileTestLoad(t, fileTestDoc(entry))
	})
	t.Run("scopes missing", func(t *testing.T) {
		doc := fileTestDoc(stateTestKey("k1", "alice"))
		fileTestLoad(t, strings.Replace(doc, `"scopes":["read"],`, "", 1))
	})
	t.Run("scopes null", func(t *testing.T) {
		doc := fileTestDoc(stateTestKey("k1", "alice"))
		fileTestLoad(t, strings.Replace(doc, `"scopes":["read"]`, `"scopes":null`, 1))
	})
	t.Run("agent with admin", func(t *testing.T) {
		entry := stateTestKey("k1", "alice")
		entry.Kind = KindAgent
		entry.Scopes = []string{"admin"}
		fileTestLoad(t, fileTestDoc(entry))
	})
	t.Run("negative not before", func(t *testing.T) {
		entry := stateTestKey("k1", "alice")
		entry.NotBefore = stateTestIntPtr(-1)
		fileTestLoad(t, fileTestDoc(entry))
	})
	t.Run("not before not before not after", func(t *testing.T) {
		entry := stateTestKey("k1", "alice")
		entry.NotBefore = stateTestIntPtr(10)
		entry.NotAfter = stateTestIntPtr(10)
		fileTestLoad(t, fileTestDoc(entry))
	})
}

// TestFileStateCorrupt covers every strict-decode rejection case.
func TestFileStateCorrupt(t *testing.T) {
	t.Run("not json", func(t *testing.T) {
		fileTestCorrupt(t, t.TempDir(), "state.json", "not json at all")
	})
	t.Run("empty file", func(t *testing.T) {
		fileTestCorrupt(t, t.TempDir(), "state.json", "")
	})
	t.Run("unknown field", func(t *testing.T) {
		fileTestCorrupt(t, t.TempDir(), "state.json", `{"version":1,"keys":[],"invites":[],"extra":1}`)
	})
	t.Run("wrong version", func(t *testing.T) {
		fileTestCorrupt(t, t.TempDir(), "state.json", `{"version":2,"keys":[],"invites":[]}`)
	})
	t.Run("duplicate kid", func(t *testing.T) {
		doc := `{"version":1,"keys":[` +
			`{"kid":"k1","public_key":"pk","name":"alice","kind":"human","scopes":[],"not_before":null,"not_after":null},` +
			`{"kid":"k1","public_key":"pk","name":"bob","kind":"human","scopes":[],"not_before":null,"not_after":null}` +
			`],"invites":[]}`
		fileTestCorrupt(t, t.TempDir(), "state.json", doc)
	})
	t.Run("wrong shape", func(t *testing.T) {
		fileTestCorrupt(t, t.TempDir(), "state.json", `[]`)
	})
}

// TestFileStateFailedUpdateLeavesNoTrace checks a failed update leaves file,
// memory and directory untouched.
func TestFileStateFailedUpdateLeavesNoTrace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	store, err := OpenFileState(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := store.Update(func(e *StateEdit) error {
		e.PutKey(stateTestKey("k1", "alice"))
		return nil
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	beforeBytes := string(fileTestRead(t, path))
	before := store.View()

	boom := errors.New("boom")
	got := store.Update(func(e *StateEdit) error {
		e.PutKey(stateTestKey("k2", "mallory"))
		return boom
	})
	if got != boom {
		t.Fatalf("Update error = %v, want %v", got, boom)
	}
	if string(fileTestRead(t, path)) != beforeBytes {
		t.Fatal("file bytes changed after failed update")
	}
	if fmt.Sprint(store.View()) != fmt.Sprint(before) {
		t.Fatal("memory view changed after failed update")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "state.json" {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Fatalf("directory contains %v, want only state.json", names)
	}
}

// TestFileStateSuccessfulUpdateClean checks no temp files survive a write.
func TestFileStateSuccessfulUpdateClean(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	store, err := OpenFileState(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := store.Update(func(e *StateEdit) error {
		e.PutKey(stateTestKey("k1", "alice"))
		return nil
	}); err != nil {
		t.Fatalf("update: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 1 {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Fatalf("directory contains %v, want only the state file", names)
	}
	if strings.HasPrefix(entries[0].Name(), ".mcp-jack-state-") {
		t.Fatalf("temp file %s left behind", entries[0].Name())
	}
}

// TestFileStateConcurrentUpdates checks concurrent writes all land on disk.
func TestFileStateConcurrentUpdates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	store, err := OpenFileState(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	const writers = 16
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			store.Update(func(e *StateEdit) error {
				e.PutKey(stateTestKey(fmt.Sprintf("k-%02d", idx), fmt.Sprintf("user-%d", idx)))
				return nil
			})
		}(i)
	}
	wg.Wait()

	reopened, err := OpenFileState(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if got := len(reopened.View().Keys); got != writers {
		t.Fatalf("keys on disk = %d, want %d", got, writers)
	}
}
