package server

import (
	"bytes"
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
	if store == nil {
		t.Fatal("OpenFileState returned a nil store for a missing file")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state file exists immediately after open or stat failed unexpectedly: %v", err)
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

func TestFileStateRequiredCollections(t *testing.T) {
	members := []struct {
		name  string
		other string
	}{
		{name: "keys", other: "invites"},
		{name: "invites", other: "keys"},
	}
	malformed := []struct {
		name  string
		value string
	}{
		{name: "absent"},
		{name: "null", value: `null`},
		{name: "object", value: `{}`},
		{name: "string", value: `"bad"`},
		{name: "number", value: `1`},
		{name: "boolean", value: `true`},
	}
	for _, member := range members {
		t.Run(member.name, func(t *testing.T) {
			for _, value := range malformed {
				t.Run(value.name, func(t *testing.T) {
					doc := `{"version":1,"` + member.other + `":[]}`
					if value.value != "" {
						doc = `{"version":1,"` + member.name + `":` + value.value + `,"` + member.other + `":[]}`
					}
					fileTestLoadNamed(t, doc, member.name)
				})
			}
		})
	}
}

func TestFileStateExplicitEmptyCollectionsLoad(t *testing.T) {
	const doc = `{"version":1,"keys":[],"invites":[]}`
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	before := fileTestRead(t, path)
	store, err := OpenFileState(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if store == nil {
		t.Fatal("OpenFileState returned a nil store for explicit empty collections")
	}
	view := store.View()
	if len(view.Keys) != 0 || len(view.Invites) != 0 {
		t.Fatalf("store is not empty: %+v", view)
	}
	if after := fileTestRead(t, path); !bytes.Equal(before, after) {
		t.Fatal("loading explicit empty collections rewrote the state file")
	}
}

func TestFileStateEmptyUpdateWritesArrays(t *testing.T) {
	checkSerializedEmptyState := func(t *testing.T, path string) {
		t.Helper()
		var doc map[string]any
		if err := json.Unmarshal(fileTestRead(t, path), &doc); err != nil {
			t.Fatalf("unmarshal state file: %v", err)
		}
		if version, ok := doc["version"].(float64); !ok || version != 1 {
			t.Fatalf("version = %v, want 1", doc["version"])
		}
		for _, member := range []string{"keys", "invites"} {
			collection, ok := doc[member].([]any)
			if !ok || len(collection) != 0 {
				t.Fatalf("%s = %v, want an empty JSON array", member, doc[member])
			}
		}
		reopened, err := OpenFileState(path)
		if err != nil {
			t.Fatalf("reopen: %v", err)
		}
		if reopened == nil {
			t.Fatal("OpenFileState returned a nil store after empty update")
		}
		view := reopened.View()
		if len(view.Keys) != 0 || len(view.Invites) != 0 {
			t.Fatalf("reopened store is not empty: %+v", view)
		}
	}

	t.Run("opened store", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "state.json")
		store, err := OpenFileState(path)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		if err := store.Update(func(*StateEdit) error { return nil }); err != nil {
			t.Fatalf("no-op update: %v", err)
		}
		checkSerializedEmptyState(t, path)
	})
	t.Run("nil slices", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "state.json")
		store := FileState{path: path}
		if err := store.Update(func(*StateEdit) error { return nil }); err != nil {
			t.Fatalf("no-op update: %v", err)
		}
		checkSerializedEmptyState(t, path)
	})
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

// fileTestLoadNamed writes doc as the state file and asserts OpenFileState
// rejects it as corrupt, with member named in the error message and the raw
// file bytes untouched by the failed load (spec 03 section 10).
func fileTestLoadNamed(t *testing.T, doc, member string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read state file: %v", err)
	}
	store, err := OpenFileState(path)
	if store != nil {
		t.Fatal("OpenFileState returned a non-nil store for an invalid document")
	}
	if err == nil || !errors.Is(err, ErrStateCorrupt) {
		t.Fatalf("error = %v, want errors.Is(err, ErrStateCorrupt)", err)
	}
	if !strings.Contains(err.Error(), member) {
		t.Fatalf("error %q does not name %q", err.Error(), member)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read state file after failed load: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("the failed load rewrote the state file")
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
	t.Run("admin string", func(t *testing.T) {
		doc := fileTestDoc(stateTestKey("k1", "alice"))
		fileTestLoadNamed(t, strings.Replace(doc, `"admin":false`, `"admin":"true"`, 1), "admin")
	})
	t.Run("admin null", func(t *testing.T) {
		doc := fileTestDoc(stateTestKey("k1", "alice"))
		fileTestLoadNamed(t, strings.Replace(doc, `"admin":false`, `"admin":null`, 1), "admin")
	})
	t.Run("admin number", func(t *testing.T) {
		doc := fileTestDoc(stateTestKey("k1", "alice"))
		fileTestLoadNamed(t, strings.Replace(doc, `"admin":false`, `"admin":1`, 1), "admin")
	})
	t.Run("legacy kind", func(t *testing.T) {
		doc := fileTestDoc(stateTestKey("k1", "alice"))
		fileTestLoadNamed(t, strings.Replace(doc, `"name":"alice"`, `"name":"alice","kind":"human"`, 1), "kind")
	})
	t.Run("legacy scopes", func(t *testing.T) {
		doc := fileTestDoc(stateTestKey("k1", "alice"))
		fileTestLoadNamed(t, strings.Replace(doc, `"admin":false`, `"admin":false,"scopes":[]`, 1), "scopes")
	})
	t.Run("admin true loads", func(t *testing.T) {
		doc := fileTestDoc(stateTestKey("k1", "alice"))
		path := filepath.Join(t.TempDir(), "state.json")
		if err := os.WriteFile(path, []byte(strings.Replace(doc, `"admin":false`, `"admin":true`, 1)), 0o600); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		store, err := OpenFileState(path)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		if !store.View().Keys[0].Admin {
			t.Fatal("Keys[0].Admin = false, want true")
		}
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

// fileTestInviteDoc wraps one raw invite record and one key as a state doc.
func fileTestInviteDoc(invite string) string {
	entry := stateTestKey("k1", "alice")
	b, err := json.Marshal(entry)
	if err != nil {
		panic(err)
	}
	return `{"version":1,"keys":[` + string(b) + `],"invites":[` + invite + "]}"
}

// TestFileStateInviteValidation checks the strict invite-record rules of
// spec 03 section 3 on load.
func TestFileStateInviteValidation(t *testing.T) {
	t.Run("valid admin invite loads", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "state.json")
		if err := os.WriteFile(path, []byte(fileTestInviteDoc(`{"invite_id":"i1","admin":true,"created_by":"root","created_at":100,"expires_at":200}`)), 0o600); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		store, err := OpenFileState(path)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		inv := store.View().Invites[0]
		if inv.InviteID != "i1" || !inv.Admin {
			t.Fatalf("invite = %+v, want i1 admin", inv)
		}
	})
	t.Run("admin omitted loads as false", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "state.json")
		if err := os.WriteFile(path, []byte(fileTestInviteDoc(`{"invite_id":"i1","created_by":"root","created_at":100,"expires_at":200}`)), 0o600); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		store, err := OpenFileState(path)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		if store.View().Invites[0].Admin {
			t.Fatal("Admin = true, want false for an omitted admin")
		}
	})
	t.Run("admin string rejected", func(t *testing.T) {
		fileTestLoadNamed(t, fileTestInviteDoc(`{"invite_id":"i1","admin":"true","created_by":"root","created_at":100,"expires_at":200}`), "admin")
	})
	t.Run("admin null rejected", func(t *testing.T) {
		fileTestLoadNamed(t, fileTestInviteDoc(`{"invite_id":"i1","admin":null,"created_by":"root","created_at":100,"expires_at":200}`), "admin")
	})
	t.Run("empty invite id rejected", func(t *testing.T) {
		fileTestLoadNamed(t, fileTestInviteDoc(`{"invite_id":"","created_by":"root","created_at":100,"expires_at":200}`), "invite_id")
	})
	t.Run("empty created by rejected", func(t *testing.T) {
		fileTestLoadNamed(t, fileTestInviteDoc(`{"invite_id":"i1","created_by":"","created_at":100,"expires_at":200}`), "created_by")
	})
	t.Run("missing created by rejected", func(t *testing.T) {
		fileTestLoadNamed(t, fileTestInviteDoc(`{"invite_id":"i1","created_at":100,"expires_at":200}`), "created_by")
	})
	t.Run("created at null rejected", func(t *testing.T) {
		fileTestLoadNamed(t, fileTestInviteDoc(`{"invite_id":"i1","created_by":"root","created_at":null,"expires_at":200}`), "created_at")
	})
	t.Run("created at missing rejected", func(t *testing.T) {
		fileTestLoadNamed(t, fileTestInviteDoc(`{"invite_id":"i1","created_by":"root","expires_at":200}`), "created_at")
	})
	t.Run("created at string rejected", func(t *testing.T) {
		fileTestLoadNamed(t, fileTestInviteDoc(`{"invite_id":"i1","created_by":"root","created_at":"100","expires_at":200}`), "created_at")
	})
	t.Run("created at fractional rejected", func(t *testing.T) {
		fileTestLoadNamed(t, fileTestInviteDoc(`{"invite_id":"i1","created_by":"root","created_at":1.5,"expires_at":200}`), "created_at")
	})
	t.Run("created at exponent rejected", func(t *testing.T) {
		fileTestLoadNamed(t, fileTestInviteDoc(`{"invite_id":"i1","created_by":"root","created_at":1e3,"expires_at":200}`), "created_at")
	})
	t.Run("expires at null rejected", func(t *testing.T) {
		fileTestLoadNamed(t, fileTestInviteDoc(`{"invite_id":"i1","created_by":"root","created_at":100,"expires_at":null}`), "expires_at")
	})
	t.Run("expires at missing rejected", func(t *testing.T) {
		fileTestLoadNamed(t, fileTestInviteDoc(`{"invite_id":"i1","created_by":"root","created_at":100}`), "expires_at")
	})
	t.Run("created after expires rejected", func(t *testing.T) {
		fileTestLoadNamed(t, fileTestInviteDoc(`{"invite_id":"i1","created_by":"root","created_at":200,"expires_at":100}`), "created_at")
	})
	t.Run("negative created at rejected", func(t *testing.T) {
		fileTestLoadNamed(t, fileTestInviteDoc(`{"invite_id":"i1","created_by":"root","created_at":-1,"expires_at":200}`), "created_at")
	})
	t.Run("created at equals expires at loads", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "state.json")
		if err := os.WriteFile(path, []byte(fileTestInviteDoc(`{"invite_id":"i1","created_by":"root","created_at":200,"expires_at":200}`)), 0o600); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		store, err := OpenFileState(path)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		if len(store.View().Invites) != 1 {
			t.Fatal("invite with created_at == expires_at did not load")
		}
	})
	t.Run("key ttl null rejected", func(t *testing.T) {
		fileTestLoadNamed(t, fileTestInviteDoc(`{"invite_id":"i1","created_by":"root","created_at":100,"expires_at":200,"key_ttl_seconds":null}`), "key_ttl_seconds")
	})
	t.Run("key ttl zero rejected", func(t *testing.T) {
		fileTestLoadNamed(t, fileTestInviteDoc(`{"invite_id":"i1","created_by":"root","created_at":100,"expires_at":200,"key_ttl_seconds":0}`), "key_ttl_seconds")
	})
	t.Run("key ttl above maximum rejected", func(t *testing.T) {
		fileTestLoadNamed(t, fileTestInviteDoc(`{"invite_id":"i1","created_by":"root","created_at":100,"expires_at":200,"key_ttl_seconds":31536001}`), "key_ttl_seconds")
	})
	t.Run("key ttl one loads", func(t *testing.T) {
		fileTestInviteTTL(t, 1)
	})
	t.Run("key ttl maximum loads", func(t *testing.T) {
		fileTestInviteTTL(t, 31536000)
	})
	t.Run("key ttl absent loads as nil", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "state.json")
		if err := os.WriteFile(path, []byte(fileTestInviteDoc(`{"invite_id":"i1","created_by":"root","created_at":100,"expires_at":200}`)), 0o600); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		store, err := OpenFileState(path)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		if store.View().Invites[0].KeyTTLSeconds != nil {
			t.Fatalf("KeyTTLSeconds = %v, want nil", store.View().Invites[0].KeyTTLSeconds)
		}
	})
	t.Run("legacy kind rejected", func(t *testing.T) {
		fileTestLoadNamed(t, fileTestInviteDoc(`{"invite_id":"i1","kind":"human","created_by":"root","created_at":100,"expires_at":200}`), "kind")
	})
	t.Run("legacy scopes rejected", func(t *testing.T) {
		fileTestLoadNamed(t, fileTestInviteDoc(`{"invite_id":"i1","scopes":[],"created_by":"root","created_at":100,"expires_at":200}`), "scopes")
	})
}

// fileTestInviteTTL loads an invite with the given key ttl and checks it.
func fileTestInviteTTL(t *testing.T, ttl int64) {
	t.Helper()
	doc := fmt.Sprintf(`{"invite_id":"i1","created_by":"root","created_at":100,"expires_at":200,"key_ttl_seconds":%d}`, ttl)
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(fileTestInviteDoc(doc)), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	store, err := OpenFileState(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	got := store.View().Invites[0]
	if got.KeyTTLSeconds == nil || *got.KeyTTLSeconds != ttl {
		t.Fatalf("KeyTTLSeconds = %v, want %d", got.KeyTTLSeconds, ttl)
	}
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
			`{"kid":"k1","public_key":"pk","name":"alice","admin":false,"not_before":null,"not_after":null},` +
			`{"kid":"k1","public_key":"pk","name":"bob","admin":false,"not_before":null,"not_after":null}` +
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
