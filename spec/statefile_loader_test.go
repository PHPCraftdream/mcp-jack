package spec_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/server"
	"github.com/PHPCraftdream/mcp-jack/spec"
)

// TestLoadVectorsRegistriesThroughFileState feeds EVERY registries case of
// load-vectors.json through the FileState loader (mirror of the Rust test
// rust/tests/state_file.rs load_vectors_registries_through_file_state).
// Adaptation: a registry document {version, aud, keys} becomes the state
// document {"version":...,"keys":[...],"invites":[]} — aud is dropped
// because the on-disk state format has no aud field; every other top-level
// field and entry field is copied verbatim, so each case's rejection
// property (unknown fields, bad kinds, duplicate ids, ...) survives the
// adaptation.
func TestLoadVectorsRegistriesThroughFileState(t *testing.T) {
	vectors, err := spec.LoadLoadVectors()
	if err != nil {
		t.Fatalf("spec.LoadLoadVectors: %v", err)
	}
	if len(vectors.Registries) == 0 {
		t.Fatalf("LoadLoadVectors: no registry cases")
	}

	for _, tc := range vectors.Registries {
		t.Run(tc.ID, func(t *testing.T) {
			var doc map[string]json.RawMessage
			if err := json.Unmarshal(tc.Document, &doc); err != nil {
				t.Fatalf("case %s: document does not decode: %v", tc.ID, err)
			}
			delete(doc, "aud") // see the adaptation note above
			doc["invites"] = json.RawMessage("[]")
			data, err := json.Marshal(doc)
			if err != nil {
				t.Fatalf("marshal adapted document: %v", err)
			}
			path := filepath.Join(t.TempDir(), "state.json")
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatalf("write state file: %v", err)
			}

			switch tc.Expect {
			case "valid":
				store, err := server.OpenFileState(path)
				if err != nil {
					t.Fatalf("case %s: OpenFileState: %v", tc.ID, err)
				}
				var keys []map[string]any
				if err := json.Unmarshal(doc["keys"], &keys); err != nil {
					t.Fatalf("case %s: keys member: %v", tc.ID, err)
				}
				loaded := store.View().Keys
				if len(loaded) != len(keys) {
					t.Fatalf("case %s: loaded %d keys, want %d: a valid registry must load completely", tc.ID, len(loaded), len(keys))
				}
				// An omitted or null kind must come out as human (spec 02 section 1).
				for i, k := range keys {
					if kind, present := k["kind"]; (!present || kind == nil) && loaded[i].Kind != server.KindHuman {
						t.Fatalf("case %s: key %d has no kind but loaded as %q, want human", tc.ID, i, loaded[i].Kind)
					}
				}
			case "invalid":
				if _, err := server.OpenFileState(path); err == nil {
					t.Fatalf("case %s: OpenFileState accepted an invalid registry", tc.ID)
				} else if !errors.Is(err, server.ErrStateCorrupt) {
					t.Fatalf("case %s: err = %v, want ErrStateCorrupt", tc.ID, err)
				}
			default:
				t.Fatalf("case %s: unknown expect %q", tc.ID, tc.Expect)
			}
		})
	}
}

// TestFileStateRejectsEmptyKind: only an omitted or null kind defaults to
// human; an explicit empty string is an invalid kind and must be rejected.
func TestFileStateRejectsEmptyKind(t *testing.T) {
	vectors, err := spec.LoadLoadVectors()
	if err != nil {
		t.Fatalf("spec.LoadLoadVectors: %v", err)
	}
	for _, tc := range vectors.Registries {
		if tc.ID != "valid-kind-omitted" {
			continue
		}
		var doc map[string]json.RawMessage
		if err := json.Unmarshal(tc.Document, &doc); err != nil {
			t.Fatalf("document does not decode: %v", err)
		}
		delete(doc, "aud")
		doc["invites"] = json.RawMessage("[]")
		var keys []map[string]any
		if err := json.Unmarshal(doc["keys"], &keys); err != nil || len(keys) == 0 {
			t.Fatalf("keys member: %v (%d keys)", err, len(keys))
		}
		keys[0]["kind"] = ""
		doc["keys"], err = json.Marshal(keys)
		if err != nil {
			t.Fatalf("marshal keys: %v", err)
		}
		data, err := json.Marshal(doc)
		if err != nil {
			t.Fatalf("marshal document: %v", err)
		}
		path := filepath.Join(t.TempDir(), "state.json")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("write state file: %v", err)
		}
		if _, err := server.OpenFileState(path); !errors.Is(err, server.ErrStateCorrupt) {
			t.Fatalf("OpenFileState with kind \"\": err = %v, want ErrStateCorrupt", err)
		}
		return
	}
	t.Fatalf("registry case valid-kind-omitted not found")
}
