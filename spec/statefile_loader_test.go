package spec_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
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
// property (unknown fields, legacy members, mistyped admin, duplicate
// ids, ...) survives the adaptation.
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
				// An omitted (or null — but valid documents never carry
				// null) admin must come out as false; an explicit strict
				// boolean must round-trip exactly (spec 02 section 1).
				byKid := make(map[string]any, len(keys))
				for _, k := range keys {
					kid, _ := k["kid"].(string)
					byKid[kid] = k["admin"]
				}
				for _, entry := range loaded {
					admin, present := byKid[entry.Kid]
					if !present {
						t.Fatalf("case %s: loaded key %s not present in the document", tc.ID, entry.Kid)
					}
					if !present || admin == nil {
						if entry.Admin {
							t.Fatalf("case %s: key %s has no admin member but loaded as admin", tc.ID, entry.Kid)
						}
						continue
					}
					want, ok := admin.(bool)
					if !ok {
						t.Fatalf("case %s: key %s: admin is %v, not a strict boolean", tc.ID, entry.Kid, admin)
					}
					if entry.Admin != want {
						t.Fatalf("case %s: key %s: admin = %v, want %v", tc.ID, entry.Kid, entry.Admin, want)
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

// TestFileStateRejectsMistypedAdmin: admin must be a strict JSON boolean
// when present; the string "true", the number 1 and JSON null are all
// invalid and must be rejected with ErrStateCorrupt (spec 02 section 1).
func TestFileStateRejectsMistypedAdmin(t *testing.T) {
	vectors, err := spec.LoadLoadVectors()
	if err != nil {
		t.Fatalf("spec.LoadLoadVectors: %v", err)
	}
	for _, tc := range vectors.Registries {
		if tc.ID != "valid-admin-false" {
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
		for _, mistyped := range []any{"true", 1, nil} {
			keys[0]["admin"] = mistyped
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
				t.Fatalf("OpenFileState with admin %#v: err = %v, want ErrStateCorrupt", mistyped, err)
			}
		}
		return
	}
	t.Fatalf("registry case valid-admin-false not found")
}

// TestStateFileVectorsThroughFileState feeds EVERY state-file-vectors.json
// case verbatim through the FileState loader: valid documents load with the
// exact key and invite counts and leave the file bytes untouched, invalid
// ones fail with ErrStateCorrupt.
func TestStateFileVectorsThroughFileState(t *testing.T) {
	vectors, err := spec.LoadStateFileVectors()
	if err != nil {
		t.Fatalf("spec.LoadStateFileVectors: %v", err)
	}
	if len(vectors.Cases) == 0 {
		t.Fatalf("LoadStateFileVectors: no cases")
	}

	for _, tc := range vectors.Cases {
		t.Run(tc.ID, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.json")
			if err := os.WriteFile(path, tc.Document, 0o600); err != nil {
				t.Fatalf("write state file: %v", err)
			}
			beforeBytes, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read state file: %v", err)
			}

			switch tc.Expect {
			case "valid":
				store, err := server.OpenFileState(path)
				if err != nil {
					t.Fatalf("case %s: OpenFileState: %v", tc.ID, err)
				}
				var doc struct {
					Keys    []json.RawMessage `json:"keys"`
					Invites []json.RawMessage `json:"invites"`
				}
				if err := json.Unmarshal(tc.Document, &doc); err != nil {
					t.Fatalf("case %s: document does not decode: %v", tc.ID, err)
				}
				view := store.View()
				if len(view.Keys) != len(doc.Keys) {
					t.Fatalf("case %s: loaded %d keys, want %d", tc.ID, len(view.Keys), len(doc.Keys))
				}
				if len(view.Invites) != len(doc.Invites) {
					t.Fatalf("case %s: loaded %d invites, want %d", tc.ID, len(view.Invites), len(doc.Invites))
				}
				afterBytes, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("read state file after load: %v", err)
				}
				if !bytes.Equal(beforeBytes, afterBytes) {
					t.Fatalf("case %s: load rewrote the state file", tc.ID)
				}

				switch tc.ID {
				case "statefile-valid-default-invite":
					inv := view.Invites[0]
					if inv.KeyTTLSeconds != nil {
						t.Fatalf("case %s: KeyTTLSeconds = %d, want nil", tc.ID, *inv.KeyTTLSeconds)
					}
					if inv.Admin {
						t.Fatalf("case %s: Admin = true, want false", tc.ID)
					}
				case "statefile-valid-invite-ttl-max":
					inv := view.Invites[0]
					if inv.KeyTTLSeconds == nil {
						t.Fatalf("case %s: KeyTTLSeconds = nil, want 31536000", tc.ID)
					}
					if *inv.KeyTTLSeconds != 31536000 {
						t.Fatalf("case %s: KeyTTLSeconds = %d, want 31536000", tc.ID, *inv.KeyTTLSeconds)
					}
				case "statefile-valid-entry-and-invite":
					// Confirm from the raw document what we assert: entry
					// alice has no admin member; the invite carries admin
					// false and key_ttl_seconds 3600.
					var doc struct {
						Keys []map[string]json.RawMessage `json:"keys"`
					}
					if err := json.Unmarshal(tc.Document, &doc); err != nil {
						t.Fatalf("case %s: document does not decode: %v", tc.ID, err)
					}
					if _, present := doc.Keys[0]["admin"]; present {
						t.Fatalf("case %s: fixture changed: alice has an admin member", tc.ID)
					}
					var invite struct {
						Admin         bool   `json:"admin"`
						KeyTTLSeconds *int64 `json:"key_ttl_seconds"`
					}
					var raw struct {
						Invites []json.RawMessage `json:"invites"`
					}
					if err := json.Unmarshal(tc.Document, &raw); err != nil {
						t.Fatalf("case %s: invites member: %v", tc.ID, err)
					}
					if len(raw.Invites) == 0 {
						t.Fatalf("case %s: fixture changed: no invites", tc.ID)
					}
					if err := json.Unmarshal(raw.Invites[0], &invite); err != nil {
						t.Fatalf("case %s: invite record: %v", tc.ID, err)
					}
					if invite.Admin {
						t.Fatalf("case %s: fixture changed: invite admin is true", tc.ID)
					}
					if invite.KeyTTLSeconds == nil || *invite.KeyTTLSeconds != 3600 {
						t.Fatalf("case %s: fixture changed: invite key_ttl_seconds = %v, want 3600", tc.ID, invite.KeyTTLSeconds)
					}
					entry := view.Keys[0]
					if entry.Admin {
						t.Fatalf("case %s: alice loaded as admin, want false (no admin member)", tc.ID)
					}
					inv := view.Invites[0]
					if inv.Admin {
						t.Fatalf("case %s: invite loaded as admin, want false", tc.ID)
					}
					if inv.KeyTTLSeconds == nil || *inv.KeyTTLSeconds != 3600 {
						t.Fatalf("case %s: invite KeyTTLSeconds = %v, want 3600", tc.ID, inv.KeyTTLSeconds)
					}
				}
			case "invalid":
				store, err := server.OpenFileState(path)
				if store != nil {
					t.Fatalf("case %s: OpenFileState returned a non-nil store on failure", tc.ID)
				}
				if err == nil {
					t.Fatalf("case %s: OpenFileState accepted an invalid state file", tc.ID)
				} else if !errors.Is(err, server.ErrStateCorrupt) {
					t.Fatalf("case %s: err = %v, want ErrStateCorrupt", tc.ID, err)
				}
			default:
				t.Fatalf("case %s: unknown expect %q", tc.ID, tc.Expect)
			}
		})
	}
}

// TestStateFileLegacyRejectionDoesNotRewrite: the legacy members kind and
// scopes must be rejected with ErrStateCorrupt naming the offending member,
// and the loader must NOT migrate, strip or rewrite the document — the file
// bytes must survive the failed load byte-identical (spec 02 section 1).
func TestStateFileLegacyRejectionDoesNotRewrite(t *testing.T) {
	vectors, err := spec.LoadStateFileVectors()
	if err != nil {
		t.Fatalf("spec.LoadStateFileVectors: %v", err)
	}
	want := map[string]string{
		"statefile-invalid-legacy-kind-entry":   "kind",
		"statefile-invalid-legacy-scopes-entry": "scopes",
		"statefile-invalid-legacy-kind-invite":  "kind",
	}
	for _, tc := range vectors.Cases {
		substr, matched := want[tc.ID]
		if !matched {
			continue
		}
		t.Run(tc.ID, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.json")
			if err := os.WriteFile(path, tc.Document, 0o600); err != nil {
				t.Fatalf("write state file: %v", err)
			}
			beforeBytes, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read state file: %v", err)
			}
			_, err = server.OpenFileState(path)
			if !errors.Is(err, server.ErrStateCorrupt) {
				t.Fatalf("err = %v, want ErrStateCorrupt", err)
			}
			if err == nil || !strings.Contains(err.Error(), substr) {
				t.Fatalf("err = %v, want the message to mention %q", err, substr)
			}
			afterBytes, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read state file after failed load: %v", err)
			}
			if !bytes.Equal(beforeBytes, afterBytes) {
				t.Fatalf("the failed load rewrote the state file")
			}
		})
	}
}
