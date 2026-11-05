package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/PHPCraftdream/mcp-jack"
)

// ErrStateCorrupt reports that an existing state file could not be decoded
// strictly (unknown fields, trailing data, wrong version or duplicate ids).
var ErrStateCorrupt = errors.New("state file is corrupt")

// stateDocument is the on-disk layout: deterministic bytes with keys sorted
// by Kid and invites sorted by InviteID.
type stateDocument struct {
	Version int             `json:"version"`
	Keys    []RegistryEntry `json:"keys"`
	Invites []InviteRecord  `json:"invites"`
}

// FileState is a file-backed StateStore. On-disk format is
// {"version":1,"keys":[...],"invites":[...]}; writes are atomic (temp file in
// the same directory, fsync, rename). Rollback semantics match MemoryState:
// an update error leaves both disk and memory untouched.
type FileState struct {
	mu      sync.Mutex
	path    string
	keys    []RegistryEntry
	invites []InviteRecord
}

// Compile-time check that FileState satisfies StateStore.
var _ StateStore = (*FileState)(nil)

// OpenFileState loads the state file at path. A missing file yields an empty
// store; an existing file must decode strictly (unknown fields rejected, no
// trailing data, version 1, no duplicate Kid or InviteID) or a corrupt error
// wrapping ErrStateCorrupt is returned together with a nil store.
func OpenFileState(path string) (*FileState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &FileState{path: path, keys: []RegistryEntry{}, invites: []InviteRecord{}}, nil
		}
		return nil, fmt.Errorf("read state file %s: %w", path, err)
	}

	doc, err := decodeState(data)
	if err != nil {
		return nil, fmt.Errorf("state file %s: %w", path, err)
	}

	return &FileState{path: path, keys: doc.Keys, invites: doc.Invites}, nil
}

func decodeState(data []byte) (*stateDocument, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	var doc stateDocument
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStateCorrupt, err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("%w: trailing data after JSON document", ErrStateCorrupt)
	}
	if doc.Version != 1 {
		return nil, fmt.Errorf("%w: unsupported version %d", ErrStateCorrupt, doc.Version)
	}

	seenKeys := make(map[string]bool, len(doc.Keys))
	for _, k := range doc.Keys {
		if seenKeys[k.Kid] {
			return nil, fmt.Errorf("%w: duplicate key %s", ErrStateCorrupt, k.Kid)
		}
		seenKeys[k.Kid] = true
	}
	seenInvites := make(map[string]bool, len(doc.Invites))
	for _, v := range doc.Invites {
		if seenInvites[v.InviteID] {
			return nil, fmt.Errorf("%w: duplicate invite %s", ErrStateCorrupt, v.InviteID)
		}
		seenInvites[v.InviteID] = true
	}
	// A persisted document must spell scopes out as arrays: a missing or null
	// value is malformed input, not an empty set (spec 02 section 1).
	for _, v := range doc.Invites {
		if v.Scopes == nil {
			return nil, fmt.Errorf("%w: invite %s has no scopes array", ErrStateCorrupt, v.InviteID)
		}
	}
	if err := validateKeys(doc.Keys); err != nil {
		return nil, err
	}
	return &doc, nil
}

// validateKeys enforces the load-time entry rules of 02-authorization.md
// section 1: name shape and uniqueness, kind, scope shape and distinctness,
// the agent/admin exclusion, validity intervals, kid = base64url(SHA-256(
// public_key)), and the public-key validity rules of 03 section 2.
func validateKeys(keys []RegistryEntry) error {
	seenNames := make(map[string]bool, len(keys))
	for i := range keys {
		k := keys[i]
		if !jack.ValidName(k.Name) {
			return fmt.Errorf("%w: invalid name %q for key %s", ErrStateCorrupt, k.Name, k.Kid)
		}
		if seenNames[k.Name] {
			return fmt.Errorf("%w: duplicate name %s", ErrStateCorrupt, k.Name)
		}
		seenNames[k.Name] = true
		if k.Kind != KindHuman && k.Kind != KindAgent {
			return fmt.Errorf("%w: invalid kind %q for key %s", ErrStateCorrupt, k.Kind, k.Kid)
		}
		if k.Scopes == nil {
			return fmt.Errorf("%w: key %s has no scopes array", ErrStateCorrupt, k.Kid)
		}
		seenScopes := make(map[string]bool, len(k.Scopes))
		for _, s := range k.Scopes {
			if !jack.ValidScope(s) {
				return fmt.Errorf("%w: invalid scope %q for key %s", ErrStateCorrupt, s, k.Kid)
			}
			if seenScopes[s] {
				return fmt.Errorf("%w: duplicate scope %q for key %s", ErrStateCorrupt, s, k.Kid)
			}
			seenScopes[s] = true
		}
		if k.Kind == KindAgent && seenScopes["admin"] {
			return fmt.Errorf("%w: agent key %s holds admin scope", ErrStateCorrupt, k.Kid)
		}
		if k.NotBefore != nil && *k.NotBefore < 0 {
			return fmt.Errorf("%w: negative not_before for key %s", ErrStateCorrupt, k.Kid)
		}
		if k.NotAfter != nil && *k.NotAfter < 0 {
			return fmt.Errorf("%w: negative not_after for key %s", ErrStateCorrupt, k.Kid)
		}
		if k.NotBefore != nil && k.NotAfter != nil && *k.NotBefore >= *k.NotAfter {
			return fmt.Errorf("%w: not_before not before not_after for key %s", ErrStateCorrupt, k.Kid)
		}
		pub, err := base64.RawURLEncoding.Strict().DecodeString(k.PublicKey)
		if err != nil || len(pub) != 32 {
			return fmt.Errorf("%w: invalid public key for key %s", ErrStateCorrupt, k.Kid)
		}
		digest := sha256.Sum256(pub)
		if kid := base64.RawURLEncoding.EncodeToString(digest[:]); kid != k.Kid {
			return fmt.Errorf("%w: kid mismatch for key %s", ErrStateCorrupt, k.Kid)
		}
		if err := jack.ValidatePublicKey(pub); err != nil {
			return fmt.Errorf("%w: key %s: %v", ErrStateCorrupt, k.Kid, err)
		}
	}
	return nil
}

// View returns a deep-copy snapshot of the in-memory state, like MemoryState.
func (s *FileState) View() StateView {
	s.mu.Lock()
	defer s.mu.Unlock()
	return StateView{
		Keys:    sortedKeys(s.keys),
		Invites: sortedInvites(s.invites),
	}
}

// Lookup returns a copy of the entry with the given kid, if present.
func (s *FileState) Lookup(kid string) (RegistryEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return lookupKey(s.keys, kid)
}

// Update runs update on a deep copy of the state; on error nothing is
// written and the error is returned unchanged. On success the new state is
// written atomically to the file (temp file in the same directory, fsync,
// rename) and only then swapped into memory. Any write failure removes the
// temp file best-effort and returns a wrapped error leaving disk and memory
// untouched.
func (s *FileState) Update(update StateUpdate) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	edit := &StateEdit{keys: cloneKeys(s.keys), invites: cloneInvites(s.invites)}
	if err := update(edit); err != nil {
		return err
	}
	if err := s.writeLocked(edit); err != nil {
		return err
	}
	s.keys = cloneKeys(edit.keys)
	s.invites = cloneInvites(edit.invites)
	return nil
}

// writeLocked marshals the given state deterministically and atomically
// replaces the file. On failure the temp file is removed best-effort and the
// in-memory state is left untouched.
func (s *FileState) writeLocked(edit *StateEdit) error {
	doc := stateDocument{
		Version: 1,
		Keys:    sortedKeys(edit.keys),
		Invites: sortedInvites(edit.invites),
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	data = append(data, '\n')

	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".mcp-jack-state-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp state file: %w", err)
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("write state file %s: %w", s.path, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("sync state file %s: %w", s.path, err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("close state file %s: %w", s.path, err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("rename state file %s: %w", s.path, err)
	}
	return nil
}
