package server

import (
	"sort"
	"sync"
)

// Principal kinds, as stored in RegistryEntry.Kind.
const (
	KindHuman = "human"
	KindAgent = "agent"
)

// RegistryEntry is one registered key in the server state. JSON tags and field
// order match the entries of spec/fixtures/registry.json; the pointer fields
// marshal as null when nil (no omitempty). See 02-authorization.md section 1.
type RegistryEntry struct {
	Kid       string   `json:"kid"`
	PublicKey string   `json:"public_key"`
	Name      string   `json:"name"`
	Kind      string   `json:"kind"`
	Scopes    []string `json:"scopes"`
	NotBefore *int64   `json:"not_before"`
	NotAfter  *int64   `json:"not_after"`
}

// InviteRecord is one pending invite. JSON tags and field order match the
// state.invites records of spec/fixtures/admin-vectors.json.
// See 03-user-management.md sections 3.2 and 9.
type InviteRecord struct {
	InviteID      string   `json:"invite_id"`
	Scopes        []string `json:"scopes"`
	Kind          string   `json:"kind"`
	CreatedBy     string   `json:"created_by"`
	CreatedAt     int64    `json:"created_at"`
	ExpiresAt     int64    `json:"expires_at"`
	KeyTTLSeconds *int64   `json:"key_ttl_seconds"`
}

// StateView is an immutable snapshot of the store: it holds deep copies, so
// mutating a returned view never affects the store. Keys are sorted by Kid
// and Invites are sorted by InviteID.
type StateView struct {
	Keys    []RegistryEntry
	Invites []InviteRecord
}

// StateEdit is a mutable deep copy of the current state handed to a
// StateUpdate. Getters return copies; edits accumulate on the edit only and
// become visible when the store swaps it in.
type StateEdit struct {
	keys    []RegistryEntry
	invites []InviteRecord
}

// Key returns a copy of the entry with the given kid, if present.
func (e *StateEdit) Key(kid string) (RegistryEntry, bool) {
	for _, entry := range e.keys {
		if entry.Kid == kid {
			out := cloneKeys([]RegistryEntry{entry})
			return out[0], true
		}
	}
	return RegistryEntry{}, false
}

// KeyByName returns a copy of the entry with the given name, if present.
func (e *StateEdit) KeyByName(name string) (RegistryEntry, bool) {
	for _, entry := range e.keys {
		if entry.Name == name {
			out := cloneKeys([]RegistryEntry{entry})
			return out[0], true
		}
	}
	return RegistryEntry{}, false
}

// Keys returns copies of all entries sorted by Kid.
func (e *StateEdit) Keys() []RegistryEntry {
	out := cloneKeys(e.keys)
	sort.Slice(out, func(i, j int) bool { return out[i].Kid < out[j].Kid })
	return out
}

// Invite returns a copy of the invite with the given id, if present.
func (e *StateEdit) Invite(inviteID string) (InviteRecord, bool) {
	for _, inv := range e.invites {
		if inv.InviteID == inviteID {
			out := cloneInvites([]InviteRecord{inv})
			return out[0], true
		}
	}
	return InviteRecord{}, false
}

// Invites returns copies of all invites sorted by InviteID.
func (e *StateEdit) Invites() []InviteRecord {
	out := cloneInvites(e.invites)
	sort.Slice(out, func(i, j int) bool { return out[i].InviteID < out[j].InviteID })
	return out
}

// PutKey replaces any entry with the same Kid or appends a new one. A nil
// Scopes slice is normalized to an empty non-nil slice so marshaled JSON
// shows [] rather than null; no other validation is performed here (spec
// rules are enforced by the caller's layers). The entry is cloned so the
// store never aliases the caller's slices or timestamp pointees: a later
// caller mutation must not change committed state outside the store mutex.
func (e *StateEdit) PutKey(entry RegistryEntry) {
	if entry.Scopes == nil {
		entry.Scopes = []string{}
	}
	for i := range e.keys {
		if e.keys[i].Kid == entry.Kid {
			e.keys[i] = cloneEntry(entry)
			return
		}
	}
	e.keys = append(e.keys, cloneEntry(entry))
}

// RemoveKey deletes the entry with the given kid and reports whether
// anything was removed.
func (e *StateEdit) RemoveKey(kid string) bool {
	for i := range e.keys {
		if e.keys[i].Kid == kid {
			e.keys = append(e.keys[:i], e.keys[i+1:]...)
			return true
		}
	}
	return false
}

// PutInvite replaces any invite with the same InviteID or appends a new one.
// A nil Scopes slice is normalized to an empty non-nil slice. The invite is
// cloned so the store never aliases the caller's slices or TTL pointees.
func (e *StateEdit) PutInvite(invite InviteRecord) {
	if invite.Scopes == nil {
		invite.Scopes = []string{}
	}
	for i := range e.invites {
		if e.invites[i].InviteID == invite.InviteID {
			e.invites[i] = cloneInvite(invite)
			return
		}
	}
	e.invites = append(e.invites, cloneInvite(invite))
}

// RemoveInvite deletes the invite with the given id and reports whether
// anything was removed.
func (e *StateEdit) RemoveInvite(inviteID string) bool {
	for i := range e.invites {
		if e.invites[i].InviteID == inviteID {
			e.invites = append(e.invites[:i], e.invites[i+1:]...)
			return true
		}
	}
	return false
}

// StateUpdate mutates a StateEdit. It must not call back into the store and
// must not block; returning an error rolls back the whole update.
type StateUpdate func(*StateEdit) error

// StateStore is the registry/invite state interface shared by the in-memory
// and file-backed implementations.
type StateStore interface {
	View() StateView
	// Lookup returns a copy of the entry with the given kid. Request
	// verification calls it once per request, so it must not copy the whole
	// registry the way View does.
	Lookup(kid string) (RegistryEntry, bool)
	Update(update StateUpdate) error
}

// MemoryState is an in-memory StateStore. Update takes a deep copy, runs the
// update on it while holding the store mutex (so concurrent Updates are
// serialized), and swaps it in only if the update returned nil; on error the
// copy is discarded and the error is returned unchanged (rollback).
type MemoryState struct {
	mu      sync.Mutex
	keys    []RegistryEntry
	invites []InviteRecord
}

// Compile-time check that MemoryState satisfies StateStore.
var _ StateStore = (*MemoryState)(nil)

// NewMemoryState returns an empty in-memory state store.
func NewMemoryState() *MemoryState {
	return &MemoryState{}
}

// View returns a deep-copy snapshot of the current state.
func (s *MemoryState) View() StateView {
	s.mu.Lock()
	defer s.mu.Unlock()
	return StateView{
		Keys:    sortedKeys(s.keys),
		Invites: sortedInvites(s.invites),
	}
}

// Lookup returns a copy of the entry with the given kid, if present.
func (s *MemoryState) Lookup(kid string) (RegistryEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return lookupKey(s.keys, kid)
}

// lookupKey finds an entry by kid and returns a deep copy of it.
func lookupKey(keys []RegistryEntry, kid string) (RegistryEntry, bool) {
	for i := range keys {
		if keys[i].Kid == kid {
			return cloneEntry(keys[i]), true
		}
	}
	return RegistryEntry{}, false
}

// Update runs update on a deep copy of the state while the mutex is held;
// see the MemoryState doc comment for the rollback semantics.
func (s *MemoryState) Update(update StateUpdate) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	edit := &StateEdit{keys: cloneKeys(s.keys), invites: cloneInvites(s.invites)}
	if err := update(edit); err != nil {
		return err
	}
	s.keys = cloneKeys(edit.keys)
	s.invites = cloneInvites(edit.invites)
	return nil
}

func cloneInt64(p *int64) *int64 {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

func cloneEntry(entry RegistryEntry) RegistryEntry {
	out := entry
	if entry.Scopes != nil {
		out.Scopes = make([]string, len(entry.Scopes))
		copy(out.Scopes, entry.Scopes)
	}
	out.NotBefore = cloneInt64(entry.NotBefore)
	out.NotAfter = cloneInt64(entry.NotAfter)
	return out
}

func cloneInvite(invite InviteRecord) InviteRecord {
	out := invite
	if invite.Scopes != nil {
		out.Scopes = make([]string, len(invite.Scopes))
		copy(out.Scopes, invite.Scopes)
	}
	out.KeyTTLSeconds = cloneInt64(invite.KeyTTLSeconds)
	return out
}

func cloneKeys(keys []RegistryEntry) []RegistryEntry {
	out := make([]RegistryEntry, len(keys))
	for i, k := range keys {
		out[i] = cloneEntry(k)
	}
	return out
}

func cloneInvites(invites []InviteRecord) []InviteRecord {
	out := make([]InviteRecord, len(invites))
	for i, v := range invites {
		out[i] = cloneInvite(v)
	}
	return out
}

func sortedKeys(keys []RegistryEntry) []RegistryEntry {
	out := cloneKeys(keys)
	sort.Slice(out, func(i, j int) bool { return out[i].Kid < out[j].Kid })
	return out
}

func sortedInvites(invites []InviteRecord) []InviteRecord {
	out := cloneInvites(invites)
	sort.Slice(out, func(i, j int) bool { return out[i].InviteID < out[j].InviteID })
	return out
}
