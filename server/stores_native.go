package server

// Package-level re-exports of implementations that now live in
// server/internal/{audit,nonce,state,invite,native}. These aliases and
// wrappers keep the historical server package API stable; the
// implementations are private to the module.

import (
	"errors"
	"io"

	audit "github.com/PHPCraftdream/mcp-jack/server/internal/audit"
	"github.com/PHPCraftdream/mcp-jack/server/internal/invite"
	native "github.com/PHPCraftdream/mcp-jack/server/internal/native"
	nonce "github.com/PHPCraftdream/mcp-jack/server/internal/nonce"
	stateimpl "github.com/PHPCraftdream/mcp-jack/server/internal/state"
)

// Audit outcome values.
const (
	AuditSuccess = audit.AuditSuccess
	AuditFailure = audit.AuditFailure
)

// AuditEvent is one audit record. It deliberately carries nothing that could
// hold an invite code or a private key: 03-user-management.md section 8
// requires time, caller kid and name, tool, target, outcome and failure code.
//
// It is an alias of audit.AuditEvent; the concrete definition lives in
// server/internal/audit.
type AuditEvent = audit.AuditEvent

// AuditSink receives audit events.
//
// It is an alias of audit.AuditSink; the concrete definition lives in
// server/internal/audit.
type AuditSink = audit.AuditSink

// MemoryAuditSink keeps audit events in memory. Record always succeeds.
//
// It is an alias of audit.MemoryAuditSink; the concrete definition lives in
// server/internal/audit.
type MemoryAuditSink = audit.MemoryAuditSink

// NewMemoryAuditSink returns an empty in-memory audit sink.
func NewMemoryAuditSink() *MemoryAuditSink {
	return audit.NewMemoryAuditSink()
}

// JSONLAuditSink writes one compact JSON object per line to an io.Writer,
// guarded by a mutex so concurrent records never interleave.
//
// It is an alias of audit.JSONLAuditSink; the concrete definition lives in
// server/internal/audit.
type JSONLAuditSink = audit.JSONLAuditSink

// NewJSONLAuditSink returns a sink writing JSON lines to w.
func NewJSONLAuditSink(w io.Writer) *JSONLAuditSink {
	return audit.NewJSONLAuditSink(w)
}

// NonceStore provides replay protection: it remembers (kid, nonce) pairs for a
// caller-supplied retention window so a repeated pair is detected atomically.
// Times are Unix seconds supplied by the caller; the store never reads a clock.
// See 01-authentication.md section 4.
//
// It is an alias of nonce.NonceStore; the concrete definition lives in
// server/internal/nonce.
type NonceStore = nonce.NonceStore

// NewNonceStore returns an empty nonce store.
func NewNonceStore() *NonceStore {
	return nonce.NewNonceStore()
}

// RegistryEntry is one registered key in the server state. JSON tags and field
// order match the entries of spec/fixtures/registry.json; the admin flag
// marshals always (false included) and the pointer fields marshal as null
// when nil (no omitempty). See 02-authorization.md section 1.
type RegistryEntry = stateimpl.RegistryEntry

// InviteRecord is one pending invite. The admin flag marshals always;
// key_ttl_seconds is present only when set (omitempty). JSON tags and field
// order match the state.invites records of spec/fixtures/admin-vectors.json.
// See 03-user-management.md sections 3.2, 3.3 and 10.
type InviteRecord = stateimpl.InviteRecord

// StateView is an immutable snapshot of the store: it holds deep copies, so
// mutating a returned view never affects the store. Keys are sorted by Kid
// and Invites are sorted by InviteID.
type StateView = stateimpl.StateView

// StateEdit is a mutable deep copy of the current state handed to a
// StateUpdate. Getters return copies; edits accumulate on the edit only and
// become visible when the store swaps it in.
type StateEdit = stateimpl.StateEdit

// StateUpdate mutates a StateEdit. It must not call back into the store and
// must not block; returning an error rolls back the whole update.
type StateUpdate = stateimpl.StateUpdate

// StateStore is the registry/invite state interface shared by the in-memory
// and file-backed implementations.
type StateStore = stateimpl.StateStore

// MemoryState is an in-memory StateStore. Update takes a deep copy, runs the
// update on it while holding the store mutex (so concurrent Updates are
// serialized), and swaps it in only if the update returned nil; on error the
// copy is discarded and the error is returned unchanged (rollback).
type MemoryState = stateimpl.MemoryState

// NewMemoryState returns an empty in-memory state store.
func NewMemoryState() *MemoryState {
	return stateimpl.NewMemoryState()
}

// ErrStateCorrupt reports that an existing state file could not be decoded
// strictly (unknown fields, trailing data, wrong version or duplicate ids).
// It stays a package-level variable here so external callers may rebind it;
// OpenFileState passes it into the internal loader, which wraps every
// corrupt-load error with the sentinel seen below at call time.
var ErrStateCorrupt = errors.New("state file is corrupt")

// FileState is a file-backed StateStore. On-disk format is
// {"version":1,"keys":[...],"invites":[...]}; writes are atomic (temp file in
// the same directory, fsync, rename). Rollback semantics match MemoryState:
// an update error leaves both disk and memory untouched.
type FileState = stateimpl.FileState

// OpenFileState loads the state file at path. A missing file yields an empty
// store; an existing file must decode strictly (unknown fields rejected, no
// trailing data, version 1, no duplicate Kid or InviteID, strict admin
// booleans, legacy kind/scopes fields rejected) or a corrupt error wrapping
// ErrStateCorrupt is returned together with a nil store. Legacy documents are
// never migrated, stripped or rewritten; a failed load never writes the file
// (spec 02 section 1, 03 section 10).
func OpenFileState(path string) (*FileState, error) {
	return stateimpl.OpenFileStateCorrupt(path, ErrStateCorrupt)
}

// Native implements the protocol-native tools of spec 03: enrollment, key
// rotation, whoami and user and invite administration. Every state change is
// one StateStore.Update, so it is atomic (spec 03 section 9). An
// invite-editing update also removes expired invites in the same edit; a
// rejected update rolls the purge back.
type Native = native.Native

// NativeOptions configures NewNativeTools.
type NativeOptions = native.NativeOptions

// NewNativeTools returns the native tool implementation.
func NewNativeTools(opts NativeOptions) *Native {
	return native.NewNativeTools(opts)
}

// BootstrapAdmin creates the first administrator's invite out of band (spec 03
// section 5): one single-use admin invite, valid for ttlSeconds. It returns
// the invite code, which exists nowhere else.
// It is a local operation, not an MCP tool; call it from the service's own
// start-up or an operator command, never from a network handler.
func BootstrapAdmin(state StateStore, now, ttlSeconds int64, opts NativeOptions) (string, error) {
	return native.BootstrapAdmin(state, now, ttlSeconds, opts)
}

// inviteIDOf forwards to invite.InviteIDOf so the remaining root tests
// (enroll_gate_test.go and verify_test.go) keep working unchanged until they
// consolidate on the internal package.
func inviteIDOf(rawCode []byte) string {
	return invite.InviteIDOf(rawCode)
}
