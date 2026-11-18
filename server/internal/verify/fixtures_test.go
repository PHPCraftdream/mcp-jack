package verify

import (
	auditimpl "github.com/PHPCraftdream/mcp-jack/server/internal/audit"
	nonceimpl "github.com/PHPCraftdream/mcp-jack/server/internal/nonce"
	stateimpl "github.com/PHPCraftdream/mcp-jack/server/internal/state"
)

// Test fixtures carried with the white-box verifier tests moved from the
// root package. The concrete definitions stay in the internal packages and
// the root middleware tests; only the tests that inspect verifier internals
// moved here.

// testNow is the fixed clock of the fixtures (2026-01-01T00:00:00Z).
const testNow int64 = 1767225600

type MemoryState = stateimpl.MemoryState
type StateEdit = stateimpl.StateEdit
type NonceStore = nonceimpl.NonceStore

func NewMemoryState() *MemoryState { return stateimpl.NewMemoryState() }

func NewNonceStore() *NonceStore { return nonceimpl.NewNonceStore() }

func NewMemoryAuditSink() *auditimpl.MemoryAuditSink { return auditimpl.NewMemoryAuditSink() }

func toolCallBody(name string) []byte {
	return []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + name + `","arguments":{}}}`)
}
