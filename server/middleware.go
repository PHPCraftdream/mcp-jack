package server

import (
	"context"
	"net/http"

	transport "github.com/PHPCraftdream/mcp-jack/server/internal/transport"
	verify "github.com/PHPCraftdream/mcp-jack/server/internal/verify"
)

// The HTTP hand-off seam moved to server/internal/transport; these aliases
// keep the server package API unchanged. This is a file-layout move only;
// no behavior changed. The core facade (server/verify.go) owns the Verifier,
// Identity and identity accessor names; the internal-only helpers
// (HasServerKeys, RawNow, WithIdentity) stay unexported in
// server/internal/verify and are used by the transport package directly.

// Identity is the read-only view of the verified caller identity the server
// SDK hands to the wrapped MCP handler (spec 02 section 3).
//
// It is an alias of verify.Identity; the concrete definition lives in
// server/internal/verify. WithIdentity stays unexported there: only the
// middleware may inject a verified identity.
type Identity = verify.Identity

// IdentityFromContext returns the verified caller identity of a request
// handed to the wrapped handler and reports whether one is present. Only the
// token the SDK's own middleware stored is recognized (spec 02 section 3).
func IdentityFromContext(ctx context.Context) (Identity, bool) {
	return verify.IdentityFromContext(ctx)
}

// HandlerConfig configures NewHandler.
type HandlerConfig = transport.HandlerConfig

// ResponseSigner holds the server signing capability without private-key export.
type ResponseSigner = transport.ResponseSigner

// ResponseKeyRequest is an owned copy; the payload is not the source of key authority.
type ResponseKeyRequest = transport.ResponseKeyRequest

// ResponseKeyAuthorization pins identity/time and the lease until the write completes.
type ResponseKeyAuthorization = transport.ResponseKeyAuthorization

// ResponseKeyProvider is selected explicitly; persistence/clock/ring invariants belong to the provider.
type ResponseKeyProvider = transport.ResponseKeyProvider

// NewHandler wraps next, an unmodified MCP server, so that only authenticated
// and authorized requests reach it and every verified answer is signed.
// See server/internal/transport.NewHandler for the full contract.
func NewHandler(cfg HandlerConfig, next http.Handler) (http.Handler, error) {
	return transport.NewHandler(cfg, next)
}
