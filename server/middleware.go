package server

import (
	"context"
	"net/http"

	"github.com/PHPCraftdream/mcp-jack/server/internal/modern"
	stream "github.com/PHPCraftdream/mcp-jack/server/internal/stream"
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

// Profile is the server deployment profile of spec 04 section 3.
type Profile = modern.Profile

const (
	// ProfileLegacy serves every request as legacy-era (the default).
	ProfileLegacy = modern.ProfileLegacy
	// ProfileModern serves every request as modern-era.
	ProfileModern = modern.ProfileModern
	// ProfileBoth decides the era per request.
	ProfileBoth = modern.ProfileBoth
)

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

// StreamOptions configures signed response streams (spec 05 section 3): the
// frame cap, the per-identity concurrency limit, the maximum duration and the
// heartbeat grant.
type StreamOptions = stream.Options

// DefaultStreamOptions returns the stream defaults of spec 05 section 3.
func DefaultStreamOptions() StreamOptions { return StreamOptions{} }

// StreamGrant reports the signed-stream limits the server granted to a
// request handed to the wrapped handler (spec 05 section 3.5).
type StreamGrant = transport.StreamGrant

// StreamFromContext returns the signed-stream grant of a request handed to the
// wrapped handler and reports whether the request opted in to a stream.
func StreamFromContext(ctx context.Context) (StreamGrant, bool) {
	return transport.StreamFromContext(ctx)
}

// NewHandler wraps next, an unmodified MCP server, so that only authenticated
// and authorized requests reach it and every verified answer is signed.
// See server/internal/transport.NewHandler for the full contract.
func NewHandler(cfg HandlerConfig, next http.Handler) (http.Handler, error) {
	return transport.NewHandler(cfg, next)
}
