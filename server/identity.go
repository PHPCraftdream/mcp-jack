package server

import "context"

// Identity is the read-only view of the verified caller identity the server
// SDK hands to the wrapped MCP handler (spec 02 section 3): exactly the
// {kid, name, admin} of the caller's registry entry at verification time —
// the same snapshot authentication and the admin gate used. It exposes no
// writable state: consumers can read a verified identity, never alter or
// fabricate one that the SDK or another handler would treat as verified.
type Identity interface {
	// Kid is the key id of the verified caller.
	Kid() string
	// Name is the registry label of the verified caller.
	Name() string
	// Admin mirrors the caller's admin flag; it is data for consumer policy,
	// not an authorization decision — the protocol enforces only the
	// jack.admin.* gate.
	Admin() bool
}

// identityToken is the authenticated value the middleware stores in the
// request context. It is unexported with unexported fields and is never
// returned by any exported function; IdentityFromContext recognizes exactly
// this type, so nothing a consumer can hold, alter or fabricate is ever
// accepted as verified (spec 02 section 3).
type identityToken struct {
	kid   string
	name  string
	admin bool
}

// identitySnapshot is the immutable read view IdentityFromContext returns: a
// copy of the token's fields behind read-only methods, with no writable
// verified attributes.
type identitySnapshot struct {
	kid   string
	name  string
	admin bool
}

func (s identitySnapshot) Kid() string  { return s.kid }
func (s identitySnapshot) Name() string { return s.name }
func (s identitySnapshot) Admin() bool  { return s.admin }

// identityContextKey is unexported: identity values can only be injected by
// the SDK's own middleware, never by package-external code.
type identityContextKey struct{}

// snapshotOf builds the consumer view of the verified caller's registry
// entry.
func snapshotOf(e RegistryEntry) identitySnapshot {
	return identitySnapshot{kid: e.Kid, name: e.Name, admin: e.Admin}
}

// sealIdentity converts the verified view into the storable token. It accepts
// only the SDK's own snapshot type, so no consumer-built or consumer-held
// Identity can enter a request context.
func sealIdentity(id Identity) (identityToken, bool) {
	s, ok := id.(identitySnapshot)
	if !ok {
		return identityToken{}, false
	}
	return identityToken{kid: s.kid, name: s.name, admin: s.admin}, true
}

// IdentityFromContext returns the verified caller identity of a request
// handed to the wrapped handler and reports whether one is present. Only the
// token the SDK's own middleware stored is recognized: an Identity a consumer
// fabricated, altered, or re-bound into a custom context.Value implementation
// is rejected, because none of them is an identityToken. Native jack.* calls
// never reach the wrapped handler, so they have no identity.
func IdentityFromContext(ctx context.Context) (Identity, bool) {
	tok, ok := ctx.Value(identityContextKey{}).(identityToken)
	if !ok {
		return nil, false
	}
	return identitySnapshot{kid: tok.kid, name: tok.name, admin: tok.admin}, true
}
