package webhook

import (
	"context"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/endpoint"
)

// VerifierConfig configures the endpoint verification routes and cache.
type VerifierConfig = endpoint.Config

// Verifier checks whether a subscriber's callback endpoint consents to delivery.
type Verifier struct{ inner *endpoint.Verifier }

// NewVerifier constructs a verifier with a hardened client and cache by default.
func NewVerifier(cfg VerifierConfig) (*Verifier, error) {
	inner, err := endpoint.NewVerifier(cfg)
	if err != nil {
		return nil, err
	}
	return &Verifier{inner: inner}, nil
}

// VerificationError describes a failed verification or document check.
type VerificationError = endpoint.Error

// Verify tries the configured verification routes in profile order.
func (v *Verifier) Verify(ctx context.Context, principal, canonicalURL string) *VerificationError {
	return v.inner.Verify(ctx, principal, canonicalURL)
}

// FetchDoc fetches and validates the endpoint's well-known receiver document.
func (v *Verifier) FetchDoc(ctx context.Context, canonicalURL string) ([]string, *VerificationError) {
	return v.inner.FetchDoc(ctx, canonicalURL)
}

// RouteInput supplies the available verification evidence.
type RouteInput = endpoint.RouteInput

// Route describes the first successful route or the final failure reason.
type Route = endpoint.Route

// GateInput describes the verification state and message type.
type GateInput = endpoint.GateInput

// EchoInput supplies the challenge response and attempt state.
type EchoInput = endpoint.EchoInput

// NonceOK reports whether value has the profile's nonce encoding.
func NonceOK(value string) bool { return endpoint.NonceOK(value) }

// ChallengeEcho checks the status and body of a challenge response.
func ChallengeEcho(status int, bodyText, nonce string) *VerificationError {
	return endpoint.ChallengeEcho(status, bodyText, nonce)
}

// AcceptEcho checks a challenge response against the attempt state.
func AcceptEcho(in EchoInput) *VerificationError { return endpoint.AcceptEcho(in) }

// PairKey returns a key for a well-formed principal and callback pair.
func PairKey(pair any) (string, bool) { return endpoint.PairKey(pair) }

// ParseReceiverDoc validates a receiver document and returns its path prefixes.
func ParseReceiverDoc(text string) ([]string, *VerificationError) {
	return endpoint.ParseReceiverDoc(text)
}

// CheckReceiverDocFetch validates the status, size, and body of a document fetch.
func CheckReceiverDocFetch(status int, bodyText string, maxBody int64) ([]string, *VerificationError) {
	return endpoint.CheckReceiverDocFetch(status, bodyText, maxBody)
}

// ReceiverDocCovers returns the first document entry covering urlPath.
func ReceiverDocCovers(receivers []string, urlPath string) (string, bool) {
	return endpoint.ReceiverDocCovers(receivers, urlPath)
}

// AllowlistEntry is a parsed operator allowlist entry.
type AllowlistEntry = endpoint.AllowlistEntry

// ParseAllowlistEntry validates and parses an operator allowlist entry.
func ParseAllowlistEntry(text string) (AllowlistEntry, bool) {
	return endpoint.ParseAllowlistEntry(text)
}

// AllowlistMatches returns the first entry that matches the callback URL.
func AllowlistMatches(entries []string, canonicalURL string) (AllowlistEntry, bool) {
	return endpoint.AllowlistMatches(entries, canonicalURL)
}

// WellKnownURL returns the receiver document URL at the callback's origin.
func WellKnownURL(canonicalURL string) (string, bool) { return endpoint.WellKnownURL(canonicalURL) }

// DocCacheTTL returns the receiver document cache lifetime in seconds.
func DocCacheTTL(maxAge *int64) int64 { return endpoint.DocCacheTTL(maxAge) }

// VerificationRoute chooses the first successful route in profile order.
func VerificationRoute(in RouteInput) Route { return endpoint.VerificationRoute(in) }

// Gate decides whether to allow an event or send a verification challenge.
func Gate(in GateInput) string { return endpoint.Gate(in) }

// VerificationCache stores verification per principal and canonical callback URL.
type VerificationCache = endpoint.Cache

// NewVerificationCache constructs an empty endpoint verification cache.
func NewVerificationCache() *VerificationCache { return endpoint.NewCache() }
