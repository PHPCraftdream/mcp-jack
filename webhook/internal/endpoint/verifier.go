package endpoint

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/delivery"
	"github.com/PHPCraftdream/mcp-jack/webhook/internal/urlcheck"
)

// RouteInput supplies the available verification evidence in R5.2.
// A nil Challenge means no attempt; &Error{} represents a successful echo.
type RouteInput struct {
	Cache     bool
	Allowlist []string
	URL       string
	Hook      bool
	Doc       []string
	DocPath   string
	Challenge *Error
}

// Route describes the first successful route or the final failure reason.
type Route struct {
	Verified bool
	Route    string
	Reason   string
}

// VerificationRoute selects the first successful route in R5.2 order.
func VerificationRoute(in RouteInput) Route {
	if in.Cache {
		return Route{Verified: true, Route: "cache"}
	}
	if _, ok := AllowlistMatches(in.Allowlist, in.URL); ok {
		return Route{Verified: true, Route: "allowlist"}
	}
	if in.Hook {
		return Route{Verified: true, Route: "out_of_band"}
	}
	if _, ok := ReceiverDocCovers(in.Doc, in.DocPath); ok {
		return Route{Verified: true, Route: "well_known"}
	}
	if in.Challenge == nil {
		return Route{Reason: "no_route"}
	}
	if *in.Challenge == (Error{}) {
		return Route{Verified: true, Route: "challenge"}
	}
	return Route{Reason: in.Challenge.Reason}
}

// GateInput describes whether the pair is verified and the type of message.
type GateInput struct {
	Verified bool
	Message  string
}

// Gate prevents event, gap and terminated delivery before verification (R5.1).
func Gate(in GateInput) string {
	if in.Message == "verification" {
		return "send-challenge"
	}
	if in.Verified {
		return "deliver"
	}
	return "refuse"
}

type pair struct{ principal, url string }

// Cache stores expiring verification results per principal and canonical URL.
// Its zero value is ready to use. A Cache must not be copied after first use.
type Cache struct {
	mu      sync.Mutex
	entries map[pair]time.Time
	now     func() time.Time
}

// NewCache creates an empty verification cache.
func NewCache() *Cache { return &Cache{} }

func (c *Cache) currentTime() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

// Get reports whether the pair has an unexpired verification.
func (c *Cache) Get(principal, canonicalURL string) bool {
	key := pair{principal, canonicalURL}
	now := c.currentTime()
	c.mu.Lock()
	defer c.mu.Unlock()
	if expiry, ok := c.entries[key]; ok {
		if now.Before(expiry) {
			return true
		}
		delete(c.entries, key)
	}
	return false
}

// Put sets the verification lifetime; a nonpositive TTL removes the entry.
func (c *Cache) Put(principal, canonicalURL string, ttl time.Duration) {
	key := pair{principal, canonicalURL}
	if principal == "" || canonicalURL == "" {
		return
	}
	expiry := c.currentTime().Add(ttl)
	c.mu.Lock()
	defer c.mu.Unlock()
	if ttl <= 0 {
		delete(c.entries, key)
		return
	}
	if c.entries == nil {
		c.entries = make(map[pair]time.Time)
	}
	c.entries[key] = expiry
}

// Config supplies verification routes and the clock for the document cache
// and, if no Cache is supplied, the private verification cache.
type Config struct {
	Client        *delivery.Client
	AllowedRanges []string
	Allowlist     []string
	Hook          func(ctx context.Context, principal, canonicalURL string) (bool, error)
	// Challenge owns the R5.5 handshake and must send it over the hardened delivery path.
	Challenge func(ctx context.Context, principal, canonicalURL string) error
	Cache     *Cache
	Now       func() int64
}

type cachedDoc struct {
	receivers []string
	expires   time.Time
}

// Verifier tries the configured verification routes and caches their successful results.
type Verifier struct {
	cfg   Config
	docMu sync.Mutex
	docs  map[string]cachedDoc
}

// NewVerifier creates a verifier with a hardened client and private cache by default.
func NewVerifier(cfg Config) (*Verifier, error) {
	cfg.Allowlist = slices.Clone(cfg.Allowlist)
	if cfg.Client == nil {
		cfg.Client = delivery.NewClient(delivery.Config{AllowedRanges: cfg.AllowedRanges})
	}
	if cfg.Cache == nil {
		cfg.Cache = NewCache()
		if clock := cfg.Now; clock != nil {
			cfg.Cache.now = func() time.Time { return time.Unix(clock(), 0) }
		}
	}
	if cfg.Now == nil {
		cfg.Now = func() int64 { return time.Now().Unix() }
	}
	return &Verifier{cfg: cfg, docs: make(map[string]cachedDoc)}, nil
}

// Verify tries the R5.2 routes in order. Without a subscription TTL in this
// API, new results use Jack's default grant (R8.5); subscription code can set
// its actual remaining TTL with Cache.Put on the supplied cache.
func (v *Verifier) Verify(ctx context.Context, principal, canonicalURL string) *Error {
	u, err := urlcheck.Check(canonicalURL)
	if err != nil {
		return &Error{Code: err.Code, Reason: err.Reason}
	}
	if principal == "" {
		return challengeFailure("pair")
	}
	if v.cfg.Cache.Get(principal, u.Canonical) {
		return nil
	}
	verified := func() *Error {
		v.cfg.Cache.Put(principal, u.Canonical, time.Hour)
		return nil
	}
	if _, ok := allowlistMatches(v.cfg.Allowlist, u); ok {
		return verified()
	}
	if v.cfg.Hook != nil {
		if ok, err := v.cfg.Hook(ctx, principal, u.Canonical); err == nil && ok {
			return verified()
		}
	}
	if doc, err := v.fetchDoc(ctx, wellKnownURL(u)); err == nil {
		if _, ok := ReceiverDocCovers(doc, u.Path); ok {
			return verified()
		}
	}
	if v.cfg.Challenge == nil {
		return challengeFailure("no_route")
	}
	if err := v.cfg.Challenge(ctx, principal, u.Canonical); err != nil {
		if refusal := challengeError(err); refusal != nil {
			return refusal
		}
	}
	return verified()
}

// FetchDoc fetches and validates the well-known document, with per-origin caching.
func (v *Verifier) FetchDoc(ctx context.Context, canonicalURL string) ([]string, *Error) {
	u, err := urlcheck.Check(canonicalURL)
	if err != nil {
		return nil, &Error{Code: err.Code, Reason: err.Reason}
	}
	return v.fetchDoc(ctx, wellKnownURL(u))
}

func (v *Verifier) fetchDoc(ctx context.Context, docURL string) ([]string, *Error) {
	now := time.Unix(v.cfg.Now(), 0)
	v.docMu.Lock()
	if cached, ok := v.docs[docURL]; ok {
		if now.Before(cached.expires) {
			v.docMu.Unlock()
			return slices.Clone(cached.receivers), nil
		}
		delete(v.docs, docURL)
	}
	v.docMu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, docURL, nil)
	if err != nil {
		return nil, &Error{Code: "document_fetch_failed", Reason: "request"}
	}
	res, refusal := v.cfg.Client.Do(req, MaxDocBytes)
	if refusal != nil {
		if refusal.Code == "too_large" {
			return nil, &Error{Code: "document_fetch_failed", Reason: "too_large"}
		}
		return nil, &Error{Code: refusal.Code, Reason: refusal.Reason}
	}
	receivers, invalid := CheckReceiverDocFetch(res.Status, string(res.Body), MaxDocBytes)
	if invalid != nil {
		return nil, invalid
	}
	if ttl := cacheControlTTL(res.Header); ttl > 0 {
		expires := time.Unix(v.cfg.Now(), 0).Add(time.Duration(ttl) * time.Second)
		v.docMu.Lock()
		v.docs[docURL] = cachedDoc{receivers: slices.Clone(receivers), expires: expires}
		v.docMu.Unlock()
	}
	return receivers, nil
}

func cacheControlTTL(header http.Header) int64 {
	for _, value := range header.Values("Cache-Control") {
		for directive := range strings.SplitSeq(value, ",") {
			name, text, ok := strings.Cut(strings.TrimSpace(directive), "=")
			if !strings.EqualFold(strings.TrimSpace(name), "max-age") {
				continue
			}
			if !ok {
				return DocCacheTTL(nil)
			}
			text = strings.TrimSpace(text)
			if len(text) >= 2 && text[0] == '"' && text[len(text)-1] == '"' {
				text = text[1 : len(text)-1]
			}
			if text == "" || strings.IndexFunc(text, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
				return DocCacheTTL(nil)
			}
			age, err := strconv.ParseInt(text, 10, 64)
			if err != nil {
				return DocCacheTTL(nil)
			}
			return DocCacheTTL(&age)
		}
	}
	return DocCacheTTL(nil)
}

// challengeError maps only known categories and reasons, never raw error text.
func challengeError(err error) *Error {
	// A callback can directly return ChallengeEcho's nil *Error as an error.
	if rejection, ok := err.(*Error); ok && rejection == nil {
		return nil
	}
	var rejection *Error
	if errors.As(err, &rejection) {
		if rejection == nil {
			return challengeFailure("")
		}
		return challengeCategory(rejection.Code, rejection.Reason)
	}
	var deliveryErr *delivery.Error
	if errors.As(err, &deliveryErr) {
		if deliveryErr == nil {
			return challengeFailure("")
		}
		return challengeCategory(deliveryErr.Code, deliveryErr.Reason)
	}
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &netErr) && netErr.Timeout() {
		return &Error{Code: "timeout"}
	}
	var certificate *tls.CertificateVerificationError
	var record tls.RecordHeaderError
	var alert tls.AlertError
	if errors.As(err, &certificate) || errors.As(err, &record) || errors.As(err, &alert) {
		return &Error{Code: "tls_error"}
	}
	var op *net.OpError
	var dns *net.DNSError
	if errors.Is(err, syscall.ECONNREFUSED) || errors.As(err, &op) || errors.As(err, &dns) {
		return &Error{Code: "connection_refused"}
	}
	// Callbacks may also report a category as an exact token.
	return challengeCategory(err.Error(), "")
}

func challengeCategory(code, reason string) *Error {
	switch code {
	case "timeout", "connection_refused", "tls_error", "http_4xx":
		return &Error{Code: code}
	case "blocked_address", "dns_rebinding", "no_answer":
		return &Error{Code: "connection_refused"}
	case "redirect_refused":
		return &Error{Code: "http_4xx"}
	case "too_large":
		return challengeFailure("too_large")
	case "http_5xx":
		return challengeFailure("status")
	case "challenge_failed":
		switch reason {
		case "status", "body", "too_large", "json", "missing", "mismatch", "expired", "reused", "pair", "no_route":
			return challengeFailure(reason)
		}
	}
	return challengeFailure("")
}
