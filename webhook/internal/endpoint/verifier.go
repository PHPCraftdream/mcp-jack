package endpoint

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
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

// DeliveryAction prevents event, gap and terminated delivery before verification (R5.1).
func DeliveryAction(in GateInput) string {
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

// GateConfig supplies the verification routes, clock, and nonce source.
type GateConfig struct {
	Client        *delivery.Client // nil uses a hardened client with AllowedRanges
	AllowedRanges []string
	Allowlist     []string
	Hook          func(ctx context.Context, principal, canonicalURL string) (bool, error)
	Cache         *Cache       // nil uses a private cache driven by Now when provided
	Now           func() int64 // nil uses Unix wall time in seconds; a supplied Cache retains its own clock
	Random        io.Reader    // nil uses crypto/rand.Reader
	NonceTTL      int64        // seconds; zero defaults to 600
}

type cachedDoc struct {
	receivers []string
	expires   time.Time
}

type nonceKey = [sha256.Size]byte

type nonceRecord struct {
	value    [16]byte
	pair     pair
	issuedAt int64
	consumed bool
}

// Gate verifies pairs by R5.2 and manages single-use challenge nonces. An
// empty principal or a URL rejected by urlcheck.Check is challenge_failed/pair;
// Fresh returns false for such a pair. Gate must not be copied after first use.
type Gate struct {
	cfg   GateConfig
	docMu sync.Mutex
	docs  map[string]cachedDoc

	nonceMu     sync.Mutex
	pending     map[pair]nonceKey
	nonces      map[nonceKey]nonceRecord // reverse index for pending and retired nonces
	lastPruneAt int64
}

// NewGate creates a gate with a hardened client and private cache by default.
func NewGate(cfg GateConfig) (*Gate, error) {
	if cfg.NonceTTL < 0 {
		return nil, errors.New("endpoint: negative nonce TTL")
	}
	if cfg.NonceTTL == 0 {
		cfg.NonceTTL = 600
	}
	if cfg.Random == nil {
		cfg.Random = rand.Reader
	}
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
	return &Gate{
		cfg: cfg, docs: make(map[string]cachedDoc),
		pending: make(map[pair]nonceKey), nonces: make(map[nonceKey]nonceRecord),
	}, nil
}

func checkedPair(principal, canonicalURL string) (pair, urlcheck.URL, bool) {
	u, err := urlcheck.Check(canonicalURL)
	return pair{principal, u.Canonical}, u, principal != "" && err == nil
}

// Covers tries routes 1–4 in R5.2 order: cached verdict, allowlist, hook, then
// the origin's well-known document. A non-nil refusal leaves the challenge to
// the caller. New verdicts use ttl, defaulted and capped at one hour.
func (g *Gate) Covers(ctx context.Context, principal, canonicalURL string, ttl time.Duration) *Error {
	key, u, ok := checkedPair(principal, canonicalURL)
	if !ok {
		return challengeFailure("pair")
	}
	if g.cfg.Cache.Get(key.principal, key.url) {
		return nil
	}
	if _, ok := allowlistMatches(g.cfg.Allowlist, u); ok {
		g.cacheVerdict(key, ttl)
		return nil
	}
	if g.cfg.Hook != nil {
		if ok, err := g.cfg.Hook(ctx, key.principal, key.url); err == nil && ok {
			g.cacheVerdict(key, ttl)
			return nil
		}
	}
	doc, refusal := g.fetchDoc(ctx, wellKnownURL(u))
	if refusal != nil {
		return refusal
	}
	if _, ok := ReceiverDocCovers(doc, u.Path); !ok {
		return challengeFailure("no_route")
	}
	g.cacheVerdict(key, ttl)
	return nil
}

// Fresh reports whether the pair has an unexpired verdict, without network I/O.
func (g *Gate) Fresh(principal, canonicalURL string) bool {
	key, _, ok := checkedPair(principal, canonicalURL)
	return ok && g.cfg.Cache.Get(key.principal, key.url)
}

func (g *Gate) cacheVerdict(key pair, ttl time.Duration) {
	if ttl <= 0 || ttl > time.Hour {
		ttl = time.Hour
	}
	g.cfg.Cache.Put(key.principal, key.url, ttl)
}

// Begin issues 16 random bytes as a 22-character unpadded base64url nonce,
// replacing any pending nonce for the pair. Its age may not exceed NonceTTL.
// A nonce source failure or collision returns challenge_failed/random.
func (g *Gate) Begin(principal, canonicalURL string) (string, *Error) {
	key, _, ok := checkedPair(principal, canonicalURL)
	if !ok {
		return "", challengeFailure("pair")
	}
	g.nonceMu.Lock()
	defer g.nonceMu.Unlock()

	var value [16]byte
	if _, err := io.ReadFull(g.cfg.Random, value[:]); err != nil {
		return "", challengeFailure("random")
	}
	now := g.cfg.Now()
	g.pruneNonces(now)
	id := sha256.Sum256(value[:])
	if _, exists := g.nonces[id]; exists {
		return "", challengeFailure("random")
	}
	g.nonces[id] = nonceRecord{value: value, pair: key, issuedAt: now}
	// Replacing the pair index invalidates its previous nonce immediately.
	g.pending[key] = id
	return base64.RawURLEncoding.EncodeToString(value[:]), nil
}

// Accept verifies and consumes a nonce, then caches the verdict as in Covers.
// The caller must check the HTTP status and JSON body with ChallengeEcho.
func (g *Gate) Accept(principal, canonicalURL, nonce, echoed string, ttl time.Duration) *Error {
	key, _, ok := checkedPair(principal, canonicalURL)
	if !ok {
		return challengeFailure("pair")
	}
	sent, sentOK := decodeGateNonce(nonce)
	echo, echoOK := decodeGateNonce(echoed)
	if !sentOK || !echoOK {
		return challengeFailure("mismatch")
	}
	matchesSent := subtle.ConstantTimeCompare(sent[:], echo[:]) == 1
	// Index by a digest, but verify the decoded nonce bytes in constant time.
	id := sha256.Sum256(echo[:])

	g.nonceMu.Lock()
	defer g.nonceMu.Unlock()
	now := g.cfg.Now()
	g.pruneNonces(now)
	record, found := g.nonces[id]
	pendingID, pending := g.pending[record.pair]
	switch {
	case !found || subtle.ConstantTimeCompare(record.value[:], echo[:]) != 1:
		return challengeFailure("mismatch")
	case !record.consumed && (!pending || pendingID != id || (record.pair == key && !matchesSent)):
		return challengeFailure("mismatch")
	case g.nonceExpired(record, now):
		return challengeFailure("expired")
	case record.consumed:
		return challengeFailure("reused")
	case record.pair != key:
		return challengeFailure("pair")
	}
	record.consumed = true
	g.nonces[id] = record
	delete(g.pending, key)
	g.cacheVerdict(key, ttl)
	return nil
}

func decodeGateNonce(encoded string) ([16]byte, bool) {
	var value [16]byte
	if !NonceOK(encoded) {
		return value, false
	}
	n, err := base64.RawURLEncoding.Strict().Decode(value[:], []byte(encoded))
	return value, err == nil && n == len(value)
}

func (g *Gate) nonceExpired(record nonceRecord, now int64) bool {
	return now >= record.issuedAt && uint64(now)-uint64(record.issuedAt) > uint64(g.cfg.NonceTTL)
}

// Sweep lazily on nonce operations, at most once per clock second. Keep a
// bounded grace period (one more TTL) to distinguish expired echoes from
// unknown ones, even if another nonce operation already ran after expiry.
func (g *Gate) pruneNonces(now int64) {
	if g.lastPruneAt == now {
		return
	}
	g.lastPruneAt = now
	for id, record := range g.nonces {
		if now >= record.issuedAt && uint64(now)-uint64(record.issuedAt) > 2*uint64(g.cfg.NonceTTL) {
			if current, ok := g.pending[record.pair]; ok && current == id {
				delete(g.pending, record.pair)
			}
			delete(g.nonces, id)
		}
	}
}

func (g *Gate) fetchDoc(ctx context.Context, docURL string) ([]string, *Error) {
	now := time.Unix(g.cfg.Now(), 0)
	g.docMu.Lock()
	if cached, ok := g.docs[docURL]; ok {
		if now.Before(cached.expires) {
			g.docMu.Unlock()
			return slices.Clone(cached.receivers), nil
		}
		delete(g.docs, docURL)
	}
	g.docMu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, docURL, nil)
	if err != nil {
		return nil, &Error{Code: "document_fetch_failed", Reason: "request"}
	}
	res, refusal := g.cfg.Client.Do(req, MaxDocBytes)
	// A known HTTP status wins even when reading its body failed.
	if res != nil && res.Status != http.StatusOK {
		return CheckReceiverDocFetch(res.Status, "", MaxDocBytes)
	}
	if refusal != nil {
		switch refusal.Code {
		case "too_large":
			return nil, &Error{Code: "document_fetch_failed", Reason: "too_large"}
		case "redirect_refused":
			// The hardened client refuses redirects before returning a Response.
			if text, ok := strings.CutPrefix(refusal.Reason, "status_"); ok {
				if status, err := strconv.Atoi(text); err == nil && status >= 300 && status < 400 {
					return CheckReceiverDocFetch(status, "", MaxDocBytes)
				}
			}
		}
		return nil, challengeFailure("no_route")
	}
	receivers, invalid := CheckReceiverDocFetch(res.Status, string(res.Body), MaxDocBytes)
	if invalid != nil {
		return nil, invalid
	}
	if ttl := cacheControlTTL(res.Header); ttl > 0 {
		expires := time.Unix(g.cfg.Now(), 0).Add(time.Duration(ttl) * time.Second)
		g.docMu.Lock()
		g.docs[docURL] = cachedDoc{receivers: slices.Clone(receivers), expires: expires}
		g.docMu.Unlock()
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
