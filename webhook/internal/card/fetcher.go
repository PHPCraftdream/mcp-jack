package card

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/delivery"
)

const cardMediaType = "application/mcp-server-card+json"

// FetcherConfig configures live discovery for one MCP origin.
type FetcherConfig struct {
	Client  *delivery.Client
	MCPURL  string
	CardURL string // Defaults to DefaultCardURL(MCPURL).
	Options Options
	Now     func() int64 // Unix seconds; nil uses the wall clock.
}

// Fetcher caches the most recent successful Server Card lookup.
type Fetcher struct {
	client          *delivery.Client
	mcpURL, cardURL string
	options         Options
	now             func() time.Time

	mu      sync.RWMutex
	keys    KeySet
	expires time.Time
}

var _ Source = (*Fetcher)(nil)
var _ Source = Static{}

// NewFetcher validates the configuration without making a request.
func NewFetcher(cfg FetcherConfig) (*Fetcher, error) {
	if cfg.Client == nil {
		return nil, errors.New("card: delivery client is required")
	}
	if cfg.CardURL == "" {
		var ok bool
		if cfg.CardURL, ok = DefaultCardURL(cfg.MCPURL); !ok {
			return nil, &FetchError{Code: "not_https", Reason: "invalid_mcp_url"}
		}
	}
	if err := checkFetchOrigin(cfg.MCPURL, cfg.CardURL); err != nil {
		return nil, err
	}
	// The reference URL checker does not check all percent escapes that Go's
	// request parser requires. Refuse URLs it cannot parse before doing I/O.
	if _, err := url.Parse(cfg.MCPURL); err != nil {
		return nil, &FetchError{Code: "not_https", Reason: "invalid_mcp_url"}
	}
	if _, err := url.Parse(cfg.CardURL); err != nil {
		return nil, &FetchError{Code: "not_https", Reason: "invalid_card_url"}
	}
	now := time.Now
	if cfg.Now != nil {
		now = func() time.Time { return time.Unix(cfg.Now(), 0) }
	}
	return &Fetcher{client: cfg.Client, mcpURL: cfg.MCPURL, cardURL: cfg.CardURL, options: cfg.Options, now: now}, nil
}

// KeySet returns an independent copy of the last successful snapshot while its
// cache lifetime lasts, and the empty set once that lifetime has passed. An
// expired snapshot must not be trusted: a failed Refresh leaves the previous
// keys usable only until their expiry, and a successful Refresh restores them.
// It does not wait for an in-flight fetch.
func (f *Fetcher) KeySet() KeySet {
	f.mu.RLock()
	keys, expires := f.keys, f.expires
	f.mu.RUnlock()
	if expires.IsZero() || !f.now().Before(expires) {
		return KeySet{}
	}
	return keys.clone()
}

// TTL returns the remaining cache lifetime or zero if stale or absent.
func (f *Fetcher) TTL() time.Duration {
	f.mu.RLock()
	expires := f.expires
	f.mu.RUnlock()
	if expires.IsZero() {
		return 0
	}
	return max(0, expires.Sub(f.now()))
}

// Refresh fetches and validates a card. Refusals leave the snapshot and its
// expiry untouched.
func (f *Fetcher) Refresh(ctx context.Context) *FetchError {
	if err := checkFetchOrigin(f.mcpURL, f.cardURL); err != nil {
		return err
	}
	start := time.Now()
	ctx, cancel := context.WithDeadline(ctx, start.Add(maxFetchMS*time.Millisecond))
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.cardURL, nil)
	if err != nil {
		return &FetchError{Code: "not_https", Reason: "invalid_card_url"}
	}
	req.Header.Set("Accept", cardMediaType)
	res, refused := f.client.Do(req, MaxCardBytes)
	elapsed := (time.Since(start) + time.Millisecond - 1).Milliseconds()
	if refused != nil {
		// A read error may accompany a response with no body. In particular,
		// an oversized body must not be treated as an empty HTTP response.
		switch refused.Code {
		case "redirect_refused":
			return &FetchError{Code: "redirect_refused", Reason: "redirect"}
		case "too_large":
			return &FetchError{Code: "too_large", Reason: "body"}
		case "timeout":
			return &FetchError{Code: "timeout", Reason: "elapsed"}
		}
		if res != nil {
			if refusal := checkFetchStatus(res.Status); refusal != nil {
				return refusal
			}
		}
		return &FetchError{Code: refused.Code, Reason: refused.Reason}
	}
	fetchedAt := f.now()
	result, refusal := FetchDecision(FetchInput{
		MCPURL: f.mcpURL, CardURL: f.cardURL, Status: res.Status, Body: res.Body,
		Headers:   map[string]string{"cache-control": strings.Join(res.Header.Values("Cache-Control"), ",")},
		ElapsedMS: &elapsed, Options: f.options,
	})
	if refusal != nil {
		return refusal
	}
	f.mu.Lock()
	f.keys = result.Keys
	f.expires = fetchedAt.Add(time.Duration(result.CacheTTL) * time.Second)
	f.mu.Unlock()
	return nil
}
