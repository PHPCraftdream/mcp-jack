package card

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"unicode"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/ipaddr"
	"github.com/PHPCraftdream/mcp-jack/webhook/internal/urlcheck"
)

const (
	MaxCardBytes   = 65536
	MaxCardTTL     = 300
	DefaultCardTTL = 300
)

// FetchInput is the metadata and body of a Server Card fetch. Header names
// must be normalized to lowercase.
type FetchInput struct {
	MCPURL, CardURL string
	Status          int
	Headers         map[string]string
	Body            []byte
	ElapsedMS       *int64
	Options         Options
}

// EgressRange is one validated advisory egress CIDR.
type EgressRange struct {
	CIDR, Family string
	Prefix       int
}

// FetchResult contains the accepted keys and ranges, discarded keys, and cache
// lifetime in seconds.
type FetchResult struct {
	Keys     []Key
	Egress   []EgressRange
	Rejected []Rejected
	CacheTTL int64
}

// FetchError contains the first refusal code and its reason.
type FetchError struct {
	Code, Reason string
}

// FetchDecision checks a completed fetch and extracts the selected remote's keys.
func FetchDecision(in FetchInput) (FetchResult, *FetchError) {
	cardURL, err := urlcheck.Check(in.CardURL)
	if err != nil {
		reason := err.Reason
		if reason == "" {
			reason = err.Code
		}
		return FetchResult{}, &FetchError{Code: "not_https", Reason: reason}
	}
	// Check only accepts HTTPS.
	mcpURL, err := urlcheck.Check(in.MCPURL)
	if err != nil || !sameOrigin(cardURL, mcpURL) {
		return FetchResult{}, &FetchError{Code: "cross_origin", Reason: "origin_mismatch"}
	}
	if in.Status >= 300 && in.Status <= 399 {
		return FetchResult{}, &FetchError{Code: "redirect_refused", Reason: "redirect"}
	}
	if in.Status < 200 || in.Status > 299 {
		return FetchResult{}, &FetchError{Code: "http_status", Reason: "status"}
	}
	if in.ElapsedMS != nil && *in.ElapsedMS > 10000 {
		return FetchResult{}, &FetchError{Code: "timeout", Reason: "elapsed"}
	}
	if len(in.Body) > MaxCardBytes {
		return FetchResult{}, &FetchError{Code: "too_large", Reason: "body"}
	}
	if !json.Valid(in.Body) {
		return FetchResult{}, &FetchError{Code: "bad_json", Reason: "json"}
	}
	if bytes.TrimLeft(in.Body, " \t\r\n")[0] != '{' {
		return FetchResult{}, &FetchError{Code: "bad_json", Reason: "shape"}
	}
	info, code := WebhookInfo(in.Body, in.MCPURL)
	if code != "" {
		return FetchResult{}, &FetchError{Code: code, Reason: "no_remote"}
	}
	keys, rejected := AcceptJWKSet(jsonArray(jsonObject(info.SigningKeys)["keys"]), in.Options)
	egress, _ := ParseCIDRList(info.Egress)
	return FetchResult{Keys: keys, Egress: egress, Rejected: rejected, CacheTTL: CardCacheTTL(in.Headers)}, nil
}

// ParseCIDRList splits input into valid egress ranges and malformed texts.
func ParseCIDRList(values []string) (accepted []EgressRange, rejected []string) {
	for _, text := range values {
		if parsed, ok := ipaddr.ParseCIDR(text); ok {
			accepted = append(accepted, EgressRange{CIDR: text, Family: parsed.Family, Prefix: parsed.Prefix})
		} else {
			rejected = append(rejected, text)
		}
	}
	return accepted, rejected
}

// CardCacheTTL uses the first exact max-age directive, capped at MaxCardTTL.
func CardCacheTTL(headers map[string]string) int64 {
	for part := range strings.SplitSeq(headers["cache-control"], ",") {
		digits, ok := strings.CutPrefix(strings.TrimFunc(part, cacheSpace), "max-age=")
		if !ok || digits == "" || strings.IndexFunc(digits, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
			continue
		}
		// On overflow ParseUint returns the maximum uint64, which also caps.
		age, _ := strconv.ParseUint(digits, 10, 64)
		return int64(min(age, MaxCardTTL))
	}
	return DefaultCardTTL
}

// cacheSpace matches the reference's JavaScript String.trim whitespace.
func cacheSpace(r rune) bool {
	return (r >= '\t' && r <= '\r') || r == '\uFEFF' || r == '\u2028' || r == '\u2029' || unicode.Is(unicode.Zs, r)
}
