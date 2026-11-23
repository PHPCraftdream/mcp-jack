// Package receiver verifies and dispatches webhook deliveries in profile order.
package receiver

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"maps"
	"math"
	"strconv"
	"strings"
	"sync"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/card"
	"github.com/PHPCraftdream/mcp-jack/webhook/internal/dsig"
	"github.com/PHPCraftdream/mcp-jack/webhook/internal/secret"
	"github.com/PHPCraftdream/mcp-jack/webhook/internal/wire"
)

// Secret is a raw HMAC key and its binding. An empty SubscriptionID is pending.
type Secret struct {
	Key            []byte
	SubscriptionID string
	CallbackURL    string
}

// JackConfig enables w1 verification with the given audience and callback URLs.
// A zero Window uses the profile default.
type JackConfig struct {
	Aud          string
	Window       int64
	CallbackURLs map[string]string
}

// WebhookKeyCheck optionally requires agreement between the card and the tool.
type WebhookKeyCheck struct {
	Required   bool
	ToolResult json.RawMessage
}

// EnqueueFunc must durably store a message before returning nil. It runs for
// verification envelopes too, while the receiver serializes deliveries. It must
// not call back into that receiver.
type EnqueueFunc func(Message) error

// Config configures the receiver. Zero limits use the profile defaults, a nil
// Jack disables w1, and a nil Keys provides no verification keys. Enqueue is required.
type Config struct {
	Window, MaxBody, DedupRetention  int64
	EnforceServerIdentity            bool
	MCPServerKID, MCPServerPublicKey string
	Keys                             card.Source
	Secrets                          []Secret
	Routed                           []string
	Jack                             *JackConfig
	WebhookKey                       WebhookKeyCheck
	Enqueue                          EnqueueFunc
}

// Delivery holds the raw request and the current time in Unix seconds. Each
// header pair contributes one value, even when that value is the empty string.
type Delivery struct {
	Now     int64
	Headers [][2]string
	Body    []byte
}

// Message is the verified message passed to Enqueue.
type Message struct {
	SubscriptionID, WebhookID, Kind, Type, Challenge string
	Cursor                                           *string
	Raw                                              json.RawMessage
}

// Result holds the response and any forwarded message. Recorded reports
// whether this call recorded a webhook id, not whether it was seen previously.
type Result struct {
	Status    int
	Code      string
	Body      []byte
	Delivered []json.RawMessage
	Recorded  bool
}

// Receiver holds the in-memory state of one receiver. Construct it with New.
type Receiver struct {
	mu         sync.Mutex
	cfg        Config
	serverKID  string
	routed     map[string]struct{}
	terminated map[string]struct{}
	accepted   map[string]int64
}

// New initializes a receiver and copies mutable configuration, retaining the
// live key source. Secrets must supply raw key bytes, not a whsec_ string or a
// nil key.
func New(cfg Config) (*Receiver, error) {
	if cfg.Enqueue == nil {
		return nil, errors.New("receiver: Config.Enqueue is required")
	}
	if cfg.Keys == nil {
		cfg.Keys = card.Static{}
	}
	cfg.Window = defaultIfZero(cfg.Window, wire.DefaultWindowSeconds)
	cfg.MaxBody = defaultIfZero(cfg.MaxBody, wire.MaxBodyBytes)
	cfg.DedupRetention = defaultIfZero(cfg.DedupRetention, wire.DedupRetentionSeconds)
	if cfg.Jack != nil {
		jack := *cfg.Jack
		jack.Window = defaultIfZero(jack.Window, wire.DefaultJackWindowSeconds)
		jack.CallbackURLs = maps.Clone(jack.CallbackURLs)
		cfg.Jack = &jack
	}
	cfg.WebhookKey.ToolResult = bytes.Clone(cfg.WebhookKey.ToolResult)
	secrets := make([]Secret, len(cfg.Secrets))
	for i, entry := range cfg.Secrets {
		if entry.Key == nil {
			return nil, errors.New("receiver: secret must supply raw key bytes")
		}
		entry.Key = bytes.Clone(entry.Key)
		secrets[i] = entry
	}
	cfg.Secrets = secrets

	serverKID := cfg.MCPServerKID
	if serverKID == "" {
		serverKID = serverKidOf(cfg.MCPServerPublicKey)
	}
	routed := make(map[string]struct{}, len(cfg.Routed))
	for _, id := range cfg.Routed {
		routed[id] = struct{}{}
	}
	cfg.Routed = nil
	return &Receiver{
		cfg: cfg, serverKID: serverKID, routed: routed,
		terminated: make(map[string]struct{}), accepted: make(map[string]int64),
	}, nil
}

func defaultIfZero(value, fallback int64) int64 {
	if value == 0 {
		return fallback
	}
	return value
}

func serverKidOf(publicKey string) string {
	if publicKey != "" {
		if raw, ok := secret.DecodeURL(publicKey); ok {
			digest := sha256.Sum256(raw)
			return secret.EncodeURL(digest[:])
		}
	}
	return ""
}

// asymmetricKeys preserves input order and excludes the MCP response key.
func asymmetricKeys(keys []card.Key, serverKID, serverPublicKey string) []dsig.AsymKey {
	accepted := make([]dsig.AsymKey, 0, len(keys))
	for _, key := range keys {
		if serverKID != "" && key.KID == serverKID {
			continue
		}
		if key.Raw == nil {
			encoded := key.X
			if encoded == "" {
				encoded = key.PublicKey
			}
			key.Raw, _ = secret.DecodeURL(encoded)
		}
		if serverPublicKey != "" && (key.PublicKey == serverPublicKey || secret.EncodeURL(key.Raw) == serverPublicKey) {
			continue
		}
		accepted = append(accepted, dsig.AsymKey{KID: key.KID, Raw: key.Raw})
	}
	return accepted
}

const (
	headerID           = "webhook-id"
	headerTimestamp    = "webhook-timestamp"
	headerSignature    = "webhook-signature"
	headerSubscription = "x-mcp-subscription-id"
	headerJack         = "jack-webhook-auth"
	headerLength       = "content-length"
)

var requiredHeaders = [...]string{headerID, headerTimestamp, headerSignature, headerSubscription}

func collectHeaders(pairs [][2]string) map[string][]string {
	values := make(map[string][]string)
	for _, pair := range pairs {
		name := strings.ToLower(pair[0])
		values[name] = append(values[name], pair[1])
	}
	return values
}

func validDeclaredLength(value string, maxBody int64) bool {
	if value == "" {
		return false
	}
	for i := range len(value) {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	length, err := strconv.ParseInt(value, 10, 64)
	return err == nil && length <= maxBody
}

// differenceExceeds compares a-b to a signed limit without int64 overflow.
func differenceExceeds(a, b, limit int64) bool {
	if b > 0 && a < math.MinInt64+b {
		return false
	}
	if b < 0 && a > math.MaxInt64+b {
		return true
	}
	return a-b > limit
}

// Handle authenticates and processes a delivery, stopping at the first failure.
func (r *Receiver) Handle(d Delivery) Result {
	r.mu.Lock()
	defer r.mu.Unlock()

	snapshot := r.cfg.Keys.KeySet()
	all := collectHeaders(d.Headers)
	for _, name := range requiredHeaders { // R3.1: absence before duplication.
		if len(all[name]) == 0 {
			return reject("missing_webhook_header")
		}
	}
	for _, name := range requiredHeaders {
		if len(all[name]) > 1 {
			return reject("duplicate_webhook_header")
		}
	}
	id, timestamp, sub := all[headerID][0], all[headerTimestamp][0], all[headerSubscription][0]
	if !wire.ValidWebhookID(id) {
		return reject("malformed_webhook_id")
	}
	if !wire.ValidTimestamp(timestamp) {
		return reject("malformed_webhook_timestamp")
	}
	if !wire.ValidSubscriptionID(sub) {
		return reject("malformed_subscription_id")
	}
	if int64(len(d.Body)) > r.cfg.MaxBody {
		return reject("body_too_large")
	}
	if values := all[headerLength]; len(values) > 0 && !validDeclaredLength(values[0], r.cfg.MaxBody) {
		return reject("body_too_large")
	}

	candidates, deferred := r.candidates(sub)
	if len(candidates) == 0 {
		return reject("unknown_subscription")
	}
	_, routed := r.routed[sub]
	_, terminated := r.terminated[sub]
	if !deferred && !routed && !terminated {
		return reject("subscription_not_routed")
	}

	entries, code := dsig.ParseHeader(all[headerSignature][0])
	if code != "" {
		return reject(code)
	}
	if code := dsig.CheckSchemes(entries); code != "" {
		return reject(code)
	}
	entries, code = dsig.DecodeValues(entries)
	if code != "" {
		return reject(code)
	}
	keys := make([][]byte, len(candidates))
	for i, candidate := range candidates {
		keys[i] = candidate.Key
	}
	matched, ok := dsig.VerifyV1(entries, keys, id, timestamp, d.Body)
	if !ok {
		return reject("bad_signature")
	}
	seconds, _ := wire.ParseTimestamp(timestamp) // Grammar already checked.
	if differenceExceeds(d.Now, seconds, r.cfg.Window) {
		return reject("stale_timestamp")
	}
	if differenceExceeds(seconds, d.Now, r.cfg.Window) {
		return reject("future_timestamp")
	}
	asymKeys := asymmetricKeys(snapshot.Accepted, r.cfg.MCPServerKID, r.cfg.MCPServerPublicKey)
	if r.cfg.EnforceServerIdentity {
		if len(asymKeys) == 0 {
			return reject("no_server_keys")
		}
		if _, code := dsig.VerifyAsym(entries, asymKeys, sub, id, timestamp, d.Body); code != "" {
			return reject(code)
		}
	}
	if jack := r.cfg.Jack; jack != nil {
		values := all[headerJack]
		if len(values) == 0 {
			return reject("missing_jack_auth")
		}
		callback := jack.CallbackURLs[sub]
		if deferred {
			callback = candidates[matched].CallbackURL
		}
		parts := dsig.W1Parts{
			Aud: jack.Aud, SubscriptionID: sub, WebhookID: id, Timestamp: timestamp,
			CallbackURL: callback, Body: d.Body,
		}
		keys := dsig.W1Keys{Keys: asymKeys, Now: d.Now, Window: jack.Window, MCPServerKID: r.serverKID}
		if _, code := dsig.W1Verify(values[0], parts, keys); code != "" {
			return reject(code)
		}
		if callback == "" {
			return reject("bad_jack_signature")
		}
	}
	if check := r.cfg.WebhookKey; check.Required {
		if code := card.CrossCheckWebhookKey(snapshot.Raw, check.ToolResult, true); code != "" {
			return reject(code)
		}
	}

	if at, seen := r.accepted[id]; seen && !differenceExceeds(d.Now, at, r.cfg.DedupRetention) {
		return Result{Status: 200, Body: []byte(`{"status":"duplicate"}`)}
	}
	message, code := wire.Parse(d.Body)
	if code != "" {
		return reject(code)
	}
	if terminated {
		return reject("subscription_terminated")
	}
	queued := Message{
		SubscriptionID: sub, WebhookID: id, Kind: message.Kind, Type: message.Type,
		Challenge: message.Challenge, Cursor: message.Cursor, Raw: bytes.Clone(message.Raw),
	}
	if err := r.cfg.Enqueue(queued); err != nil {
		return reject("enqueue_failed")
	}
	if deferred && message.Kind != wire.KindVerification {
		return reject("subscription_not_routed")
	}

	r.accepted[id] = d.Now
	if message.Kind == wire.KindVerification {
		if deferred {
			candidates[matched].SubscriptionID = sub
			r.routed[sub] = struct{}{}
		}
		// wire.Parse restricts the challenge to the base64url alphabet.
		return Result{Status: 200, Body: []byte(`{"challenge":"` + message.Challenge + `"}`), Recorded: true}
	}
	if message.Kind == wire.KindTerminated {
		r.terminated[sub] = struct{}{}
		delete(r.routed, sub)
	}
	return Result{
		Status: 200, Body: []byte(`{"status":"accepted"}`), Recorded: true,
		Delivered: []json.RawMessage{message.Raw},
	}
}

// candidates returns the first registered secret, or every pending secret in
// configuration order. Its pointers also allow a challenge to bind the match.
func (r *Receiver) candidates(sub string) (entries []*Secret, deferred bool) {
	for i := range r.cfg.Secrets {
		entry := &r.cfg.Secrets[i]
		if entry.SubscriptionID == sub {
			return []*Secret{entry}, false
		}
		if entry.SubscriptionID == "" {
			entries = append(entries, entry)
		}
	}
	return entries, true
}
