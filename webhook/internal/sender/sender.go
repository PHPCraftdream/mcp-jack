// Package sender signs and delivers mcp-jack webhook messages over HTTPS.
package sender

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"reflect"
	"strconv"
	"time"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/delivery"
	"github.com/PHPCraftdream/mcp-jack/webhook/internal/endpoint"
	"github.com/PHPCraftdream/mcp-jack/webhook/internal/wire"
)

const (
	maxResponseBody = 65536
	suspensionPoll  = 1 // seconds, only when a suspension hook is configured
)

// VerificationGate is the endpoint verification front-end of R5.1-R5.9.
// Begin returns an unpadded base64url nonce on success. Fresh reports the
// cached verdict without network I/O, and Transport exposes the hardened
// client the gate fetches the well-known document with.
type VerificationGate interface {
	Covers(ctx context.Context, principal, canonicalURL string, ttl time.Duration) *endpoint.Error
	Begin(principal, canonicalURL string) (string, *endpoint.Error)
	Accept(principal, canonicalURL, nonce, echoed string, ttl time.Duration) *endpoint.Error
	Fresh(principal, canonicalURL string) bool
	Transport() *delivery.Client
}

// Config supplies signing material, verification and optional scheduling hooks.
// The verification gate also supplies the delivery transport, so there is no
// separate policy to keep in sync: the well-known fetch and the deliveries
// share one hardened client by construction.
type Config struct {
	Signing SigningOptions
	// Verifier is required and supplies the delivery client.
	Verifier VerificationGate
	// Now defaults to Unix wall seconds.
	Now func() int64
	// Sleep defaults to a context-aware timer.
	Sleep func(ctx context.Context, d time.Duration) error
	// Suspended is optional and polled while waiting to attempt a delivery.
	Suspended func() bool
}

type deliveryClient interface {
	Do(req *http.Request, maxBody int64) (*delivery.Response, *delivery.Error)
}

// Sender performs signed webhook attempts and runs the retry schedule.
type Sender struct {
	client    deliveryClient
	verifier  VerificationGate
	signing   SigningOptions
	now       func() int64
	sleep     func(context.Context, time.Duration) error
	suspended func() bool
}

// New constructs a sender that reuses the verification gate's hardened
// delivery client. The gate supplies the transport (via Transport), so the
// well-known fetch and the deliveries share one policy by construction.
func New(cfg Config) (*Sender, error) {
	if nilVerifier(cfg.Verifier) {
		return nil, errors.New("sender requires an endpoint verification gate")
	}
	client := cfg.Verifier.Transport()
	if client == nil {
		return nil, errors.New("sender requires the verifier's delivery client")
	}
	signing, err := prepareSigning(cfg.Signing)
	if err != nil {
		return nil, err
	}
	if cfg.Now == nil {
		cfg.Now = func() int64 { return time.Now().Unix() }
	}
	if cfg.Sleep == nil {
		cfg.Sleep = sleepContext
	}
	return &Sender{
		client:   client,
		verifier: cfg.Verifier, signing: signing, now: cfg.Now, sleep: cfg.Sleep, suspended: cfg.Suspended,
	}, nil
}

func nilVerifier(g VerificationGate) bool {
	v := reflect.ValueOf(g)
	switch v.Kind() {
	case reflect.Invalid:
		return true
	case reflect.Chan, reflect.Func, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}

func (s *Sender) ensureVerified(ctx context.Context, msg Message) *endpoint.Error {
	if s.verifier == nil {
		return &endpoint.Error{Code: "challenge_failed", Reason: "missing_verifier"}
	}
	if msg.Principal == "" || msg.CallbackURL == "" || msg.SubscriptionID == "" {
		return &endpoint.Error{Code: "challenge_failed", Reason: "pair"}
	}
	if s.verifier.Covers(ctx, msg.Principal, msg.CallbackURL, msg.TTL) == nil {
		return nil
	}

	nonce, refusal := s.verifier.Begin(msg.Principal, msg.CallbackURL)
	if refusal != nil {
		return refusal
	}
	id, err := NewWebhookID("verification", rand.Reader)
	if err != nil {
		return &endpoint.Error{Code: "challenge_failed", Reason: "random"}
	}
	challenge := msg
	challenge.WebhookID = id
	challenge.Body = []byte(`{"type":"verification","challenge":"` + nonce + `"}`)
	req, code := s.signing.request(ctx, challenge, s.now())
	if code != "" {
		return &endpoint.Error{Code: "challenge_failed", Reason: code}
	}

	res, deliveryErr := s.client.Do(req, endpoint.MaxChallengeBytes)
	// A returned non-2xx status fails the echo even if its body could not be read.
	if res != nil && (res.Status < 200 || res.Status > 299) {
		return endpoint.ChallengeEcho(res.Status, "", nonce)
	}
	if deliveryErr != nil {
		if deliveryErr.Code == "too_large" {
			// The client discards the body. Preserve ChallengeEcho's size refusal.
			return &endpoint.Error{Code: "challenge_failed", Reason: "too_large"}
		}
		return &endpoint.Error{Code: transportCategory(deliveryErr.Code), Reason: deliveryErr.Code}
	}
	if res == nil {
		return &endpoint.Error{Code: "connection_refused"}
	}
	if refusal := endpoint.ChallengeEcho(res.Status, string(res.Body), nonce); refusal != nil {
		return refusal
	}
	// ChallengeEcho proves the decoded echo equals nonce, so no second parse is needed.
	return s.verifier.Accept(msg.Principal, msg.CallbackURL, nonce, nonce, msg.TTL)
}

// AttemptResult reports the HTTP status or an internal refusal code. LastError
// is the profile's public category and never includes raw endpoint data.
type AttemptResult struct {
	Status          int
	Code, LastError string
	RetryAfter      int64
	HasRetryAfter   bool
}

// Attempt verifies the endpoint, then makes one delivery attempt with a fresh
// timestamp and signature. It does not wait for suspension or retry.
func (s *Sender) Attempt(ctx context.Context, msg Message) AttemptResult {
	if refusal := s.ensureVerified(ctx, msg); refusal != nil {
		return AttemptResult{Code: refusal.Code, LastError: refusal.Code}
	}
	return s.attemptVerified(ctx, msg)
}

func (s *Sender) attemptVerified(ctx context.Context, msg Message) AttemptResult {
	if len(msg.Body) > wire.MaxBodyBytes {
		return AttemptResult{Code: "body_too_large", LastError: "http_4xx"}
	}
	req, code := s.signing.request(ctx, msg, s.now())
	if code != "" {
		return AttemptResult{Code: code, LastError: "http_4xx"}
	}
	response, err := s.client.Do(req, maxResponseBody)
	// Once the status arrives, R1.7 classifies the delivery by it, not the body.
	if response == nil {
		if err == nil {
			return AttemptResult{Code: "connection_refused", LastError: "connection_refused"}
		}
		return AttemptResult{Code: err.Code, LastError: transportCategory(err.Code)}
	}
	category := LastError(response.Status)
	if category == "" && (response.Status < 200 || response.Status > 299) {
		category = "http_4xx"
	}
	retryAfter, hasRetryAfter := parseRetryAfter(response.Header.Get("Retry-After"))
	return AttemptResult{Status: response.Status, LastError: category, RetryAfter: retryAfter, HasRetryAfter: hasRetryAfter}
}

func transportCategory(code string) string {
	switch code {
	case "connection_refused", "timeout", "tls_error", "challenge_failed":
		return code
	case "blocked_address", "dns_rebinding", "no_answer":
		return "connection_refused"
	default: // Includes redirect_refused, which the client returns without a status.
		return "http_4xx"
	}
}

func parseRetryAfter(value string) (int64, bool) {
	if value == "" {
		return 0, false
	}
	for i := range len(value) {
		if value[i] < '0' || value[i] > '9' {
			return 0, false
		}
	}
	// ParseInt saturates an out-of-range decimal; the schedule caps it further.
	seconds, _ := strconv.ParseInt(value, 10, 64)
	return seconds, true
}

// Result describes the last attempt made by Deliver, if any.
type Result struct {
	Accepted  bool
	Attempts  int
	LastError string
	Status    int
}

// Deliver verifies the endpoint before running the R1.8 schedule with the same
// message ID and bytes each time. Verification is re-checked before every
// attempt, so an expired pair ends the delivery unverified instead of receiving
// a late retry.
func (s *Sender) Deliver(ctx context.Context, msg Message) Result {
	if refusal := s.ensureVerified(ctx, msg); refusal != nil {
		return Result{LastError: refusal.Code}
	}
	var result Result
	start := s.now()
	clock := scheduleClock{wall: start, active: start}
	next := start
	var capAt int64
	for attempt := 1; attempt <= wire.MaxAttempts; attempt++ {
		if !s.waitUntil(ctx, &clock, next) {
			return result
		}
		// A verdict can expire while the sender waits; every attempt, including
		// the first, needs a fresh one or the pair is no longer consented.
		if !s.verifier.Fresh(msg.Principal, msg.CallbackURL) {
			return Result{LastError: "challenge_failed"}
		}
		if attempt == 1 {
			start = clock.active
			capAt = addSeconds(start, wire.RetryCapSeconds)
		} else if clock.active > capAt {
			return result
		}
		res := s.attemptVerified(ctx, msg)
		clock.advance(s.now(), 0)
		result = Result{Attempts: attempt, Status: res.Status, LastError: res.LastError}
		in := AttemptInput{
			Status: res.Status, Attempt: attempt, T0: start, ResponseTime: clock.active,
			RetryAfter: res.RetryAfter, HasRetryAfter: res.HasRetryAfter,
		}
		switch res.Code {
		case "": // HTTP response
		case "connection_refused", "no_answer", "timeout", "tls_error", "challenge_failed":
			in.Transport = res.LastError
		default:
			// In particular, R1.9 makes blocked addresses, rebinding and
			// refused redirects final even though Decide models transports.
			return result
		}
		out := Decide(in)
		switch out.Action {
		case "accept":
			result.Accepted = true
			return result
		case "final":
			return result
		case "retry":
			next = out.NextAt
		}
	}
	return result
}

// scheduleClock records time elapsed outside of observed suspension. The wall
// clock is still used directly for each attempt's signed timestamp.
type scheduleClock struct{ wall, active int64 }

func (c *scheduleClock) advance(now, waited int64) {
	c.active = addSeconds(c.active, max(waited, now-c.wall))
	c.wall = now
}

func (s *Sender) waitUntil(ctx context.Context, clock *scheduleClock, target int64) bool {
	var waited int64
	for ctx.Err() == nil {
		if s.suspended != nil && s.suspended() {
			if s.sleep(ctx, suspensionPoll*time.Second) != nil {
				return false
			}
			clock.wall = s.now() // discard the interval that overlaps observed suspension
			waited = 0
			continue
		}
		clock.advance(s.now(), waited)
		if clock.active >= target {
			return true
		}
		waited = target - clock.active
		if s.suspended != nil {
			waited = min(waited, suspensionPoll)
		}
		if s.sleep(ctx, time.Duration(waited)*time.Second) != nil {
			return false
		}
	}
	return false
}

func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
