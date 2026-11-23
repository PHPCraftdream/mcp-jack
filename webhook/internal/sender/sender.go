// Package sender signs and delivers mcp-jack webhook messages over HTTPS.
package sender

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/delivery"
	"github.com/PHPCraftdream/mcp-jack/webhook/internal/wire"
)

const (
	maxResponseBody = 65536
	suspensionPoll  = 1 // seconds, only when a suspension hook is configured
)

// Config supplies signing material, the delivery policy and optional scheduling hooks.
type Config struct {
	Signing       SigningOptions
	AllowedRanges []string
	Resolver      delivery.Resolver
	Dialer        delivery.Dialer
	Now           func() int64                                     // defaults to Unix wall seconds
	Sleep         func(ctx context.Context, d time.Duration) error // defaults to a context-aware timer
	Suspended     func() bool                                      // optional; polled while waiting to attempt a delivery
}

type deliveryClient interface {
	Do(req *http.Request, maxBody int64) (*delivery.Response, *delivery.Error)
}

// Sender performs signed webhook attempts and runs the retry schedule.
type Sender struct {
	client    deliveryClient
	signing   SigningOptions
	now       func() int64
	sleep     func(context.Context, time.Duration) error
	suspended func() bool
}

// New constructs a sender with a dedicated, policy-enforcing delivery client.
func New(cfg Config) (*Sender, error) {
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
		client: delivery.NewClient(delivery.Config{
			AllowedRanges: cfg.AllowedRanges, Resolver: cfg.Resolver, Dialer: cfg.Dialer,
		}),
		signing: signing, now: cfg.Now, sleep: cfg.Sleep, suspended: cfg.Suspended,
	}, nil
}

// AttemptResult reports the HTTP status or an internal refusal code. LastError
// is the profile's public category and never includes raw endpoint data.
type AttemptResult struct {
	Status          int
	Code, LastError string
	RetryAfter      int64
	HasRetryAfter   bool
}

// Attempt makes one delivery attempt with a fresh timestamp and signature.
// It does not wait for suspension or retry.
func (s *Sender) Attempt(ctx context.Context, msg Message) AttemptResult {
	if len(msg.Body) > wire.MaxBodyBytes {
		return AttemptResult{Code: "body_too_large", LastError: "http_4xx"}
	}
	req, code := s.signing.request(ctx, msg, s.now())
	if code != "" {
		return AttemptResult{Code: code, LastError: "http_4xx"}
	}
	response, err := s.client.Do(req, maxResponseBody)
	if err != nil {
		category := "http_4xx"
		switch err.Code {
		case "connection_refused", "timeout", "tls_error", "challenge_failed":
			category = err.Code
		case "blocked_address", "dns_rebinding", "no_answer":
			category = "connection_refused"
		}
		return AttemptResult{Code: err.Code, LastError: category}
	}
	category := LastError(response.Status)
	if category == "" && (response.Status < 200 || response.Status > 299) {
		category = "http_4xx"
	}
	retryAfter, hasRetryAfter := parseRetryAfter(response.Header.Get("Retry-After"))
	return AttemptResult{Status: response.Status, LastError: category, RetryAfter: retryAfter, HasRetryAfter: hasRetryAfter}
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

// Deliver runs the R1.8 schedule using the same message ID and bytes each time.
func (s *Sender) Deliver(ctx context.Context, msg Message) Result {
	var result Result
	start := s.now()
	clock := scheduleClock{wall: start, active: start}
	next := start
	var capAt int64
	for attempt := 1; attempt <= wire.MaxAttempts; attempt++ {
		if !s.waitUntil(ctx, &clock, next) {
			return result
		}
		if attempt == 1 {
			start = clock.active
			capAt = addSeconds(start, wire.RetryCapSeconds)
		} else if clock.active > capAt {
			return result
		}
		res := s.Attempt(ctx, msg)
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
