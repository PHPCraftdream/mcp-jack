// Package stream implements the server side of the signed streams profile
// (spec 05 sections 1-3): the Jack-Accept opt-in, the open header and the
// signed frame chain of an accepted response stream.
package stream

import (
	"errors"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultFrameMaxBytes is frameMaxBytes of 3.2 when the caller sets none.
	DefaultFrameMaxBytes int64 = 1 << 20
	// MinFrameMaxBytes is the smallest legal frameMaxBytes of 3.2.
	MinFrameMaxBytes int64 = 1024
	// DefaultMaxConcurrentStreams is maxConcurrentStreams of 3.3.
	DefaultMaxConcurrentStreams = 4
	// DefaultMaxStreamDuration is maxStreamDurationMs of 3.4.
	DefaultMaxStreamDuration = time.Hour
	// DefaultWindow is W of spec 01 section 4.
	DefaultWindow = 30 * time.Second
)

// Options configures the server signer of spec 05 section 3. The zero value
// means the defaults of that section.
type Options struct {
	// FrameMaxBytes bounds the data value of one message frame (3.2); zero
	// means DefaultFrameMaxBytes.
	FrameMaxBytes int64
	// MaxConcurrentStreams is the per-identity stream limit (3.3); zero means
	// DefaultMaxConcurrentStreams.
	MaxConcurrentStreams int
	// MaxStreamDuration is the maximum stream duration (3.4); zero means
	// DefaultMaxStreamDuration.
	MaxStreamDuration time.Duration
	// Heartbeat is the heartbeat the deployment wants granted (3.5); Normalize
	// clamps it to floor(W * 500) milliseconds.
	Heartbeat time.Duration
}

// Validate rejects settings the profile does not admit. A zero value is valid
// and means the default.
func (o Options) Validate() error {
	if o.FrameMaxBytes != 0 && o.FrameMaxBytes < MinFrameMaxBytes {
		return errors.New("server: stream FrameMaxBytes must be at least 1024")
	}
	if o.MaxConcurrentStreams < 0 {
		return errors.New("server: stream MaxConcurrentStreams must not be negative")
	}
	if o.MaxStreamDuration < 0 {
		return errors.New("server: stream MaxStreamDuration must not be negative")
	}
	if o.Heartbeat < 0 {
		return errors.New("server: stream Heartbeat must not be negative")
	}
	return nil
}

// Normalize fills every zero value with its default and clamps Heartbeat to the
// grant of 3.5 for the given verification window.
func (o Options) Normalize(window time.Duration) Options {
	if o.FrameMaxBytes == 0 {
		o.FrameMaxBytes = DefaultFrameMaxBytes
	}
	if o.MaxConcurrentStreams == 0 {
		o.MaxConcurrentStreams = DefaultMaxConcurrentStreams
	}
	if o.MaxStreamDuration == 0 {
		o.MaxStreamDuration = DefaultMaxStreamDuration
	}
	o.Heartbeat = GrantHeartbeat(o.Heartbeat, window)
	return o
}

// GrantHeartbeat returns the heartbeat grant of 3.5: at most
// floor(W * 500) milliseconds, and the maximum when the request is zero or
// negative.
func GrantHeartbeat(requested, window time.Duration) time.Duration {
	if window <= 0 {
		window = DefaultWindow
	}
	maxMillis := int64(window/time.Millisecond) / 2
	if maxMillis < 0 {
		maxMillis = 0
	}
	requestedMillis := int64(requested / time.Millisecond)
	if requested <= 0 || requestedMillis > maxMillis {
		requestedMillis = maxMillis
	}
	return time.Duration(requestedMillis) * time.Millisecond
}

// AcceptsS1 reports whether the Jack-Accept header lines of 1.1 carry the
// token s1 at least once.
func AcceptsS1(values []string) bool {
	for _, line := range values {
		for _, token := range acceptTokens(line) {
			if token == "s1" {
				return true
			}
		}
	}
	return false
}

// acceptTokens parses one Jack-Accept line with the grammar of 1.1. A line the
// grammar does not admit contributes no token, so it yields nil.
func acceptTokens(line string) []string {
	line = strings.Trim(line, " ")
	if line == "" {
		return nil
	}
	parts := strings.Split(line, ",")
	tokens := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.Trim(part, " ")
		if !isAcceptToken(part) {
			return nil
		}
		tokens = append(tokens, part)
	}
	return tokens
}

// isAcceptToken reports whether s is 1*( %x2D / %x30-39 / %x41-5A / %x61-7A ).
func isAcceptToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '-', c >= '0' && c <= '9', c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z':
		default:
			return false
		}
	}
	return true
}

// Limiter bounds concurrent streams per authenticated identity (3.3).
type Limiter struct {
	mu     sync.Mutex
	max    int
	active map[string]int
}

// NewLimiter returns a limiter of max streams per identity; max <= 0 means
// DefaultMaxConcurrentStreams.
func NewLimiter(max int) *Limiter {
	if max <= 0 {
		max = DefaultMaxConcurrentStreams
	}
	return &Limiter{max: max, active: make(map[string]int)}
}

// Acquire reserves one slot for identity. It reports false when the limit is
// reached; the returned release function is safe to call more than once and
// frees the slot exactly once, so a slot is free on every path (3.3).
func (l *Limiter) Acquire(identity string) (func(), bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.active[identity] >= l.max {
		return func() {}, false
	}
	l.active[identity]++
	released := false
	return func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		if released {
			return
		}
		released = true
		if n := l.active[identity] - 1; n > 0 {
			l.active[identity] = n
		} else {
			delete(l.active, identity)
		}
	}, true
}

// Active reports the number of held slots for identity.
func (l *Limiter) Active(identity string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.active[identity]
}
