package sender

import (
	"math"
	"net/http"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/wire"
)

// RetryOffsets returns the R1.8 attempt offsets in seconds.
func RetryOffsets() [4]int64 { return [4]int64{0, 30, 270, 870} }

// RetrySchedule returns the absolute Unix times of the four scheduled attempts.
func RetrySchedule(t0 int64) [wire.MaxAttempts]int64 {
	var schedule [wire.MaxAttempts]int64
	for i, offset := range RetryOffsets() {
		schedule[i] = addSeconds(t0, offset)
	}
	return schedule
}

// LastError returns the R1.7 category for an HTTP status, if any.
func LastError(status int) string {
	switch {
	case status >= 500 && status <= 599:
		return "http_5xx"
	case status >= 300 && status <= 499:
		return "http_4xx"
	default:
		return ""
	}
}

// AttemptInput describes one completed attempt. Attempt is one-based for deliveries.
type AttemptInput struct {
	Status                       int
	Transport                    string
	Attempt                      int
	T0, ResponseTime, RetryAfter int64
	HasRetryAfter                bool
}

// Outcome is an acceptance, a retry at NextAt, or a final failure.
type Outcome struct {
	Action, LastError string
	NextAt            int64
}

// Decide mirrors the reference senderDecision for integral inputs. It does not
// map internal delivery policy refusals; Deliver handles those separately.
func Decide(in AttemptInput) Outcome {
	category := in.Transport
	if category == "" {
		if in.Status >= 200 && in.Status <= 299 {
			return Outcome{Action: "accept"}
		}
		category = LastError(in.Status)
		if category == "" {
			category = "http_4xx"
		}
	}
	final := Outcome{Action: "final", LastError: category}
	if in.Transport == "" && in.Status != http.StatusTooEarly && in.Status != http.StatusTooManyRequests && category != "http_5xx" {
		return final
	}
	if in.Attempt < 0 || in.Attempt >= wire.MaxAttempts {
		return final
	}
	next := addSeconds(in.T0, RetryOffsets()[in.Attempt])
	if in.HasRetryAfter && in.RetryAfter > 0 {
		next = max(next, addSeconds(in.ResponseTime, in.RetryAfter))
	}
	next = min(next, addSeconds(in.T0, wire.RetryCapSeconds))
	if next <= in.ResponseTime {
		return final
	}
	return Outcome{Action: "retry", LastError: category, NextAt: next}
}

// addSeconds adds a nonnegative delay without letting a large Retry-After wrap.
func addSeconds(at, delay int64) int64 {
	if at > math.MaxInt64-delay {
		return math.MaxInt64
	}
	return at + delay
}
