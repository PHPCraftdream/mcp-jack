package sender_test

import (
	"math"
	"strconv"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/sender"
)

func TestSenderReferenceStatusClassification(t *testing.T) {
	const t0 = int64(1767225600)
	for _, tc := range []struct {
		status       int
		action, last string
		nextAt       int64
	}{
		{99, "final", "http_4xx", 0},
		{199, "final", "http_4xx", 0},
		{200, "accept", "", 0},
		{204, "accept", "", 0},
		{299, "accept", "", 0},
		{301, "final", "http_4xx", 0},
		{404, "final", "http_4xx", 0},
		{410, "final", "http_4xx", 0},
		{413, "final", "http_4xx", 0},
		{425, "retry", "http_4xx", t0 + 30},
		{429, "retry", "http_4xx", t0 + 30},
		{500, "retry", "http_5xx", t0 + 30},
		{502, "retry", "http_5xx", t0 + 30},
		{503, "retry", "http_5xx", t0 + 30},
		{504, "retry", "http_5xx", t0 + 30},
		{599, "retry", "http_5xx", t0 + 30},
		{600, "final", "http_4xx", 0},
	} {
		t.Run(strconv.Itoa(tc.status), func(t *testing.T) {
			in := sender.AttemptInput{Status: tc.status, Attempt: 1, T0: t0, ResponseTime: t0}
			want := sender.Outcome{Action: tc.action, LastError: tc.last, NextAt: tc.nextAt}
			if got := sender.Decide(in); got != want {
				t.Errorf("Decide(%+v) = %+v, want %+v", in, got, want)
			}
		})
	}
}

func TestSenderReferenceTransportClassification(t *testing.T) {
	for _, code := range []string{"connection_refused", "timeout", "tls_error", "challenge_failed", "blocked_address", "dns_rebinding", "redirect_refused"} {
		t.Run(code, func(t *testing.T) {
			in := sender.AttemptInput{Transport: code, Attempt: 1, T0: 1000, ResponseTime: 1000}
			want := sender.Outcome{Action: "retry", LastError: code, NextAt: 1030}
			if got := sender.Decide(in); got != want {
				t.Errorf("Decide(%+v) = %+v, want %+v", in, got, want)
			}
			in.Attempt = 4
			want = sender.Outcome{Action: "final", LastError: code}
			if got := sender.Decide(in); got != want {
				t.Errorf("Decide(%+v) = %+v, want %+v", in, got, want)
			}
		})
	}
}

func TestSenderReferenceRetryAfterAndCap(t *testing.T) {
	const t0 = int64(1767225600)
	for _, tc := range []struct {
		name            string
		attempt         int
		response, delay int64
		hasDelay        bool
		wantNext        int64
	}{
		{"next original slot", 2, 40, 120, true, t0 + 270},
		{"postpone from response", 1, 5, 120, true, t0 + 125},
		{"ignore absent", 1, 5, 120, false, t0 + 30},
		{"ignore zero", 1, 5, 0, true, t0 + 30},
		{"cap", 1, 0, 1000, true, t0 + 900},
		{"cap without overflow", 1, 0, math.MaxInt64, true, t0 + 900},
		{"cap equals response", 3, 900, 120, true, 0},
		{"cap before response", 3, 901, 120, true, 0},
		{"missed next slot", 1, 31, 0, false, 0},
		{"fourth is final", 4, 870, 25, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := sender.AttemptInput{
				Status: 503, Attempt: tc.attempt, T0: t0, ResponseTime: t0 + tc.response,
				RetryAfter: tc.delay, HasRetryAfter: tc.hasDelay,
			}
			want := sender.Outcome{Action: "retry", LastError: "http_5xx", NextAt: tc.wantNext}
			if tc.wantNext == 0 {
				want.Action = "final"
			}
			if got := sender.Decide(in); got != want {
				t.Errorf("Decide(%+v) = %+v, want %+v", in, got, want)
			}
		})
	}
}

func TestSenderReferenceScheduleAndLastError(t *testing.T) {
	if got, want := sender.RetryOffsets(), ([4]int64{0, 30, 270, 870}); got != want {
		t.Errorf("RetryOffsets() = %v, want %v", got, want)
	}
	if got, want := sender.RetrySchedule(1767225600), ([4]int64{1767225600, 1767225630, 1767225870, 1767226470}); got != want {
		t.Errorf("RetrySchedule() = %v, want %v", got, want)
	}
	for _, tc := range []struct {
		status int
		last   string
	}{
		{99, ""}, {199, ""}, {200, ""}, {299, ""},
		{300, "http_4xx"}, {399, "http_4xx"}, {400, "http_4xx"}, {499, "http_4xx"},
		{500, "http_5xx"}, {599, "http_5xx"}, {600, ""},
	} {
		if got := sender.LastError(tc.status); got != tc.last {
			t.Errorf("LastError(%d) = %q, want %q", tc.status, got, tc.last)
		}
	}
}
