package sender_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/delivery"
	"github.com/PHPCraftdream/mcp-jack/webhook/internal/dsig"
	"github.com/PHPCraftdream/mcp-jack/webhook/internal/sender"
	"github.com/PHPCraftdream/mcp-jack/webhook/internal/wire"
)

func profileSenderConfig() sender.Config {
	return sender.Config{Signing: sender.SigningOptions{Secrets: []dsig.EmissionSecret{
		{Secret: bytes.Repeat([]byte{0xa7}, 32), Current: true},
	}}}
}

func profileSenderMessage() sender.Message {
	return sender.Message{
		WebhookID: "msg_" + strings.Repeat("A", 32), SubscriptionID: "sub_a3f1c8e2b0d49f7e",
		CallbackURL: "https://hooks.example.test/events",
		Body:        []byte(`{"eventId":"evt_789","name":"incident.created","timestamp":"2026-11-22T09:00:00Z","data":{}}`),
	}
}

func newProfileSender(t *testing.T, cfg sender.Config) *sender.Sender {
	t.Helper()
	s, err := sender.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSenderProfileWebhookIDShapes(t *testing.T) {
	tail := regexp.MustCompile(`^[A-Za-z0-9]{32}$`)
	for _, tc := range []struct{ kind, prefix string }{
		{"", "msg_"},
		{"gap", "msg_gap_"},
		{"terminated", "msg_terminated_"},
		{"verification", "msg_verification_"},
	} {
		t.Run(tc.prefix, func(t *testing.T) {
			random := bytes.NewReader(bytes.Repeat([]byte{0xb7}, 32))
			id, err := sender.NewWebhookID(tc.kind, random)
			if suffix, ok := strings.CutPrefix(id, tc.prefix); err != nil || !ok || !tail.MatchString(suffix) {
				t.Fatalf("NewWebhookID(%q) = (%q, %v), want %q and 32 alphanumeric characters", tc.kind, id, err, tc.prefix)
			}
			if random.Len() != 0 {
				t.Errorf("unused random bytes: %d", random.Len())
			}
		})
	}
	if _, err := sender.NewWebhookID("unknown", strings.NewReader("")); err == nil {
		t.Error("unknown message kind was accepted")
	}
	if _, err := sender.NewWebhookID("", strings.NewReader("short")); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("short random source: got %v, want unexpected EOF", err)
	}
}

func TestSenderProfileAttemptRefusals(t *testing.T) {
	cfg := profileSenderConfig()
	lookups := 0
	cfg.Resolver = delivery.ResolverFunc(func(context.Context, string) ([]string, error) {
		lookups++
		return []string{"127.0.0.1"}, nil
	})
	cfg.Dialer = delivery.DialerFunc(func(context.Context, string, string) (net.Conn, error) {
		t.Error("refused request reached the dialer")
		return nil, errors.New("unexpected dial")
	})
	s := newProfileSender(t, cfg)
	ctx := context.Background()
	msg := profileSenderMessage()
	msg.Body = make([]byte, wire.MaxBodyBytes+1)
	if got, want := s.Attempt(ctx, msg), (sender.AttemptResult{Code: "body_too_large", LastError: "http_4xx"}); got != want || lookups != 0 {
		t.Errorf("oversize Attempt = %+v, lookups = %d; want %+v and no lookups", got, lookups, want)
	}
	msg.Body = msg.Body[:wire.MaxBodyBytes]
	if got, want := s.Attempt(ctx, msg), (sender.AttemptResult{Code: "blocked_address", LastError: "connection_refused"}); got != want || lookups != 1 {
		t.Errorf("blocked Attempt = %+v, lookups = %d; want %+v and one lookup", got, lookups, want)
	}
	if got, want := s.Deliver(ctx, msg), (sender.Result{Attempts: 1, LastError: "connection_refused"}); got != want || lookups != 2 {
		t.Errorf("blocked Deliver = %+v, lookups = %d; want %+v and two total lookups", got, lookups, want)
	}
}

func TestSenderProfileDeliverRetrySchedule(t *testing.T) {
	const t0 = int64(1767225600)
	var now = t0
	var sleeps []time.Duration
	var attemptsAt []int64
	cfg := profileSenderConfig()
	cfg.Now = func() int64 { return now }
	cfg.Sleep = func(_ context.Context, d time.Duration) error {
		sleeps = append(sleeps, d)
		now += int64(d / time.Second)
		return nil
	}
	cfg.Resolver = delivery.ResolverFunc(func(context.Context, string) ([]string, error) {
		attemptsAt = append(attemptsAt, now)
		return []string{"192.0.0.9"}, nil // the profile allows PCP anycast
	})
	cfg.Dialer = delivery.DialerFunc(func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("injected connection refusal")
	})
	s := newProfileSender(t, cfg)
	got := s.Deliver(context.Background(), profileSenderMessage())
	if want := (sender.Result{Attempts: 4, LastError: "connection_refused"}); got != want {
		t.Errorf("Deliver = %+v, want %+v", got, want)
	}
	if want := []int64{t0, t0 + 30, t0 + 270, t0 + 870}; !slices.Equal(attemptsAt, want) {
		t.Errorf("attempt times = %v, want %v", attemptsAt, want)
	}
	if want := []time.Duration{30 * time.Second, 240 * time.Second, 600 * time.Second}; !slices.Equal(sleeps, want) {
		t.Errorf("sleeps = %v, want %v", sleeps, want)
	}
}

func TestSenderProfileDeliverStopsOnHTTPStatus(t *testing.T) {
	for _, tc := range []struct {
		name string
		want sender.Result
	}{
		{"accepted", sender.Result{Accepted: true, Attempts: 1, Status: 204}},
		{"final", sender.Result{Attempts: 1, Status: 410, LastError: "http_4xx"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := profileSenderConfig()
			cfg.Sleep = func(context.Context, time.Duration) error {
				t.Error("unexpected sleep after terminal HTTP response")
				return errors.New("unexpected retry")
			}
			s := newProfileSender(t, cfg)
			sender.UseDeliveryForTest(s, func(*http.Request, int64) (*delivery.Response, *delivery.Error) {
				return &delivery.Response{Status: tc.want.Status, Body: []byte("private endpoint response")}, nil
			})
			if got := s.Deliver(context.Background(), profileSenderMessage()); got != tc.want {
				t.Errorf("Deliver = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestSenderProfileSuspensionDoesNotConsumeSchedule(t *testing.T) {
	const t0 = int64(1767225600)
	now := t0
	var sleeps []time.Duration
	var attemptsAt []int64
	checks := 0
	cfg := profileSenderConfig()
	cfg.Now = func() int64 { return now }
	cfg.Suspended = func() bool { checks++; return checks == 1 }
	cfg.Sleep = func(_ context.Context, d time.Duration) error {
		sleeps = append(sleeps, d)
		if len(sleeps) == 1 {
			now += 1200 // suspended longer than the entire active retry window
		} else {
			now += int64(d / time.Second)
		}
		return nil
	}
	cfg.Resolver = delivery.ResolverFunc(func(context.Context, string) ([]string, error) {
		attemptsAt = append(attemptsAt, now)
		return []string{"192.0.0.9"}, nil
	})
	cfg.Dialer = delivery.DialerFunc(func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("injected connection refusal")
	})
	s := newProfileSender(t, cfg)
	if got := s.Deliver(context.Background(), profileSenderMessage()); got.Attempts != 4 || got.Accepted {
		t.Errorf("Deliver = %+v, want four failed attempts", got)
	}
	if want := []int64{t0 + 1200, t0 + 1230, t0 + 1470, t0 + 2070}; !slices.Equal(attemptsAt, want) {
		t.Errorf("attempt times = %v, want %v", attemptsAt, want)
	}
	if len(sleeps) == 0 {
		t.Fatal("suspended delivery did not sleep")
	}
	var activeWait time.Duration
	for _, d := range sleeps[1:] {
		activeWait += d
	}
	if activeWait != 870*time.Second {
		t.Errorf("active wait = %v, want 870s", activeWait)
	}
}

func TestSenderProfileDeliverRetryAfterHeaders(t *testing.T) {
	for _, tc := range []struct {
		value string
		delay time.Duration
	}{
		{"120", 120 * time.Second},
		{"1000", 900 * time.Second},
		{"Thu, 01 Jan 2026 00:02:00 GMT", 30 * time.Second},
		{"+120", 30 * time.Second},
	} {
		t.Run(tc.value, func(t *testing.T) {
			var now int64 = 1767225600
			var sleeps []time.Duration
			cfg := profileSenderConfig()
			cfg.Now = func() int64 { return now }
			cfg.Sleep = func(_ context.Context, d time.Duration) error {
				sleeps = append(sleeps, d)
				now += int64(d / time.Second)
				return nil
			}
			s := newProfileSender(t, cfg)
			sender.UseDeliveryForTest(s, func(*http.Request, int64) (*delivery.Response, *delivery.Error) {
				if len(sleeps) == 0 {
					return &delivery.Response{Status: 503, Header: http.Header{"Retry-After": {tc.value}}}, nil
				}
				return &delivery.Response{Status: 200}, nil
			})
			if got, want := s.Deliver(context.Background(), profileSenderMessage()), (sender.Result{Accepted: true, Attempts: 2, Status: 200}); got != want {
				t.Errorf("Deliver = %+v, want %+v", got, want)
			}
			if want := []time.Duration{tc.delay}; !slices.Equal(sleeps, want) {
				t.Errorf("sleeps = %v, want %v", sleeps, want)
			}
		})
	}
}
