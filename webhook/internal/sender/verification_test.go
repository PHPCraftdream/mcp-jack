package sender_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/delivery"
	"github.com/PHPCraftdream/mcp-jack/webhook/internal/dsig"
	"github.com/PHPCraftdream/mcp-jack/webhook/internal/endpoint"
	"github.com/PHPCraftdream/mcp-jack/webhook/internal/sender"
)

const verificationNonce = "AAAAAAAAAAAAAAAAAAAAAA"

type stubGate struct {
	covers    func(context.Context, string, string, time.Duration) *endpoint.Error
	begin     func(string, string) (string, *endpoint.Error)
	accept    func(string, string, string, string, time.Duration) *endpoint.Error
	fresh     func(principal, url string) bool
	transport *delivery.Client
}

func (g *stubGate) Covers(ctx context.Context, principal, url string, ttl time.Duration) *endpoint.Error {
	if g.covers != nil {
		return g.covers(ctx, principal, url, ttl)
	}
	return nil
}

func (g *stubGate) Begin(principal, url string) (string, *endpoint.Error) {
	if g.begin != nil {
		return g.begin(principal, url)
	}
	return verificationNonce, nil
}

func (g *stubGate) Accept(principal, url, nonce, echo string, ttl time.Duration) *endpoint.Error {
	if g.accept != nil {
		return g.accept(principal, url, nonce, echo, ttl)
	}
	return nil
}

// Fresh defaults to true so tests that only exercise a challenge keep working.
func (g *stubGate) Fresh(principal, url string) bool {
	if g.fresh != nil {
		return g.fresh(principal, url)
	}
	return true
}

// Transport returns the injected client or, so that plain &stubGate{...}
// literals keep working, a fresh default-policy client.
func (g *stubGate) Transport() *delivery.Client {
	if g.transport != nil {
		return g.transport
	}
	return delivery.NewClient(delivery.Config{})
}

func TestSenderRequiresVerifier(t *testing.T) {
	for _, gate := range []sender.VerificationGate{nil, (*endpoint.Gate)(nil)} {
		cfg := profileSenderConfig()
		cfg.Verifier = gate
		if s, err := sender.New(cfg); s != nil || err == nil {
			t.Errorf("New with %T = (%v, %v), want nil sender and error", gate, s, err)
		}
	}
}

// clientlessGate satisfies VerificationGate but exposes no delivery client.
// The gate, not the sender config, owns the transport because the well-known
// fetch and the deliveries must share one hardened policy; a gate that cannot
// supply a client is a wiring bug the sender refuses to paper over.
type clientlessGate struct{}

func (clientlessGate) Covers(context.Context, string, string, time.Duration) *endpoint.Error {
	return nil
}

func (clientlessGate) Begin(string, string) (string, *endpoint.Error) {
	return verificationNonce, nil
}

func (clientlessGate) Accept(string, string, string, string, time.Duration) *endpoint.Error {
	return nil
}

func (clientlessGate) Fresh(string, string) bool { return true }

func (clientlessGate) Transport() *delivery.Client { return nil }

func TestSenderRequiresGateTransport(t *testing.T) {
	cfg := profileSenderConfig()
	cfg.Verifier = clientlessGate{}
	s, err := sender.New(cfg)
	if s != nil {
		t.Errorf("New with a clientless gate = %v, want nil sender", s)
	}
	if err == nil {
		t.Fatal("New with a clientless gate returned nil error")
	}
	if got, want := err.Error(), "sender requires the verifier's delivery client"; got != want {
		t.Errorf("New error = %q, want %q", got, want)
	}
}

func TestSenderRefusesIncompleteVerificationInputs(t *testing.T) {
	for name, clear := range map[string]func(*sender.Message){
		"principal":    func(m *sender.Message) { m.Principal = "" },
		"callback":     func(m *sender.Message) { m.CallbackURL = "" },
		"subscription": func(m *sender.Message) { m.SubscriptionID = "" },
	} {
		t.Run(name, func(t *testing.T) {
			msg := profileSenderMessage()
			clear(&msg)
			cfg := profileSenderConfig()
			cfg.Verifier = &stubGate{covers: func(context.Context, string, string, time.Duration) *endpoint.Error {
				t.Fatal("incomplete message reached the gate")
				return nil
			}}
			s := newProfileSender(t, cfg)
			sender.UseDeliveryForTest(s, func(*http.Request, int64) (*delivery.Response, *delivery.Error) {
				t.Fatal("incomplete message reached the client")
				return nil, nil
			})
			want := sender.AttemptResult{Code: "challenge_failed", LastError: "challenge_failed"}
			if got := s.Attempt(t.Context(), msg); got != want {
				t.Errorf("Attempt = %+v, want %+v", got, want)
			}
			if got, want := s.Deliver(t.Context(), msg), (sender.Result{LastError: "challenge_failed"}); got != want {
				t.Errorf("Deliver = %+v, want %+v", got, want)
			}
		})
	}
	var zero sender.Sender
	if got, want := zero.Deliver(t.Context(), profileSenderMessage()), (sender.Result{LastError: "challenge_failed"}); got != want {
		t.Errorf("zero Sender.Deliver = %+v, want %+v", got, want)
	}
}

func verificationSigningConfig() sender.Config {
	cfg := profileSenderConfig()
	cfg.Signing.JackKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, ed25519.SeedSize))
	cfg.Signing.Audience = "example-receiver"
	return cfg
}

func TestSenderRequestHeaderMapKeys(t *testing.T) {
	// Assert the request Header map keys, not captured wire bytes.
	cfg := verificationSigningConfig()
	msg := profileSenderMessage()
	s := newProfileSender(t, cfg)
	called := false
	sender.UseDeliveryForTest(s, func(req *http.Request, _ int64) (*delivery.Response, *delivery.Error) {
		called = true
		want := []string{
			"Content-Type",
			"webhook-id",
			"webhook-timestamp",
			"webhook-signature",
			"X-MCP-Subscription-Id",
			"Jack-Webhook-Auth",
		}
		if len(req.Header) != len(want) {
			t.Errorf("request Header map has %d keys, want %d: %v", len(req.Header), len(want), req.Header)
		}
		for _, key := range want {
			if _, ok := req.Header[key]; !ok {
				t.Errorf("request Header map is missing exact key %q: %v", key, req.Header)
			}
		}
		for key := range req.Header {
			if !slices.Contains(want, key) {
				t.Errorf("unexpected request Header map key %q", key)
			}
		}
		return &delivery.Response{Status: http.StatusOK}, nil
	})
	if got := s.Attempt(t.Context(), msg); got.Status != http.StatusOK || got.Code != "" {
		t.Errorf("Attempt = %+v, want status 200 and no refusal code", got)
	}
	if !called {
		t.Fatal("fake client was not called")
	}
}

func TestSenderVerifiesBeforeEvent(t *testing.T) {
	msg := profileSenderMessage()
	msg.CallbackURL += "?channel=%2fA" // w1 must retain the exact stored URL.
	msg.TTL = 17 * time.Minute
	cfg := verificationSigningConfig()
	const now = int64(1795338000)
	cfg.Now = func() int64 { return now }
	var steps []string
	checkPair := func(principal, url string) {
		t.Helper()
		if principal != msg.Principal || url != msg.CallbackURL {
			t.Errorf("gate pair = (%q, %q), want (%q, %q)", principal, url, msg.Principal, msg.CallbackURL)
		}
	}
	cfg.Verifier = &stubGate{
		covers: func(_ context.Context, principal, url string, ttl time.Duration) *endpoint.Error {
			steps = append(steps, "covers")
			checkPair(principal, url)
			if ttl != msg.TTL {
				t.Errorf("Covers TTL = %s, want %s", ttl, msg.TTL)
			}
			return &endpoint.Error{Code: "challenge_failed", Reason: "no_route"}
		},
		begin: func(principal, url string) (string, *endpoint.Error) {
			steps = append(steps, "begin")
			checkPair(principal, url)
			return verificationNonce, nil
		},
		accept: func(principal, url, nonce, echo string, ttl time.Duration) *endpoint.Error {
			if want := []string{"covers", "begin", "challenge"}; !slices.Equal(steps, want) {
				t.Errorf("before Accept: %v, want %v", steps, want)
			}
			steps = append(steps, "accept")
			checkPair(principal, url)
			if nonce != verificationNonce || echo != nonce || ttl != msg.TTL {
				t.Errorf("Accept nonce = %q, echo = %q, TTL = %s", nonce, echo, ttl)
			}
			return nil
		},
	}
	s := newProfileSender(t, cfg)
	var ids []string
	sender.UseDeliveryForTest(s, func(req *http.Request, limit int64) (*delivery.Response, *delivery.Error) {
		body := readSenderRequest(t, req)
		if req.Method != http.MethodPost || req.URL.String() != msg.CallbackURL {
			t.Errorf("unexpected request: %s %s", req.Method, req.URL)
		}
		// The sender preserves literal header spelling before going on the wire.
		id := checkSignedPost(t, req.Header, msg, body, cfg.Signing, now)
		ids = append(ids, id)
		switch len(ids) {
		case 1:
			steps = append(steps, "challenge")
			if !strings.HasPrefix(id, "msg_verification_") || limit != endpoint.MaxChallengeBytes ||
				string(body) != `{"type":"verification","challenge":"`+verificationNonce+`"}` {
				t.Errorf("first request: id %q, body %q, limit %d", id, body, limit)
			}
			return &delivery.Response{Status: 200, Body: []byte(`{"challenge":"` + verificationNonce + `"}`)}, nil
		case 2:
			steps = append(steps, "event")
			if !bytes.Equal(body, msg.Body) {
				t.Errorf("event changed: %q", body)
			}
			return &delivery.Response{Status: 200}, nil
		default:
			t.Fatalf("unexpected additional POST: %s %q", id, body)
			return nil, nil
		}
	})
	if got, want := s.Deliver(t.Context(), msg), (sender.Result{Accepted: true, Attempts: 1, Status: 200}); got != want {
		t.Errorf("Deliver = %+v, want %+v", got, want)
	}
	if want := []string{"covers", "begin", "challenge", "accept", "event"}; !slices.Equal(steps, want) {
		t.Errorf("verification/delivery order = %v, want %v", steps, want)
	}
	if len(ids) != 2 || ids[1] != msg.WebhookID {
		t.Errorf("request IDs = %v, want challenge then %q", ids, msg.WebhookID)
	}
}

func TestSenderChallengeRefusalsAreFinal(t *testing.T) {
	for _, tc := range []struct {
		name   string
		res    *delivery.Response
		err    *delivery.Error
		accept *endpoint.Error
		want   string
	}{
		{name: "status with failed body", res: &delivery.Response{Status: 500}, err: &delivery.Error{Code: "timeout"}, want: "challenge_failed"},
		{name: "returned redirect status", res: &delivery.Response{Status: 302}, want: "challenge_failed"},
		{name: "wrong echo", res: &delivery.Response{Status: 200, Body: []byte(`{"challenge":"wrong"}`)}, want: "challenge_failed"},
		{name: "invalid JSON", res: &delivery.Response{Status: 200, Body: []byte(`{"challenge":`)}, want: "challenge_failed"},
		{name: "oversize", res: &delivery.Response{Status: 200}, err: &delivery.Error{Code: "too_large"}, want: "challenge_failed"},
		{name: "connection refused", err: &delivery.Error{Code: "connection_refused"}, want: "connection_refused"},
		{name: "timeout", err: &delivery.Error{Code: "timeout"}, want: "timeout"},
		{name: "TLS failure", err: &delivery.Error{Code: "tls_error"}, want: "tls_error"},
		{name: "refused redirect", err: &delivery.Error{Code: "redirect_refused", Reason: "status_302"}, want: "http_4xx"},
		{name: "Accept refuses", res: &delivery.Response{Status: 200, Body: []byte(`{"challenge":"` + verificationNonce + `"}`)},
			accept: &endpoint.Error{Code: "challenge_failed", Reason: "expired"}, want: "challenge_failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := profileSenderConfig()
			cfg.Sleep = func(context.Context, time.Duration) error {
				t.Fatal("verification must not use the retry schedule")
				return errors.New("unexpected retry")
			}
			covers, posts, accepts := 0, 0, 0
			cfg.Verifier = &stubGate{
				covers: func(context.Context, string, string, time.Duration) *endpoint.Error {
					covers++
					return &endpoint.Error{Code: "challenge_failed", Reason: "no_route"}
				},
				accept: func(string, string, string, string, time.Duration) *endpoint.Error {
					accepts++
					return tc.accept
				},
			}
			s := newProfileSender(t, cfg)
			sender.UseDeliveryForTest(s, func(req *http.Request, _ int64) (*delivery.Response, *delivery.Error) {
				posts++
				if body := readSenderRequest(t, req); string(body) != `{"type":"verification","challenge":"`+verificationNonce+`"}` {
					t.Fatalf("unexpected request body: %q", body)
				}
				return tc.res, tc.err
			})
			msg := profileSenderMessage()
			if got, want := s.Deliver(t.Context(), msg), (sender.Result{LastError: tc.want}); got != want {
				t.Errorf("Deliver = %+v, want %+v", got, want)
			}
			if wantAccept := tc.accept != nil; covers != 1 || posts != 1 || accepts > 1 || (accepts == 1) != wantAccept {
				t.Errorf("Deliver: Covers = %d, POSTs = %d, Accept = %d; want one Covers, one challenge and Accept = %v", covers, posts, accepts, wantAccept)
			}
			if got, want := s.Attempt(t.Context(), msg), (sender.AttemptResult{Code: tc.want, LastError: tc.want}); got != want {
				t.Errorf("Attempt = %+v, want %+v", got, want)
			}
			if covers != 2 || posts != 2 {
				t.Errorf("Attempt: total Covers = %d, POSTs = %d; want two of each", covers, posts)
			}
		})
	}
}

func TestSenderCoveredPairSkipsChallenge(t *testing.T) {
	msg := profileSenderMessage()
	cfg := profileSenderConfig()
	cfg.Verifier = &stubGate{begin: func(string, string) (string, *endpoint.Error) {
		t.Fatal("Covers succeeded, but Begin was called")
		return "", nil
	}}
	s := newProfileSender(t, cfg)
	posts := 0
	sender.UseDeliveryForTest(s, func(req *http.Request, _ int64) (*delivery.Response, *delivery.Error) {
		posts++
		if id := req.Header["webhook-id"][0]; id != msg.WebhookID || !bytes.Equal(readSenderRequest(t, req), msg.Body) {
			t.Errorf("expected original event %s, got %s", msg.WebhookID, id)
		}
		return &delivery.Response{Status: 200}, &delivery.Error{Code: "too_large"}
	})
	if got, want := s.Deliver(t.Context(), msg), (sender.Result{Accepted: true, Attempts: 1, Status: 200}); got != want || posts != 1 {
		t.Errorf("Deliver = %+v, POSTs = %d, want %+v and one event", got, posts, want)
	}
}

func TestSenderVerifiesThroughHardenedTLS(t *testing.T) {
	if !sender.InTLSChildForTest(t) {
		return
	}
	msg := profileSenderMessage()
	msg.TTL = 15 * time.Minute
	cfg := verificationSigningConfig()
	const now = int64(1795338000)
	cfg.Now = func() int64 { return now }
	cfg.Sleep = func(context.Context, time.Duration) error {
		t.Error("unexpected retry in TLS delivery")
		return errors.New("unexpected retry")
	}
	var mu sync.Mutex
	var requests []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.TLS == nil || r.TLS.ServerName != "example.com" || !strings.HasPrefix(r.Host, "example.com:") {
			t.Errorf("request did not use example.com as authority and SNI: Host=%q", r.Host)
		}
		if r.Method == http.MethodGet && r.URL.Path == "/.well-known/mcp-webhook-receiver.json" {
			requests = append(requests, "document")
			// Reach the challenge route after a real, unsuccessful document fetch.
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost || r.URL.Path != "/hook" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL)
			http.NotFound(w, r)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("could not read request: %v", err)
			w.WriteHeader(400)
			return
		}
		want := msg
		want.CallbackURL = "https://" + r.Host + r.URL.RequestURI()
		id := checkSignedPost(t, r.Header, want, body, cfg.Signing, now)
		w.Header().Set("Content-Type", "application/json")
		if strings.HasPrefix(id, "msg_verification_") {
			requests = append(requests, "challenge")
			var challenge struct{ Type, Challenge string }
			if err := json.Unmarshal(body, &challenge); err != nil || challenge.Type != "verification" || !endpoint.NonceOK(challenge.Challenge) {
				t.Errorf("invalid challenge: %q (%v)", body, err)
				w.WriteHeader(400)
				return
			}
			_, _ = fmt.Fprintf(w, `{"challenge":%q}`, challenge.Challenge)
			return
		}
		requests = append(requests, "event")
		if id != msg.WebhookID || !bytes.Equal(body, msg.Body) {
			t.Errorf("event = %s %q, want %s %q", id, body, msg.WebhookID, msg.Body)
		}
		_, _ = io.WriteString(w, `{"status":"accepted"}`)
	}))
	t.Cleanup(srv.Close)
	listener := srv.Listener.Addr().String()
	_, port, err := net.SplitHostPort(listener)
	if err != nil {
		t.Fatal(err)
	}
	// The client carries the injected policy; the gate and the sender both use
	// this one instance, which is the sharing the transport rule requires.
	client := delivery.NewClient(delivery.Config{
		AllowedRanges: []string{"127.0.0.1/32"},
		Resolver: delivery.ResolverFunc(func(_ context.Context, host string) ([]string, error) {
			if host != "example.com" {
				return nil, fmt.Errorf("unexpected lookup of %q", host)
			}
			return []string{"127.0.0.1"}, nil
		}),
		Dialer: delivery.DialerFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
			if want := net.JoinHostPort("127.0.0.1", port); address != want {
				return nil, fmt.Errorf("dial target %q, want %q", address, want)
			}
			return (&net.Dialer{}).DialContext(ctx, network, listener)
		}),
	})
	gate := sender.GateForTest(t, client, srv.Certificate())
	cfg.Verifier = gate
	s := newProfileSender(t, cfg)
	callback := msg
	callback.CallbackURL = "https://" + net.JoinHostPort("example.com", port) + "/hook"
	if got, want := s.Deliver(t.Context(), callback), (sender.Result{Accepted: true, Attempts: 1, Status: 200}); got != want {
		t.Errorf("Deliver = %+v, want %+v", got, want)
	}
	if !gate.Fresh(callback.Principal, callback.CallbackURL) {
		t.Error("successful challenge was not cached")
	}
	mu.Lock()
	defer mu.Unlock()
	if want := []string{"document", "challenge", "event"}; !slices.Equal(requests, want) {
		t.Errorf("server saw %v, want %v", requests, want)
	}
}

func TestSenderDeliverRechecksFreshnessBeforeEveryAttempt(t *testing.T) {
	const t0 = int64(1767225600)
	now := t0
	var sleeps []time.Duration
	cfg := profileSenderConfig()
	freshCalls := 0
	cfg.Verifier = &stubGate{fresh: func(string, string) bool {
		freshCalls++
		return freshCalls == 1
	}}
	cfg.Now = func() int64 { return now }
	cfg.Sleep = func(_ context.Context, d time.Duration) error {
		sleeps = append(sleeps, d)
		now += int64(d / time.Second)
		return nil
	}
	s := newProfileSender(t, cfg)
	requests := 0
	sender.UseDeliveryForTest(s, func(*http.Request, int64) (*delivery.Response, *delivery.Error) {
		requests++
		return &delivery.Response{Status: 503}, &delivery.Error{Code: "timeout"}
	})
	if got, want := s.Deliver(t.Context(), profileSenderMessage()), (sender.Result{LastError: "challenge_failed"}); got != want {
		t.Errorf("Deliver = %+v, want %+v", got, want)
	}
	if requests != 1 {
		t.Errorf("delivery requests = %d, want exactly one before the verdict expired", requests)
	}
	if want := []time.Duration{30 * time.Second}; !slices.Equal(sleeps, want) {
		t.Errorf("sleeps = %v, want %v", sleeps, want)
	}
}

func TestSenderDeliverExpiredVerdictEndsRetrySchedule(t *testing.T) {
	const t0 = int64(1767225600)
	now := t0
	msg := profileSenderMessage()
	msg.TTL = 2 * time.Second
	client := delivery.NewClient(delivery.Config{})
	gate, err := endpoint.NewGate(endpoint.GateConfig{
		Client: client,
		Now:    func() int64 { return now },
		Hook:   func(context.Context, string, string) (bool, error) { return true, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if gate.Transport() != client {
		t.Fatal("gate does not expose the shared client")
	}
	cfg := profileSenderConfig()
	cfg.Verifier = gate
	cfg.Now = func() int64 { return now }
	cfg.Sleep = func(_ context.Context, d time.Duration) error {
		now += int64(d / time.Second)
		return nil
	}
	s := newProfileSender(t, cfg)
	requests := 0
	sender.UseDeliveryForTest(s, func(*http.Request, int64) (*delivery.Response, *delivery.Error) {
		requests++
		if requests > 1 {
			t.Fatal("a pair verified for two seconds received the 30 s retry")
		}
		return &delivery.Response{Status: 503}, &delivery.Error{Code: "timeout"}
	})
	if got, want := s.Deliver(t.Context(), msg), (sender.Result{LastError: "challenge_failed"}); got != want {
		t.Errorf("Deliver = %+v, want %+v", got, want)
	}
	if requests != 1 {
		t.Errorf("delivery requests = %d, want exactly one", requests)
	}
}

func readSenderRequest(t *testing.T, req *http.Request) []byte {
	t.Helper()
	defer req.Body.Close()
	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func checkSignedPost(t *testing.T, h http.Header, msg sender.Message, body []byte, opts sender.SigningOptions, now int64) string {
	t.Helper()
	get := func(name string) string {
		// Get handles network-canonicalized headers, but the fake client sees
		// their exact wire spelling instead.
		if values := h[name]; len(values) == 1 {
			return values[0]
		}
		return h.Get(name)
	}
	id, ts := get("webhook-id"), get("webhook-timestamp")
	if get("Content-Type") != "application/json" || get("X-MCP-Subscription-Id") != msg.SubscriptionID || ts != strconv.FormatInt(now, 10) {
		t.Errorf("unexpected POST headers: %v", h)
	}
	if got, want := get("webhook-signature"), dsig.V1Sign(opts.Secrets[0].Secret, id, ts, body); got != want {
		t.Errorf("v1 signature does not match %s", id)
	}
	pub := opts.JackKey.Public().(ed25519.PublicKey)
	digest := sha256.Sum256(pub)
	parts := dsig.W1Parts{Aud: opts.Audience, SubscriptionID: msg.SubscriptionID, WebhookID: id, Timestamp: ts, CallbackURL: msg.CallbackURL, Body: body}
	keys := dsig.W1Keys{Now: now, Keys: []dsig.AsymKey{{KID: base64.RawURLEncoding.EncodeToString(digest[:]), Raw: pub}}}
	if _, code := dsig.W1Verify(get("Jack-Webhook-Auth"), parts, keys); code != "" {
		t.Errorf("w1 signature on %s failed verification: %s", id, code)
	}
	return id
}
