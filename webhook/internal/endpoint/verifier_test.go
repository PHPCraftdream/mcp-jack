package endpoint_test

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/delivery"
	"github.com/PHPCraftdream/mcp-jack/webhook/internal/endpoint"
)

const endpointURL = "https://hooks.example.test/hooks/a"

func TestEndpointAllowlistParsingAndMatching(t *testing.T) {
	for _, tt := range []struct {
		text, host string
		port       int
		path       string
	}{
		{"https://HOOKS.example.test.:443/hooks", "hooks.example.test", 443, "/hooks"},
		{"https://hooks.example.test?", "hooks.example.test", 443, "/"},
		{"https://[2001:0DB8::1]:8443", "[2001:db8::1]", 8443, "/"},
		{"https://*.Example.test.:65535/hooks/", "*.example.test", 65535, "/hooks/"},
		{"https://*.example.test", "*.example.test", 443, "/"},
		{"https://*.example.test:1", "*.example.test", 1, "/"},
		{"https://*.example.test/a/../b", "*.example.test", 443, "/a/../b"},
	} {
		want := endpoint.AllowlistEntry{HostPattern: tt.host, Port: tt.port, Path: tt.path}
		if got, ok := endpoint.ParseAllowlistEntry(tt.text); !ok || got != want {
			t.Errorf("ParseAllowlistEntry(%q) = (%+v, %t), want %+v", tt.text, got, ok, want)
		}
	}
	for _, text := range []string{
		"http://hooks.example.test", "HTTPS://hooks.example.test", "https://", "https://hooks.example.test/x?y=1",
		"https://hooks.example.test/#f", "https://user@hooks.example.test", "https://hooks.example.test/%2E",
		"https://*.example.test?", "https://*.example.test/#f", "https://*.example.test/with space",
		"https://*.example.test/é", "https://*.example.test/\x7f", "https://*.example.test/\n", "https://*.a@b.test",
		"https://*.127.0.0.1", "https://*.[2001:db8::1]", "https://*.test", "https://*..example.test",
		"https://*.example.test:0", "https://*.example.test:0443", "https://*.example.test:65536",
		"https://*.example.test:+443", "https://*.example.test:44x", "https://*.example.test:",
	} {
		if got, ok := endpoint.ParseAllowlistEntry(text); ok || got != (endpoint.AllowlistEntry{}) {
			t.Errorf("accepted %q: %+v", text, got)
		}
	}

	const literal = "https://hooks.example.test/hooks"
	const wildcard = "https://*.example.test/hooks"
	for _, tt := range []struct {
		entry, url string
		ok         bool
	}{
		{literal, endpointURL, true}, {literal, literal, true}, {literal, literal + "x", false},
		{literal, literal + "%2Fa", false}, {literal, "https://HOOKS.EXAMPLE.TEST.:443/hooks/a?x=1", true},
		{literal, "https://hooks.example.test:8443/hooks", false}, {literal, "https://hooks.example.test/Hooks/a", false},
		{literal, "http://hooks.example.test/hooks", false}, {literal, literal + "/.%2e/a", false},
		{literal + "/", literal, false}, {literal + "/", endpointURL, true},
		{"https://hooks.example.test/", "https://hooks.example.test/other", true},
		{wildcard, "https://a.b.example.test/hooks", true}, {wildcard, "https://a.example.test/hooks", true},
		{wildcard, "https://example.test/hooks", false}, {wildcard, "https://notexample.test/hooks", false},
		{wildcard, "https://a.example.test.evil.test/hooks", false}, {wildcard, "https://a.example.test:8443/hooks", false},
		{"https://*.example.test:8443/hooks", "https://a.example.test:8443/hooks/a", true},
	} {
		got, ok := endpoint.AllowlistMatches([]string{"bad", tt.entry}, tt.url)
		if ok != tt.ok || (!ok && got != (endpoint.AllowlistEntry{})) {
			t.Errorf("AllowlistMatches(%q, %q) = (%+v, %t), want match %t", tt.entry, tt.url, got, ok, tt.ok)
		}
	}
	if got, ok := endpoint.AllowlistMatches([]string{wildcard, literal}, endpointURL); !ok || got.HostPattern != "*.example.test" {
		t.Errorf("first match = (%+v, %t)", got, ok)
	}
}

func TestEndpointPureRouteAndGateOrder(t *testing.T) {
	in := endpoint.RouteInput{
		Cache: true, Allowlist: []string{"https://hooks.example.test/hooks"}, URL: endpointURL,
		Hook: true, Doc: []string{"/hooks/"}, DocPath: "/hooks/a", Challenge: &endpoint.Error{},
	}
	for _, tt := range []struct {
		want string
		next func(*endpoint.RouteInput)
	}{
		{"cache", func(in *endpoint.RouteInput) { in.Cache = false }},
		{"allowlist", func(in *endpoint.RouteInput) { in.URL = "https://other.example.test/hooks/a" }},
		{"out_of_band", func(in *endpoint.RouteInput) { in.Hook = false }},
		{"well_known", func(in *endpoint.RouteInput) { in.DocPath = "/hooks" }},
		{"challenge", func(in *endpoint.RouteInput) {
			in.Challenge = &endpoint.Error{Code: "challenge_failed", Reason: "mismatch"}
		}},
	} {
		if got := endpoint.VerificationRoute(in); got != (endpoint.Route{Verified: true, Route: tt.want}) {
			t.Errorf("route = %+v, want %q", got, tt.want)
		}
		tt.next(&in)
	}
	if got := endpoint.VerificationRoute(in); got != (endpoint.Route{Reason: "mismatch"}) {
		t.Errorf("failed challenge route = %+v", got)
	}
	in.Challenge = nil
	if got := endpoint.VerificationRoute(in); got != (endpoint.Route{Reason: "no_route"}) {
		t.Errorf("absent challenge route = %+v", got)
	}
	for _, verified := range []bool{false, true} {
		for _, msg := range []string{"verification", "event", "gap", "terminated"} {
			want := "refuse"
			if msg == "verification" {
				want = "send-challenge"
			} else if verified {
				want = "deliver"
			}
			if got := endpoint.DeliveryAction(endpoint.GateInput{Verified: verified, Message: msg}); got != want {
				t.Errorf("DeliveryAction(%t, %q) = %q, want %q", verified, msg, got, want)
			}
		}
	}
}

func newEndpointGate(t *testing.T, cfg endpoint.GateConfig) *endpoint.Gate {
	t.Helper()
	g, err := endpoint.NewGate(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func beginEndpointNonce(t *testing.T, g *endpoint.Gate, principal, callback string) string {
	t.Helper()
	nonce, err := g.Begin(principal, callback)
	assertEndpointError(t, err, "", "")
	if !endpoint.NonceOK(nonce) {
		t.Fatalf("invalid issued nonce %q", nonce)
	}
	return nonce
}

func TestEndpointGateNonces(t *testing.T) {
	now := int64(1000)
	random := strings.NewReader(strings.Repeat("a", 16) + strings.Repeat("b", 16) + strings.Repeat("c", 16))
	g := newEndpointGate(t, endpoint.GateConfig{Now: func() int64 { return now }, Random: random})
	alice := beginEndpointNonce(t, g, "alice", endpointURL)
	bob := beginEndpointNonce(t, g, "bob", endpointURL)
	if alice != base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("a", 16))) || alice == bob {
		t.Fatal("Begin did not encode exactly the 16 bytes read from Random")
	}
	if g.Fresh("alice", endpointURL) {
		t.Fatal("issuing a nonce must not verify a pair")
	}
	assertEndpointError(t, g.Accept("alice", endpointURL, alice, endpointNonce, 0), "challenge_failed", "mismatch")
	assertEndpointError(t, g.Accept("alice", endpointURL, alice, bob, 0), "challenge_failed", "pair")
	assertEndpointError(t, g.Accept("charlie", endpointURL, alice, alice, 0), "challenge_failed", "pair")
	assertEndpointError(t, g.Accept("alice", endpointURL+"/other", alice, alice, 0), "challenge_failed", "pair")
	assertEndpointError(t, g.Accept("charlie", endpointURL, endpointNonce, endpointNonce, 0), "challenge_failed", "mismatch")
	if g.Fresh("alice", endpointURL) {
		t.Fatal("rejected echoes must not verify a pair")
	}

	replacement := beginEndpointNonce(t, g, "alice", endpointURL)
	assertEndpointError(t, g.Accept("alice", endpointURL, alice, alice, 0), "challenge_failed", "mismatch")
	assertEndpointError(t, g.Accept("alice", endpointURL, alice, replacement, 0), "challenge_failed", "mismatch")
	_, err := g.Begin("alice", endpointURL) // exhausted reader must leave the pending nonce intact
	assertEndpointError(t, err, "challenge_failed", "random")

	now += 600
	assertEndpointError(t, g.Accept("alice", endpointURL, replacement, replacement, 2*time.Hour), "", "")
	if !g.Fresh("alice", endpointURL) || g.Fresh("bob", endpointURL) || g.Fresh("alice", endpointURL+"/other") {
		t.Fatal("only the accepted pair should be fresh")
	}
	assertEndpointError(t, g.Accept("alice", endpointURL, replacement, replacement, 0), "challenge_failed", "reused")
	assertEndpointError(t, g.Accept("bob", endpointURL, bob, replacement, 0), "challenge_failed", "reused")
	now++
	assertEndpointError(t, g.Accept("bob", endpointURL, bob, bob, 0), "challenge_failed", "expired")
	assertEndpointError(t, g.Accept("bob", endpointURL, bob, bob, 0), "challenge_failed", "expired")
	now += 3598
	if !g.Fresh("alice", endpointURL) {
		t.Fatal("verdict expired before the one-hour cap")
	}
	now++
	if g.Fresh("alice", endpointURL) {
		t.Fatal("verdict outlived the one-hour cap")
	}
	assertEndpointError(t, g.Accept("alice", endpointURL, replacement, replacement, 0), "challenge_failed", "mismatch")
}

func TestEndpointGateConcurrentAccept(t *testing.T) {
	g := newEndpointGate(t, endpoint.GateConfig{})
	nonce := beginEndpointNonce(t, g, "alice", endpointURL)
	start := make(chan struct{})
	results := make(chan *endpoint.Error, 2)
	for range 2 {
		go func() {
			<-start
			results <- g.Accept("alice", endpointURL, nonce, nonce, 0)
		}()
	}
	close(start)
	first, second := <-results, <-results
	if first != nil {
		first, second = second, first
	}
	assertEndpointError(t, first, "", "")
	assertEndpointError(t, second, "challenge_failed", "reused")
}

func TestEndpointGateVerdictTTL(t *testing.T) {
	for _, tt := range []struct {
		name string
		ttl  time.Duration
		secs int64
	}{
		{"explicit", 2 * time.Second, 2},
		{"default", 0, 3600},
		{"negative", -time.Second, 3600},
		{"clamped", 2 * time.Hour, 3600},
	} {
		t.Run(tt.name, func(t *testing.T) {
			now := int64(1000)
			g := newEndpointGate(t, endpoint.GateConfig{
				Allowlist: []string{endpointURL}, Now: func() int64 { return now },
			})
			assertEndpointError(t, g.Covers(t.Context(), "alice", endpointURL, tt.ttl), "", "")
			now += tt.secs - 1
			if !g.Fresh("alice", endpointURL) {
				t.Fatal("verdict expired early")
			}
			// Cache must beat the matching allowlist without extending the verdict.
			assertEndpointError(t, g.Covers(t.Context(), "alice", endpointURL, time.Hour), "", "")
			now++
			if g.Fresh("alice", endpointURL) {
				t.Fatal("verdict outlived its TTL or was renewed by a cache hit")
			}
		})
	}
}

func TestEndpointGateInvalidPair(t *testing.T) {
	g := newEndpointGate(t, endpoint.GateConfig{
		Hook: func(context.Context, string, string) (bool, error) {
			t.Fatal("invalid pair reached hook")
			return false, nil
		},
	})
	for _, p := range [][2]string{{"", endpointURL}, {"alice", ""}, {"alice", "http://example.com"}, {"alice", endpointURL + "/%2e%2e"}} {
		assertEndpointError(t, g.Covers(t.Context(), p[0], p[1], 0), "challenge_failed", "pair")
		_, err := g.Begin(p[0], p[1])
		assertEndpointError(t, err, "challenge_failed", "pair")
		assertEndpointError(t, g.Accept(p[0], p[1], endpointNonce, endpointNonce, 0), "challenge_failed", "pair")
		if g.Fresh(p[0], p[1]) {
			t.Fatalf("invalid pair is fresh: %q", p)
		}
	}
}

func TestEndpointGateDocumentTLS(t *testing.T) {
	// Trust httptest's certificate only in an isolated subprocess: the
	// hardened client uses platform roots and SetFallbackRoots is process-wide.
	const child = "MCP_JACK_ENDPOINT_TLS_TEST_CHILD"
	if os.Getenv(child) != "1" {
		cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestEndpointGateDocumentTLS$", "-test.v")
		cmd.Env = append(os.Environ(), child+"=1", "GODEBUG=x509usefallbackroots=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("TLS test subprocess: %v\n%s", err, output)
		}
		return
	}

	type reply struct {
		status      int
		body, cache string
	}
	var served atomic.Pointer[reply]
	var requests, lookups, dials atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodGet || r.URL.RequestURI() != "/.well-known/mcp-webhook-receiver.json" ||
			r.TLS.ServerName != "example.com" || !strings.HasPrefix(r.Host, "example.com:") {
			t.Errorf("unexpected document request: %s %s Host=%q SNI=%q", r.Method, r.URL, r.Host, r.TLS.ServerName)
		}
		current := served.Load()
		w.Header().Set("Cache-Control", current.cache)
		if current.status == http.StatusFound {
			w.Header().Set("Location", endpointURL)
		}
		w.WriteHeader(current.status)
		_, _ = io.WriteString(w, current.body)
	}))
	t.Cleanup(srv.Close)
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	x509.SetFallbackRoots(roots)

	address := srv.Listener.Addr().String()
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	origin := "https://" + net.JoinHostPort("example.com", port)
	callback := origin + "/hooks/a?not-forwarded=1"
	cfg := delivery.Config{
		AllowedRanges: []string{"127.0.0.1/32"},
		Resolver: delivery.ResolverFunc(func(_ context.Context, host string) ([]string, error) {
			lookups.Add(1)
			if host != "example.com" {
				return nil, fmt.Errorf("unexpected lookup: %s", host)
			}
			return []string{"127.0.0.1"}, nil
		}),
		Dialer: delivery.DialerFunc(func(ctx context.Context, network, target string) (net.Conn, error) {
			dials.Add(1)
			if want := net.JoinHostPort("127.0.0.1", port); target != want {
				return nil, fmt.Errorf("unexpected dial: %s, want %s", target, want)
			}
			return (&net.Dialer{}).DialContext(ctx, network, address)
		}),
	}
	client := delivery.NewClient(cfg)
	atCap := endpointDoc + strings.Repeat(" ", endpoint.MaxDocBytes-len(endpointDoc))
	served.Store(&reply{http.StatusOK, atCap, "max-age=999"})

	t.Run("route-order-and-origin-cache", func(t *testing.T) {
		now := int64(1000)
		calls := 0
		g := newEndpointGate(t, endpoint.GateConfig{
			Client: client, Allowlist: []string{origin + "/trusted"}, Now: func() int64 { return now },
			Hook: func(_ context.Context, principal, url string) (bool, error) {
				calls++
				if !strings.HasPrefix(url, origin+"/") {
					t.Errorf("hook received unexpected URL %q", url)
				}
				switch principal {
				case "hook":
					return true, nil
				case "doc":
					return true, errors.New("not confirmed")
				default:
					return false, nil
				}
			},
		})
		assertEndpointError(t, g.Covers(t.Context(), "allowlisted", origin+"/trusted", 0), "", "")
		if calls != 0 || lookups.Load() != 0 {
			t.Fatal("allowlist did not short-circuit hook and document")
		}
		assertEndpointError(t, g.Covers(t.Context(), "hook", callback, 0), "", "")
		if calls != 1 || lookups.Load() != 0 {
			t.Fatal("hook did not short-circuit document")
		}
		assertEndpointError(t, g.Covers(t.Context(), "doc", callback, time.Second), "", "")
		if calls != 2 || lookups.Load() != 1 || dials.Load() != 1 || requests.Load() != 1 || !g.Fresh("doc", callback) {
			t.Fatal("expected one hook call and one hardened fetch for the document route")
		}
		now += 299
		assertEndpointError(t, g.Covers(t.Context(), "doc", origin+"/hooks/b", 0), "", "")
		assertEndpointError(t, g.Covers(t.Context(), "doc", origin+"/hooks%2Fa", 0), "challenge_failed", "no_route")
		if requests.Load() != 1 || g.Fresh("doc", callback) {
			t.Fatal("expected shared document cache but independent pair verdicts")
		}
		now++
		assertEndpointError(t, g.Covers(t.Context(), "doc", callback, 0), "", "")
		if requests.Load() != 2 {
			t.Fatal("document cache outlived the 300-second cap")
		}
	})

	for _, tt := range []struct {
		name         string
		reply        reply
		code, reason string
	}{
		{"oversize", reply{http.StatusOK, atCap + " ", ""}, "document_fetch_failed", "too_large"},
		{"status-before-size", reply{http.StatusNotFound, atCap + " ", ""}, "document_fetch_failed", "status_404"},
		{"redirect", reply{http.StatusFound, "", ""}, "document_fetch_failed", "status_302"},
		{"invalid", reply{http.StatusOK, `{"receivers":["/hooks",null]}`, ""}, "invalid_document", "entry"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			served.Store(&tt.reply)
			before := lookups.Load()
			g := newEndpointGate(t, endpoint.GateConfig{Client: client})
			assertEndpointError(t, g.Covers(t.Context(), "alice", callback, 0), tt.code, tt.reason)
			if g.Fresh("alice", callback) || lookups.Load() != before+1 {
				t.Fatal("failed document verified the pair or redirected")
			}
		})
	}

	t.Run("blocked-address", func(t *testing.T) {
		beforeLookups, beforeDials := lookups.Load(), dials.Load()
		cfg.AllowedRanges = nil
		g := newEndpointGate(t, endpoint.GateConfig{Client: delivery.NewClient(cfg)})
		assertEndpointError(t, g.Covers(t.Context(), "alice", callback, 0), "challenge_failed", "no_route")
		if g.Fresh("alice", callback) || lookups.Load() != beforeLookups+1 || dials.Load() != beforeDials {
			t.Fatal("blocked address must be refused after lookup, without dialing or verifying")
		}
	})
}
