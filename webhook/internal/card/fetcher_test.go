package card_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
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

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/card"
	"github.com/PHPCraftdream/mcp-jack/webhook/internal/delivery"
)

func TestFetcherTLS(t *testing.T) {
	// Isolate the process-wide fallback roots so we can trust httptest's
	// certificate without changing delivery.Client or affecting other tests.
	const child = "MCP_JACK_CARD_TLS_TEST_CHILD"
	if os.Getenv(child) != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestFetcherTLS$", "-test.v")
		cmd.Env = append(os.Environ(), child+"=1", "GODEBUG=x509usefallbackroots=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("TLS test subprocess: %v\n%s", err, output)
		}
		return
	}

	type reply struct {
		status      int
		cache, body string
	}
	var served atomic.Pointer[reply]
	var requests, lookups atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodGet || r.URL.Path != "/mcp/server-card" || r.Header.Get("Accept") != "application/mcp-server-card+json" {
			t.Errorf("unexpected card request: %s %s, Accept %q", r.Method, r.URL, r.Header.Get("Accept"))
		}
		current := served.Load()
		if current.cache != "" {
			w.Header().Set("Cache-Control", current.cache)
		}
		if current.status == http.StatusFound {
			w.Header().Set("Location", "/mcp/server-card?redirected=1")
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
	baseURL := "https://" + net.JoinHostPort("example.com", port)
	mcpURL := baseURL + "/mcp"
	client := delivery.NewClient(delivery.Config{
		AllowedRanges: []string{"127.0.0.1/32"},
		Resolver: delivery.ResolverFunc(func(_ context.Context, host string) ([]string, error) {
			lookups.Add(1)
			if host != "example.com" {
				return nil, fmt.Errorf("unexpected lookup for %q", host)
			}
			return []string{"127.0.0.1"}, nil
		}),
		Dialer: delivery.DialerFunc(func(ctx context.Context, network, target string) (net.Conn, error) {
			if target != net.JoinHostPort("127.0.0.1", port) {
				return nil, fmt.Errorf("unexpected dial target %q", target)
			}
			return (&net.Dialer{}).DialContext(ctx, network, address)
		}),
	})

	old, _ := cardTestJWK(20)
	newKey, _ := cardTestJWK(21)
	both := cardTestSigningKeys(t, []card.JWK{old, newKey})
	publish := func(t *testing.T, keys json.RawMessage, cache string) {
		t.Helper()
		body := cardTestJSON(t, map[string]any{"remotes": []any{
			map[string]any{"url": mcpURL, "extensionsInfo": map[string]any{
				card.EventsExtension: map[string]any{"webhooks": map[string]any{"signingKeys": keys}},
			}},
		}})
		served.Store(&reply{status: http.StatusOK, cache: cache, body: string(body)})
	}
	newFetcher := func(t *testing.T, now func() int64) *card.Fetcher {
		t.Helper()
		f, err := card.NewFetcher(card.FetcherConfig{Client: client, MCPURL: mcpURL, Now: now})
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	refresh := func(t *testing.T, f *card.Fetcher) card.KeySet {
		t.Helper()
		if err := f.Refresh(t.Context()); err != nil {
			t.Fatal(err)
		}
		return f.KeySet()
	}

	t.Run("cache lifetime and rotation", func(t *testing.T) {
		now := int64(1000)
		f := newFetcher(t, func() int64 { return now })
		if snapshot := f.KeySet(); snapshot.Raw != nil || len(snapshot.Accepted) != 0 || len(snapshot.Rejected) != 0 || f.TTL() != 0 {
			t.Fatalf("new fetcher: snapshot %+v, TTL %v", snapshot, f.TTL())
		}
		publish(t, cardTestSigningKeys(t, []card.JWK{old}), "")
		if set := refresh(t, f); len(set.Accepted) != 1 || set.Accepted[0].KID != old.Kid || f.TTL() != 300*time.Second {
			t.Fatalf("before rotation: snapshot %+v, TTL %v", set, f.TTL())
		}

		publish(t, both, "max-age=60")
		set := refresh(t, f)
		if !bytes.Equal(set.Raw, both) || len(set.Accepted) != 2 || len(set.Rejected) != 0 || f.TTL() != time.Minute {
			t.Fatalf("during rotation: snapshot %+v, TTL %v", set, f.TTL())
		}
		for _, kid := range []string{old.Kid, newKey.Kid} {
			if _, ok := card.KeyForKID(set.Accepted, kid); !ok {
				t.Errorf("published kid %q not accepted", kid)
			}
		}

		now += 20
		served.Store(&reply{status: http.StatusNotFound})
		if err := f.Refresh(t.Context()); err == nil || err.Code != "http_status" {
			t.Fatalf("failed refresh = %v, want http_status", err)
		}
		if !bytes.Equal(f.KeySet().Raw, both) || f.TTL() != 40*time.Second {
			t.Fatalf("failed refresh changed snapshot or TTL: %+v, %v", f.KeySet(), f.TTL())
		}
		now += 40 // Past the 60 s lifetime: the snapshot must no longer be trusted.
		if set := f.KeySet(); set.Raw != nil || len(set.Accepted) != 0 || len(set.Rejected) != 0 || f.TTL() != 0 {
			t.Fatalf("expired snapshot still served: %+v, TTL %v", set, f.TTL())
		}

		publish(t, cardTestSigningKeys(t, []card.JWK{newKey}), "max-age=600")
		set = refresh(t, f)
		if len(set.Accepted) != 1 || set.Accepted[0].KID != newKey.Kid || f.TTL() != 300*time.Second {
			t.Fatalf("after rotation: snapshot %+v, TTL %v", set, f.TTL())
		}
		if _, ok := card.KeyForKID(set.Accepted, old.Kid); ok {
			t.Fatal("removed kid is still accepted")
		}
	})

	t.Run("expiry and refresh restore trust", func(t *testing.T) {
		now := int64(1000)
		f := newFetcher(t, func() int64 { return now })
		keys := cardTestSigningKeys(t, []card.JWK{old, newKey})
		publish(t, keys, "max-age=60")
		set := refresh(t, f)
		if !bytes.Equal(set.Raw, keys) || len(set.Accepted) != 2 || f.TTL() != time.Minute {
			t.Fatalf("fresh snapshot: %+v, TTL %v", set, f.TTL())
		}

		now += 61 // Past the lifetime without a refresh.
		if set := f.KeySet(); set.Raw != nil || len(set.Accepted) != 0 || len(set.Rejected) != 0 || f.TTL() != 0 {
			t.Fatalf("expired snapshot still served: %+v, TTL %v", set, f.TTL())
		}

		served.Store(&reply{status: http.StatusNotFound})
		if err := f.Refresh(t.Context()); err == nil || err.Code != "http_status" {
			t.Fatalf("failed refresh = %v, want http_status", err)
		}
		if set := f.KeySet(); set.Raw != nil || len(set.Accepted) != 0 || f.TTL() != 0 {
			t.Fatalf("failed refresh revived expired keys: %+v, TTL %v", set, f.TTL())
		}

		publish(t, keys, "max-age=60")
		set = refresh(t, f)
		if !bytes.Equal(set.Raw, keys) || len(set.Accepted) != 2 || f.TTL() != time.Minute {
			t.Fatalf("successful refresh did not restore trust: %+v, TTL %v", set, f.TTL())
		}
	})

	t.Run("response refusals", func(t *testing.T) {
		for _, tt := range []struct {
			status     int
			body, code string
		}{
			{404, "", "http_status"},
			{302, "", "redirect_refused"},
			{200, strings.Repeat(" ", card.MaxCardBytes+1), "too_large"},
			{404, strings.Repeat(" ", card.MaxCardBytes+1), "too_large"},
			{200, "{", "bad_json"},
			{200, "[]", "bad_json"},
			{200, `{"remotes":[{"url":"https://other.example.com/mcp"}]}`, "no_remote"},
		} {
			served.Store(&reply{status: tt.status, body: tt.body})
			before := requests.Load()
			f := newFetcher(t, nil)
			if err := f.Refresh(t.Context()); err == nil || err.Code != tt.code {
				t.Errorf("refresh for HTTP %d, %d bytes = %v, want %s", tt.status, len(tt.body), err, tt.code)
			}
			if requests.Load() != before+1 {
				t.Errorf("refresh for %s made %d requests, want 1", tt.code, requests.Load()-before)
			}
		}
	})

	t.Run("cross origin rejected without I/O", func(t *testing.T) {
		beforeRequests, beforeLookups := requests.Load(), lookups.Load()
		f, err := card.NewFetcher(card.FetcherConfig{
			Client: client, MCPURL: mcpURL, CardURL: "https://other.example.com/server-card",
		})
		var refusal *card.FetchError
		if f != nil || !errors.As(err, &refusal) || refusal.Code != "cross_origin" {
			t.Fatalf("NewFetcher = %v, %v; want cross_origin", f, err)
		}
		if requests.Load() != beforeRequests || lookups.Load() != beforeLookups {
			t.Fatal("cross-origin configuration performed network I/O")
		}
	})

	t.Run("timeout", func(t *testing.T) {
		f := newFetcher(t, nil)
		ctx, cancel := context.WithDeadline(t.Context(), time.Unix(0, 0))
		defer cancel()
		if err := f.Refresh(ctx); err == nil || err.Code != "timeout" {
			t.Fatalf("Refresh = %v, want timeout", err)
		}
	})

	t.Run("invalid raw alg retained for cross-check", func(t *testing.T) {
		bad := cardTestJWKMembers(old)
		bad["alg"] = "RS256"
		raw := cardTestSigningKeys(t, []any{bad, newKey})
		publish(t, raw, "max-age=300")
		f, err := card.NewFetcher(card.FetcherConfig{
			Client: client, MCPURL: mcpURL, CardURL: baseURL + "/mcp/server-card", Now: func() int64 { return 0 },
		})
		if err != nil {
			t.Fatal(err)
		}
		set := refresh(t, f)
		if !bytes.Equal(set.Raw, raw) || len(set.Accepted) != 1 || set.Accepted[0].KID != newKey.Kid ||
			len(set.Rejected) != 1 || set.Rejected[0].Reason != "alg" || set.Rejected[0].KID == nil || *set.Rejected[0].KID != old.Kid || f.TTL() != 300*time.Second {
			t.Fatalf("unexpected snapshot: %+v, TTL %v", set, f.TTL())
		}
		if code := card.CrossCheckWebhookKey(set.Raw, cardTestTool(t, newKey), true); code != "webhook_key_mismatch" {
			t.Errorf("cross-check returned %q, want webhook_key_mismatch", code)
		}
		set.Raw[0] = '!'
		set.Accepted[0].Raw[0] ^= 1
		*set.Rejected[0].KID = "changed"
		if fresh := f.KeySet(); !bytes.Equal(fresh.Raw, raw) || bytes.Equal(fresh.Accepted[0].Raw, set.Accepted[0].Raw) || *fresh.Rejected[0].KID != old.Kid {
			t.Fatalf("cached snapshot was mutated: %+v", fresh)
		}
	})
}
