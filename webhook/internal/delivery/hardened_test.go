package delivery_test

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/delivery"
)

func TestHardenedTLS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		port := r.Context().Value(http.LocalAddrContextKey).(*net.TCPAddr).Port
		if want := fmt.Sprintf("example.com:%d", port); r.Host != want {
			t.Errorf("Host = %q, want %q", r.Host, want)
		}
		if r.TLS == nil || r.TLS.ServerName != "example.com" || r.ProtoMajor != 1 {
			t.Errorf("expected example.com SNI over HTTP/1, got TLS=%v, protocol=%q", r.TLS, r.Proto)
		}
		if r.URL.Path != "/hook" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if r.URL.RawQuery == "redirect=1" {
			// An invalid Location must not be parsed, much less followed.
			w.Header().Set("Location", "https://[")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, "accepted")
	}))
	defer server.Close()

	listener := server.Listener.Addr().String()
	_, port, err := net.SplitHostPort(listener)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	var mu sync.Mutex
	var dials []string
	client := delivery.NewClientWithTestRoots(delivery.Config{
		AllowedRanges: []string{"127.0.0.1/32"},
		Resolver:      exampleResolver("127.0.0.1"),
		Dialer: delivery.DialerFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
			mu.Lock()
			dials = append(dials, address)
			mu.Unlock()
			return (&net.Dialer{}).DialContext(ctx, network, listener)
		}),
	}, roots)

	endpoint := "https://" + net.JoinHostPort("example.com", port) + "/hook"
	req, err := http.NewRequest(http.MethodPost, endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, refusal := client.Do(req, 1024)
	if refusal != nil || res == nil || res.Status != http.StatusAccepted || string(res.Body) != "accepted" {
		t.Fatalf("Do() = %+v, %v; want 202 with body accepted", res, refusal)
	}

	req, err = http.NewRequest(http.MethodPost, endpoint+"?redirect=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	res, refusal = client.Do(req, 1024)
	if res != nil || refusal == nil || refusal.Code != "redirect_refused" || refusal.Reason != "status_302" {
		t.Fatalf("redirect Do() = %+v, %v; want nil, redirect_refused: status_302", res, refusal)
	}

	mu.Lock()
	defer mu.Unlock()
	wantDial := net.JoinHostPort("127.0.0.1", port)
	if len(dials) != 2 || dials[0] != wantDial || dials[1] != wantDial {
		t.Errorf("dial addresses = %q; want one dial to %s per request", dials, wantDial)
	}
}

func TestHardenedTLSBlockedBeforeDial(t *testing.T) {
	var dialed atomic.Bool
	client := delivery.NewClient(delivery.Config{
		AllowedRanges: []string{"127.0.0.1/32"},
		Resolver:      exampleResolver("10.0.0.5"),
		Dialer: delivery.DialerFunc(func(context.Context, string, string) (net.Conn, error) {
			dialed.Store(true)
			return nil, errors.New("blocked address reached dialer")
		}),
	})
	res, refusal := client.Do(bodyTestRequest(t), 1024)
	if dialed.Load() {
		t.Error("dialer ran for a blocked address")
	}
	if res != nil || refusal == nil || refusal.Code != "blocked_address" || refusal.Reason != "private_use" {
		t.Fatalf("Do() = %+v, %v; want nil, blocked_address: private_use", res, refusal)
	}
}

func exampleResolver(ip string) delivery.Resolver {
	return delivery.ResolverFunc(func(_ context.Context, host string) ([]string, error) {
		if host != "example.com" {
			return nil, fmt.Errorf("unexpected resolver host %q", host)
		}
		return []string{ip}, nil
	})
}
