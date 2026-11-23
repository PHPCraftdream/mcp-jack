package delivery_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/delivery"
)

func TestDeliveryClient(t *testing.T) {
	const https = "https://hooks.example.test:8443/hook"
	dialErr := errors.New("injected dial failure")
	for _, tt := range []struct {
		name, url    string
		answers      []string
		peer         string
		dialErr      error
		code, reason string
		wantHost     string
		wantAddress  string
	}{
		{
			name: "non-HTTPS", url: "http://hooks.example.test/", code: "scheme_not_https",
		},
		{
			name: "blocked answer", url: https, answers: []string{"192.0.0.9", "127.0.0.1"},
			code: "blocked_address", reason: "loopback", wantHost: "hooks.example.test",
		},
		{
			name: "empty answer", url: https,
			code: "no_answer", reason: "no_records", wantHost: "hooks.example.test",
		},
		{
			name: "peer mismatch", url: https, answers: []string{"192.0.0.9", "192.0.0.10"}, peer: "192.0.0.10",
			code: "dns_rebinding", reason: "peer_mismatch", wantHost: "hooks.example.test", wantAddress: "192.0.0.9:8443",
		},
		{
			name: "literal skips DNS", url: "https://[2001:1::1]/", dialErr: dialErr,
			code: "connection_refused", wantAddress: "[2001:1::1]:443",
		},
		{
			name: "dial deadline", url: https, answers: []string{"192.0.0.9"}, dialErr: context.DeadlineExceeded,
			code: "timeout", wantHost: "hooks.example.test", wantAddress: "192.0.0.9:8443",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			lookups := make(chan string, 2)
			dials := make(chan [2]string, 2)
			var conn net.Conn
			if tt.peer != "" {
				local, remote := net.Pipe()
				t.Cleanup(func() { _ = local.Close(); _ = remote.Close() })
				conn = deliveryTestPeerConn{Conn: local, peer: &net.TCPAddr{IP: net.ParseIP(tt.peer), Port: 8443}}
			}
			client := delivery.NewClient(delivery.Config{
				Resolver: delivery.ResolverFunc(func(_ context.Context, host string) ([]string, error) {
					select {
					case lookups <- host:
					default:
					}
					return tt.answers, nil
				}),
				Dialer: delivery.DialerFunc(func(_ context.Context, network, address string) (net.Conn, error) {
					select {
					case dials <- [2]string{network, address}:
						if conn != nil && address == tt.wantAddress {
							return conn, nil
						}
					default:
					}
					if tt.dialErr != nil {
						return nil, tt.dialErr
					}
					return nil, dialErr
				}),
			})
			req, err := http.NewRequest(http.MethodPost, tt.url, nil)
			if err != nil {
				t.Fatal(err)
			}
			res, refusal := client.Do(req, 1024)
			if res != nil || refusal == nil || refusal.Code != tt.code || refusal.Reason != tt.reason {
				t.Fatalf("Do() = %v, %v; want nil, code %q, reason %q", res, refusal, tt.code, tt.reason)
			}
			if tt.dialErr != nil && !errors.Is(refusal.Err, tt.dialErr) {
				t.Errorf("Err = %v, want %v", refusal.Err, tt.dialErr)
			}
			if tt.wantHost == "" {
				if len(lookups) != 0 {
					t.Fatal("unexpected DNS lookup")
				}
			} else if len(lookups) != 1 || <-lookups != tt.wantHost {
				t.Errorf("want exactly one lookup for %q", tt.wantHost)
			}
			if tt.wantAddress == "" {
				if len(dials) != 0 {
					t.Fatal("unexpected dial")
				}
			} else if len(dials) != 1 {
				t.Errorf("got %d dials, want one", len(dials))
			} else if got := <-dials; got != [2]string{"tcp", tt.wantAddress} {
				t.Errorf("DialContext got %q, want tcp %s", got, tt.wantAddress)
			}
		})
	}
}

type deliveryTestPeerConn struct {
	net.Conn
	peer net.Addr
}

func (c deliveryTestPeerConn) RemoteAddr() net.Addr { return c.peer }

func TestDeliveryBodyDeadline(t *testing.T) {
	const limit = 4
	for _, tt := range []struct{ name, prefix string }{
		{name: "during body", prefix: "a"},
		{name: "during size probe", prefix: "abcd"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var headersAt time.Time
				client := delivery.NewClientWithTestTransport(func(req *http.Request) (*http.Response, error) {
					time.Sleep(3 * time.Second) // Simulate earlier request phases without using the body budget.
					headersAt = time.Now()
					body := io.MultiReader(strings.NewReader(tt.prefix), waitForCancellation{req.Context()})
					return testHTTPResponse(body), nil
				})
				res, refusal := client.Do(bodyTestRequest(t), limit)
				assertBodyTestHeaders(t, res)
				if refusal == nil || refusal.Code != "timeout" || res.Body != nil {
					t.Fatalf("Do() = %+v, %v; want timeout without a body", res, refusal)
				}
				if elapsed := time.Since(headersAt); elapsed != 10*time.Second {
					t.Errorf("body deadline elapsed after %v from header receipt, want 10s", elapsed)
				}
			})
		})
	}
}

func TestDeliveryBodyLimit(t *testing.T) {
	const limit = 4
	for _, tt := range []struct{ name, body, code string }{
		{name: "one byte over", body: "abcde", code: "too_large"},
		{name: "exactly at cap", body: "abcd"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			client := delivery.NewClientWithTestTransport(func(*http.Request) (*http.Response, error) {
				return testHTTPResponse(strings.NewReader(tt.body)), nil
			})
			res, refusal := client.Do(bodyTestRequest(t), limit)
			assertBodyTestHeaders(t, res)
			if tt.code != "" {
				if refusal == nil || refusal.Code != tt.code || res.Body != nil {
					t.Fatalf("Do() = %+v, %v; want %s without a body", res, refusal, tt.code)
				}
			} else if refusal != nil || string(res.Body) != tt.body {
				t.Fatalf("Do() = %+v, %v; want body %q without error", res, refusal, tt.body)
			}
		})
	}
}

type waitForCancellation struct{ ctx context.Context }

func (r waitForCancellation) Read([]byte) (int, error) {
	<-r.ctx.Done()
	return 0, r.ctx.Err()
}

func testHTTPResponse(body io.Reader) *http.Response {
	return &http.Response{
		StatusCode: http.StatusTooManyRequests,
		Header:     http.Header{"Retry-After": {"120"}},
		Body:       io.NopCloser(body),
	}
}

func bodyTestRequest(t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "https://example.com/hook", nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func assertBodyTestHeaders(t *testing.T, res *delivery.Response) {
	t.Helper()
	if res == nil || res.Status != http.StatusTooManyRequests || res.Header.Get("Retry-After") != "120" {
		t.Fatalf("response = %+v; want status 429 and Retry-After: 120", res)
	}
}
