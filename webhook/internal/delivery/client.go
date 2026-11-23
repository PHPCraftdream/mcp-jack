package delivery

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/urlcheck"
)

const (
	connectTimeout = 10 * time.Second
	headerTimeout  = 10 * time.Second
	bodyTimeout    = 10 * time.Second
	requestTimeout = 20 * time.Second
)

// Config controls the outbound address policy and optional network hooks.
type Config struct {
	AllowedRanges []string
	Resolver      Resolver
	Dialer        Dialer
}

// Error is a refused attempt. Err, when present, is the underlying failure.
type Error struct {
	Code, Reason string
	Err          error
}

func (e *Error) Error() string { return errorText(e.Code, e.Reason) }

// Unwrap returns the underlying failure.
func (e *Error) Unwrap() error { return e.Err }

// Response is a non-redirect HTTP response with a bounded body.
type Response struct {
	Status int
	Header http.Header
	Body   []byte
}

// Client sends HTTPS requests using the webhook delivery policy.
type Client struct {
	http *http.Client
}

// NewClient creates a client for deliveries, verification POSTs and well-known fetches.
func NewClient(cfg Config) *Client {
	return newClient(cfg, nil)
}

func newClient(cfg Config, roots *x509.CertPool) *Client {
	if cfg.Resolver == nil {
		cfg.Resolver = net.DefaultResolver
	}
	if cfg.Dialer == nil {
		cfg.Dialer = &net.Dialer{Timeout: connectTimeout}
	}
	cfg.AllowedRanges = append([]string(nil), cfg.AllowedRanges...)

	d := pinnedDialer{dialer: cfg.Dialer, roots: roots}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           d.dial,
		DialTLSContext:        d.dialTLS,
		ForceAttemptHTTP2:     false,
		Protocols:             new(http.Protocols),
		DisableKeepAlives:     true, // Each decision must get a fresh, peer-checked connection.
		DisableCompression:    true, // Do not automatically decompress response bodies.
		ResponseHeaderTimeout: headerTimeout,
	}
	transport.Protocols.SetHTTP1(true)

	return &Client{http: &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			prepared, err := prepare(req, cfg)
			if err != nil {
				if req.Body != nil {
					_ = req.Body.Close()
				}
				return nil, err
			}
			res, roundTripErr := transport.RoundTrip(prepared)
			if roundTripErr != nil {
				return nil, roundTripErr
			}
			// Intercept before http.Client can inspect or resolve a Location header.
			if res.StatusCode >= 300 && res.StatusCode < 400 {
				_ = res.Body.Close()
				return nil, &Error{Code: "redirect_refused", Reason: statusReason(res.StatusCode)}
			}
			return res, nil
		}),
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Timeout:       requestTimeout,
	}}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func prepare(req *http.Request, cfg Config) (*http.Request, *Error) {
	if !strings.EqualFold(req.URL.Scheme, "https") {
		return nil, &Error{Code: "scheme_not_https"}
	}
	if req.URL.Opaque != "" || (req.URL.Path != "" && req.URL.Path[0] != '/') {
		return nil, &Error{Code: "invalid_callback_url", Reason: "path"}
	}
	u, urlErr := urlcheck.Check(req.URL.String())
	if urlErr != nil {
		return nil, &Error{Code: urlErr.Code, Reason: urlErr.Reason}
	}

	connectBy := time.Now().Add(connectTimeout)
	ctx, cancel := context.WithDeadline(req.Context(), connectBy)
	defer cancel()
	in := CheckInput{AllowedRanges: cfg.AllowedRanges}
	if u.HostKind == "name" {
		var err error
		in.Answers, err = cfg.Resolver.LookupHost(ctx, u.HostValue)
		if err != nil {
			var dnsErr *net.DNSError
			if !isTimeout(err) && errors.As(err, &dnsErr) && dnsErr.IsNotFound && len(in.Answers) == 0 {
				return nil, &Error{Code: "no_answer", Reason: "no_records", Err: err}
			}
			return nil, networkError("connection_refused", err)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, networkError("connection_refused", err)
	}
	decision := check(u, in)
	if !decision.Allow {
		return nil, &Error{Code: decision.Code, Reason: decision.Reason}
	}

	target := dialTarget{decision: decision, host: u.HostValue, port: u.Port, connectBy: connectBy}
	prepared := req.Clone(context.WithValue(req.Context(), dialKey{}, target))
	prepared.URL.Scheme = "https"
	prepared.URL.Host = decision.HostHeader
	prepared.Host = decision.HostHeader
	for name := range prepared.Header {
		if strings.EqualFold(name, "Host") {
			delete(prepared.Header, name)
		}
	}
	return prepared, nil
}

// Do sends req and reads at most maxBody+1 response bytes. A negative limit or
// a body exceeding maxBody is refused with too_large. A body read failure
// returns the response status and headers alongside the error, without a body.
func (c *Client) Do(req *http.Request, maxBody int64) (*Response, *Error) {
	if req == nil || req.URL == nil {
		return nil, &Error{Code: "scheme_not_https"}
	}
	if maxBody < 0 {
		return nil, &Error{Code: "too_large"}
	}
	ctx, cancel := context.WithCancel(req.Context())
	defer cancel()
	res, err := c.http.Do(req.WithContext(ctx))
	if err != nil {
		return nil, networkError("connection_refused", err)
	}
	defer res.Body.Close()

	// R1.6's second cap starts at header receipt and covers the entire body,
	// including the size probe. Cancel the request to unblock an in-flight read.
	readBy := time.Now().Add(bodyTimeout)
	timer := time.AfterFunc(time.Until(readBy), cancel)
	defer timer.Stop()
	reader := bodyDeadlineReader{body: res.Body, deadline: readBy}
	response := &Response{Status: res.StatusCode, Header: res.Header}

	limited := &io.LimitedReader{R: reader, N: maxBody}
	body, err := io.ReadAll(limited)
	if err != nil {
		return response, networkError("connection_refused", err)
	}
	if limited.N == 0 {
		// Probe for one extra byte without overflowing maxBody+1.
		var extra [1]byte
		if _, err := io.ReadFull(reader, extra[:]); err == nil {
			return response, &Error{Code: "too_large"}
		} else if err != io.EOF {
			return response, networkError("connection_refused", err)
		}
	}
	response.Body = body
	return response, nil
}

type bodyDeadlineReader struct {
	body     io.Reader
	deadline time.Time
}

func (r bodyDeadlineReader) Read(p []byte) (int, error) {
	if !time.Now().Before(r.deadline) {
		return 0, context.DeadlineExceeded
	}
	n, err := r.body.Read(p)
	if !time.Now().Before(r.deadline) {
		// Cancellation may surface as context.Canceled or a closed connection.
		return 0, context.DeadlineExceeded
	}
	return n, err
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout())
}

func networkError(code string, err error) *Error {
	var deliveryErr *Error
	if errors.As(err, &deliveryErr) {
		return deliveryErr
	}
	if isTimeout(err) {
		code = "timeout"
	}
	return &Error{Code: code, Err: err}
}
