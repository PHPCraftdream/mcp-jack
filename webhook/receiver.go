package webhook

import (
	"errors"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/receiver"
	"github.com/PHPCraftdream/mcp-jack/webhook/internal/secret"
)

// ReceiverConfig configures authentication, routing, and durable enqueue.
type ReceiverConfig = receiver.Config

// Secret binds a raw HMAC key to a subscription or a pending callback.
type Secret = receiver.Secret

// JackConfig configures Jack signature verification.
type JackConfig = receiver.JackConfig

// WebhookKeyCheck configures the optional Server Card key cross-check.
type WebhookKeyCheck = receiver.WebhookKeyCheck

// EnqueueFunc durably stores a verified message before acknowledgement.
// It must not call back into the receiver. A nil hook does not provide durability.
type EnqueueFunc = receiver.EnqueueFunc

// ReceivedMessage is the verified message passed to EnqueueFunc.
type ReceivedMessage = receiver.Message

// Delivery contains raw header pairs, body bytes, and the current Unix second.
type Delivery = receiver.Delivery

// ReceiverResult is the receiver's response and dispatch result.
type ReceiverResult = receiver.Result

// ReceiverState is a snapshot of a receiver's state.
type ReceiverState = receiver.State

// SecretState describes a secret binding without exposing the key bytes.
type SecretState = receiver.SecretState

// Receiver authenticates and dispatches inbound webhook deliveries.
type Receiver struct {
	inner   *receiver.Receiver
	maxBody int64
}

// NewReceiver constructs a receiver. MaxBody may lower, but not raise, the profile cap.
func NewReceiver(cfg ReceiverConfig) (*Receiver, error) {
	if cfg.MaxBody == 0 || cfg.MaxBody > MaxBodyBytes {
		cfg.MaxBody = MaxBodyBytes
	}
	inner, err := receiver.New(cfg)
	if err != nil {
		return nil, err
	}
	return &Receiver{inner: inner, maxBody: cfg.MaxBody}, nil
}

// Handle authenticates and processes a delivery.
func (r *Receiver) Handle(d Delivery) ReceiverResult { return r.inner.Handle(d) }

// Route adds subscription IDs to the routed set.
func (r *Receiver) Route(ids []string) { r.inner.Route(ids) }

// State returns a snapshot of routing, termination, deduplication, and bindings.
func (r *Receiver) State() ReceiverState { return r.inner.State() }

// NewHTTPHandler exposes r as an HTTP handler.
func NewHTTPHandler(r *Receiver) http.Handler { return r }

// ServeHTTP processes the request with the receiver and writes its exact response.
// net/http preserves value order per header name, but not wire order across
// names or fields it has already normalized. Use Handle for raw header pairs.
func (r *Receiver) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	d := Delivery{Headers: requestHeaders(req)}
	if req.Body != nil && r.maxBody >= 0 && !skipBody(d.Headers, r.maxBody) {
		var err error
		d.Body, err = io.ReadAll(io.LimitReader(req.Body, r.maxBody+1))
		if err != nil && int64(len(d.Body)) <= r.maxBody {
			// An incomplete read must never authenticate just the bytes read so far.
			panic(http.ErrAbortHandler)
		}
	}
	d.Now = time.Now().Unix()
	result := r.Handle(d)
	w.Header().Set("Content-Type", "application/json")
	if result.Status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", "Webhook-Signature")
	}
	w.WriteHeader(result.Status)
	_, _ = w.Write(result.Body)
}

func requestHeaders(req *http.Request) [][2]string {
	keys := make([]string, 0, len(req.Header))
	for name := range req.Header {
		keys = append(keys, name)
	}
	slices.Sort(keys)
	var pairs [][2]string
	var hasLength, hasHost, hasTransferEncoding bool
	for _, key := range keys {
		name := key
		for _, value := range req.Header[key] {
			switch strings.ToLower(name) {
			case "content-length":
				hasLength = true
				name = "content-length"
			case "host":
				hasHost = true
			case "transfer-encoding":
				hasTransferEncoding = true
			}
			pairs = append(pairs, [2]string{name, value})
		}
	}
	// If a parsed length is zero and there is no header, net/http may mean absent.
	if !hasLength && req.ContentLength > 0 {
		pairs = append(pairs, [2]string{"content-length", strconv.FormatInt(req.ContentLength, 10)})
	}
	if !hasHost && req.Host != "" {
		pairs = append(pairs, [2]string{"Host", req.Host})
	}
	if !hasTransferEncoding && len(req.TransferEncoding) > 0 {
		pairs = append(pairs, [2]string{"Transfer-Encoding", strings.Join(req.TransferEncoding, ", ")})
	}
	return pairs
}

// skipBody is a transport optimization only. Handle decides the refusal and its precedence.
func skipBody(headers [][2]string, limit int64) bool {
	for _, pair := range headers {
		if pair[0] == "content-length" {
			// ParseUint saturates on overflow; the receiver validates the syntax.
			n, _ := strconv.ParseUint(pair[1], 10, 64)
			return n > uint64(limit)
		}
	}
	return false
}

// SecretKey decodes a whsec_ secret or returns only the refusal reason.
func SecretKey(value string) ([]byte, error) {
	key, reason := secret.Parse(value)
	if reason != "" {
		return nil, errors.New(reason)
	}
	return key, nil
}
