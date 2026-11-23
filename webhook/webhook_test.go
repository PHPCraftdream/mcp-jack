package webhook_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/mcp-jack/webhook"
)

const (
	testSub  = "sub_a3f1c8e2b0d49f7e"
	testID   = "msg_7Qk2mZ4rT9xV1bN6pL3sD8wY5cJ0hG2f"
	testBody = `{"eventId":"evt_789","name":"incident.created","timestamp":"2026-11-22T09:00:00Z","data":{"incidentId":"INC-1234"}}`
	testNow  = int64(1795338000)
)

func newTestReceiver(t *testing.T) (*webhook.Receiver, []byte, string) {
	t.Helper()
	raw := []byte("0123456789ABCDEF0123456789ABCDEF")
	encoded := "whsec_" + base64.StdEncoding.EncodeToString(raw)
	key, err := webhook.SecretKey(encoded)
	if err != nil || !bytes.Equal(key, raw) {
		t.Fatal("could not decode the fixture secret")
	}
	r, err := webhook.NewReceiver(webhook.ReceiverConfig{
		Secrets: []webhook.Secret{{SubscriptionID: testSub, Key: key}},
		Routed:  []string{testSub},
	})
	if err != nil {
		t.Fatal(err)
	}
	return r, key, encoded
}

func signDelivery(key []byte, id, sub string, now, signedAt int64, body string) webhook.Delivery {
	ts := strconv.FormatInt(signedAt, 10)
	mac := hmac.New(sha256.New, key)
	_, _ = io.WriteString(mac, id+"."+ts+"."+body)
	return webhook.Delivery{
		Now: now,
		Headers: [][2]string{
			{"webhook-id", id},
			{"webhook-timestamp", ts},
			{"webhook-signature", "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))},
			{"X-MCP-Subscription-Id", sub},
		},
		Body: []byte(body),
	}
}

func TestWebhookReceiverAdapter(t *testing.T) {
	r, key, encoded := newTestReceiver(t)
	h := webhook.NewHTTPHandler(r)
	now := time.Now().Unix()
	d := signDelivery(key, testID, testSub, now, now, testBody)
	request := func(body io.Reader) *http.Request {
		req := httptest.NewRequest(http.MethodPost, "https://hooks.example.test/x", body)
		req.Header.Set("Content-Type", "application/json")
		for _, pair := range d.Headers {
			req.Header.Add(pair[0], pair[1])
		}
		return req
	}
	serve := func(req *http.Request, status int) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != status || w.Header().Get("Content-Type") != "application/json" {
			t.Fatalf("got status %d/content type %q, want %d/application/json", w.Code, w.Header().Get("Content-Type"), status)
		}
		return w
	}
	if w := serve(request(strings.NewReader(testBody)), 200); w.Body.String() != `{"status":"accepted"}` {
		t.Fatalf("unexpected accepted body: %q", w.Body.Bytes())
	}
	if w := serve(request(strings.NewReader(testBody)), 200); w.Body.String() != `{"status":"duplicate"}` {
		t.Fatalf("unexpected duplicate body: %q", w.Body.Bytes())
	}
	w := serve(request(strings.NewReader(testBody+" ")), 401)
	if got := w.Header().Get("WWW-Authenticate"); got != "Webhook-Signature" {
		t.Fatalf("WWW-Authenticate = %q", got)
	}
	assertSafeError(t, w.Body.Bytes(), "bad_signature", key, encoded)

	req := request(strings.NewReader(testBody))
	req.Header.Add("Webhook-Id", testID)
	w = serve(req, 400)
	assertSafeError(t, w.Body.Bytes(), "duplicate_webhook_header", key, encoded)

	for _, explicit := range []bool{true, false} {
		body := &countingBody{r: strings.NewReader(testBody)}
		req = request(body)
		if explicit {
			req.Header.Set("Content-Length", strconv.Itoa(webhook.MaxBodyBytes+1))
		} else {
			req.ContentLength = webhook.MaxBodyBytes + 1
		}
		w = serve(req, 413)
		assertSafeError(t, w.Body.Bytes(), "body_too_large", key, encoded)
		if body.read != 0 {
			t.Fatalf("read %d bytes despite oversized declared length (explicit=%v)", body.read, explicit)
		}
	}

	body := &countingBody{r: strings.NewReader(strings.Repeat("x", webhook.MaxBodyBytes+100))}
	w = serve(request(body), 413)
	assertSafeError(t, w.Body.Bytes(), "body_too_large", key, encoded)
	if body.read != webhook.MaxBodyBytes+1 {
		t.Fatalf("oversized stream: read %d bytes, want %d", body.read, webhook.MaxBodyBytes+1)
	}
}

type countingBody struct {
	r    io.Reader
	read int
}

func (b *countingBody) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	b.read += n
	return n, err
}

func TestWebhookRetryProperty(t *testing.T) {
	if got := webhook.RetryOffsets(); got != [4]int64{0, 30, 270, 870} {
		t.Fatalf("RetryOffsets() = %v", got)
	}
	for i := range int64(101) {
		t0 := i * 7919 * 10007
		want := [4]int64{t0, t0 + 30, t0 + 270, t0 + 870}
		if got := webhook.RetrySchedule(t0); got != want {
			t.Fatalf("RetrySchedule(%d) = %v, want %v", t0, got, want)
		}
		for status := 100; status <= 599; status++ {
			for attempt := 1; attempt <= 5; attempt++ {
				for _, delay := range []int64{0, 50, math.MaxInt64} {
					in := webhook.AttemptInput{
						Status: status, Attempt: attempt, T0: t0,
						ResponseTime: want[min(attempt-1, len(want)-1)] + i%21,
						RetryAfter:   delay, HasRetryAfter: delay != 0,
					}
					out := webhook.Decide(in)
					if out.NextAt > t0+900 {
						t.Fatalf("Decide(%+v) = %+v exceeds cap", in, out)
					}
					if out.Action == "retry" && (attempt >= 4 || status >= 200 && status < 300 || status == 410 || status == 413) {
						t.Fatalf("Decide(%+v) = %+v retries a final outcome", in, out)
					}
				}
			}
		}
	}
}

type addressRow struct {
	prefix netip.Prefix
	name   string
}

func deepestName(addr netip.Addr, rows []addressRow) string {
	depth, name := -1, ""
	for _, row := range rows {
		if row.prefix.Bits() > depth && row.prefix.Contains(addr) {
			depth, name = row.prefix.Bits(), row.name
		}
	}
	return name
}

func TestWebhookAddressTableEdges(t *testing.T) {
	var v4, v6 []addressRow
	for _, row := range webhook.IPV4Blocks {
		v4 = append(v4, addressRow{netip.PrefixFrom(netip.AddrFrom4(row.Bytes), row.Prefix), row.Name})
	}
	for _, row := range webhook.IPV6Blocks {
		v6 = append(v6, addressRow{netip.PrefixFrom(netip.AddrFrom16(row.Bytes), row.Prefix), row.Name})
	}
	for family, rows := range map[string][]addressRow{"ipv4": v4, "ipv6": v6} {
		if len(rows) == 0 {
			t.Fatalf("%s table is empty", family)
		}
		for _, row := range rows {
			first := row.prefix.Addr().AsSlice()
			last := bytes.Clone(first)
			for bit := row.prefix.Bits(); bit < len(first)*8; bit++ {
				mask := byte(1 << (7 - bit%8))
				first[bit/8] &^= mask
				last[bit/8] |= mask
			}
			for _, edge := range [][]byte{first, last} {
				addr, ok := netip.AddrFromSlice(edge)
				if !ok {
					t.Fatalf("invalid address bytes for %s", row.prefix)
				}
				want := deepestName(addr, rows)
				if want == "ipv4_mapped" || want == "nat64_well_known" {
					embedded := netip.AddrFrom4([4]byte(edge[12:]))
					if name := deepestName(embedded, v4); name != "" {
						want += "/" + name
					}
				}
				got := webhook.ClassifyAddress(addr.String())
				if got.Family != family || got.Reason != want {
					t.Errorf("%s edge %s: got %s/%s, want %s/%s", row.prefix, addr, got.Family, got.Reason, family, want)
				}
			}
		}
	}
}

func TestWebhookRebindingAndDialGuard(t *testing.T) {
	for _, tc := range []struct {
		answer, code, reason, dial string
	}{
		{"10.0.0.5", "blocked_address", "private_use", ""},
		{"93.184.216.34", "connection_refused", "", "93.184.216.34:443"},
	} {
		t.Run(tc.code, func(t *testing.T) {
			dialed := make(chan string, 1)
			lookups := 0
			c := webhook.NewDeliveryClient(webhook.DeliveryConfig{
				Resolver: webhook.ResolverFunc(func(_ context.Context, host string) ([]string, error) {
					lookups++
					if host != "hooks.example.test" {
						t.Errorf("resolved hostname %q", host)
					}
					return []string{tc.answer}, nil
				}),
				Dialer: webhook.DialerFunc(func(_ context.Context, _, address string) (net.Conn, error) {
					select {
					case dialed <- address:
					default:
						t.Error("unexpected repeated dial")
					}
					return nil, errors.New("stub dial failure")
				}),
			})
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://hooks.example.test/x", nil)
			if err != nil {
				t.Fatal(err)
			}
			var refusal *webhook.DeliveryError
			if _, refusal = c.Do(req, 1024); refusal == nil || refusal.Code != tc.code || refusal.Reason != tc.reason {
				t.Fatalf("delivery refusal = %+v, want %s/%s", refusal, tc.code, tc.reason)
			}
			var gotDial string
			var called bool
			select {
			case gotDial = <-dialed:
				called = true
			default:
			}
			if lookups != 1 || called != (tc.dial != "") || gotDial != tc.dial {
				t.Fatalf("got %d lookups and dial %q (called=%v), want 1 lookup and dial %q", lookups, gotDial, called, tc.dial)
			}
		})
	}
}

func TestWebhookReplayWindowBoundaries(t *testing.T) {
	r, key, _ := newTestReceiver(t)
	for i, tc := range []struct {
		delta  int64
		badMAC bool
		status int
		code   string
	}{
		{-300, false, 200, ""},
		{-301, false, 401, "stale_timestamp"},
		{300, false, 200, ""},
		{301, false, 401, "future_timestamp"},
		{-301, true, 401, "bad_signature"},
	} {
		id := fmt.Sprintf("msg_replay%d", i)
		d := signDelivery(key, id, testSub, testNow, testNow+tc.delta, testBody)
		if tc.badMAC {
			d.Body = append(d.Body, ' ')
		}
		got := r.Handle(d)
		if got.Status != tc.status || got.Code != tc.code {
			t.Errorf("offset %d, badMAC %v: got %d/%s, want %d/%s", tc.delta, tc.badMAC, got.Status, got.Code, tc.status, tc.code)
		}
		if tc.status == 200 && string(got.Body) != `{"status":"accepted"}` {
			t.Errorf("offset %d: expected acceptance body", tc.delta)
		}
	}
}

func TestWebhookNoSecretInErrors(t *testing.T) {
	r, key, encoded := newTestReceiver(t)
	valid := func(sub string, ts int64) webhook.Delivery {
		return signDelivery(key, testID, sub, testNow, ts, testBody)
	}
	bad := valid(testSub, testNow)
	bad.Body = append(bad.Body, ' ')
	malformed := valid(testSub, testNow)
	malformed.Headers[2][1] = "v1, " + encoded
	for _, tc := range []struct {
		d    webhook.Delivery
		code string
	}{
		{bad, "bad_signature"},
		{valid("sub_a3f1c8e2b0d49f7f", testNow), "unknown_subscription"},
		{malformed, "malformed_signature_header"},
		{valid(testSub, testNow-301), "stale_timestamp"},
	} {
		t.Run(tc.code, func(t *testing.T) {
			got := r.Handle(tc.d)
			if got.Code != tc.code {
				t.Fatalf("wrong Result.Code, want %s", tc.code)
			}
			if strings.Contains(got.Code, encoded) || strings.Contains(got.Code, string(key)) {
				t.Fatal("result code contains secret material")
			}
			assertSafeError(t, got.Body, tc.code, key, encoded)
		})
	}
}

func assertSafeError(t *testing.T, body []byte, code string, key []byte, encoded string) {
	t.Helper()
	if bytes.Contains(body, []byte(encoded)) || bytes.Contains(body, key) {
		t.Fatal("error body contains secret material")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		t.Fatal("expected a JSON object")
	}
	if tok, err := dec.Token(); err != nil || tok != "error" {
		t.Fatal("expected a single error member")
	}
	var fields map[string]any
	if err := dec.Decode(&fields); err != nil || len(fields) != 2 {
		t.Fatal("expected an error object containing only code and message")
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		t.Fatal("expected only one error member")
	}
	if _, err := dec.Token(); err != io.EOF {
		t.Fatal("unexpected bytes after the error object")
	}
	if got, ok := fields["code"].(string); !ok || got != code {
		t.Fatalf("wrong error code, want %s", code)
	}
	if _, ok := fields["message"].(string); !ok {
		t.Fatal("expected a string error message")
	}
}
