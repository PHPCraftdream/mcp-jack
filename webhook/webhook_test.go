package webhook_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
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
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/webhook"
)

const (
	testSub  = "sub_a3f1c8e2b0d49f7e"
	testID   = "msg_7Qk2mZ4rT9xV1bN6pL3sD8wY5cJ0hG2f"
	testBody = `{"eventId":"evt_789","name":"incident.created","timestamp":"2026-11-22T09:00:00Z","data":{"incidentId":"INC-1234"}}`
	testNow  = int64(1795338000)
)

func newTestReceiver(t *testing.T, enqueue webhook.EnqueueFunc) (*webhook.Receiver, []byte, string) {
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
		Enqueue: enqueue,
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

func discardMessage(webhook.ReceivedMessage) error { return nil }

func TestNewReceiverRequiresEnqueue(t *testing.T) {
	r, err := webhook.NewReceiver(webhook.ReceiverConfig{})
	if r != nil || err == nil || err.Error() != "receiver: Config.Enqueue is required" {
		t.Fatalf("NewReceiver with nil Enqueue = %v, %v; want the receiver's required Enqueue error", r, err)
	}
}

type observedResponse struct {
	*httptest.ResponseRecorder
	beforeHeader func(int)
}

func (w observedResponse) WriteHeader(status int) {
	w.beforeHeader(status)
	w.ResponseRecorder.WriteHeader(status)
}

func TestWebhookReceiverAdapter(t *testing.T) {
	var queued []webhook.ReceivedMessage
	r, key, encoded := newTestReceiver(t, func(msg webhook.ReceivedMessage) error {
		queued = append(queued, msg)
		return nil
	})
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
		h.ServeHTTP(observedResponse{w, func(status int) {
			if status == http.StatusOK && (len(queued) != 1 || string(queued[0].Raw) != testBody) {
				t.Fatalf("before HTTP 200, want exactly one enqueue of the raw body; got %+v", queued)
			}
		}}, req)
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
	if len(queued) != 1 {
		t.Fatalf("enqueued %d messages across all requests, want 1", len(queued))
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

func TestCardSourceReceiverRotation(t *testing.T) {
	// Isolate the test root so hostname and TLS verification stay enabled and
	// no other test sees a changed trust store.
	const child = "MCP_JACK_WEBHOOK_CARD_TLS_TEST_CHILD"
	if os.Getenv(child) != "1" {
		cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestCardSourceReceiverRotation$")
		cmd.Env = append(os.Environ(), child+"=1", "GODEBUG=x509usefallbackroots=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("TLS test subprocess: %v\n%s", err, output)
		}
		return
	}

	var cardBody atomic.Value // []byte, replaced between refreshes
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet || req.URL.Path != "/mcp/server-card" {
			t.Errorf("unexpected Server Card request: %s %s", req.Method, req.URL)
		}
		w.Header().Set("Content-Type", "application/mcp-server-card+json")
		_, _ = w.Write(cardBody.Load().([]byte))
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
	mcpURL := "https://" + net.JoinHostPort("example.com", port) + "/mcp"
	client := webhook.NewDeliveryClient(webhook.DeliveryConfig{
		AllowedRanges: []string{"127.0.0.1/32"},
		Resolver: webhook.ResolverFunc(func(_ context.Context, host string) ([]string, error) {
			if host != "example.com" {
				return nil, fmt.Errorf("unexpected host %q", host)
			}
			return []string{"127.0.0.1"}, nil
		}),
		Dialer: webhook.DialerFunc(func(ctx context.Context, network, target string) (net.Conn, error) {
			if target != net.JoinHostPort("127.0.0.1", port) {
				return nil, fmt.Errorf("unexpected dial target %q", target)
			}
			return (&net.Dialer{}).DialContext(ctx, network, address)
		}),
	})
	source, err := webhook.NewCardSource(webhook.CardSourceConfig{Client: client, MCPURL: mcpURL})
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("0123456789ABCDEF0123456789ABCDEF")
	var enqueued int
	r, err := webhook.NewReceiver(webhook.ReceiverConfig{
		Keys:                  source,
		EnforceServerIdentity: true,
		Secrets:               []webhook.Secret{{SubscriptionID: testSub, Key: secret}},
		Routed:                []string{testSub},
		Enqueue:               func(webhook.ReceivedMessage) error { enqueued++; return nil },
	})
	if err != nil {
		t.Fatal(err)
	}

	key := func(seed byte) (ed25519.PrivateKey, webhook.JWK) {
		priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
		pub := priv.Public().(ed25519.PublicKey)
		return priv, webhook.JWK{Kty: "OKP", Crv: "Ed25519", Kid: jack.KeyID(pub), X: base64.RawURLEncoding.EncodeToString(pub)}
	}
	oldPriv, oldJWK := key(20)
	newPriv, newJWK := key(21)
	publishAndRefresh := func(keys ...webhook.JWK) {
		t.Helper()
		card := map[string]any{"remotes": []any{map[string]any{
			"url": mcpURL,
			"extensionsInfo": map[string]any{"io.modelcontextprotocol/events": map[string]any{
				"webhooks": map[string]any{"signingKeys": map[string]any{"keys": keys}},
			}},
		}}}
		body, err := json.Marshal(card)
		if err != nil {
			t.Fatal(err)
		}
		cardBody.Store(body)
		if refusal := source.Refresh(t.Context()); refusal != nil {
			t.Fatal(refusal)
		}
	}
	check := func(id string, priv ed25519.PrivateKey, jwk webhook.JWK, status int, code string) {
		t.Helper()
		d := signDelivery(secret, id, testSub, testNow, testNow, testBody)
		signature, err := webhook.EmissionHeader(webhook.Emission{
			WebhookID: id, Timestamp: strconv.FormatInt(testNow, 10), EndpointID: testSub, Body: d.Body,
			Secrets: []webhook.EmissionSecret{{Secret: secret, Current: true}},
			Keys:    []webhook.EmissionKey{{Key: priv, KID: jwk.Kid, Current: true}},
		})
		if err != nil {
			t.Fatal(err)
		}
		d.Headers[2][1] = signature
		if got := r.Handle(d); got.Status != status || got.Code != code {
			t.Fatalf("%s: got %d/%s, want %d/%s", id, got.Status, got.Code, status, code)
		}
	}
	publishAndRefresh(oldJWK)
	check("msg_old_only", oldPriv, oldJWK, 200, "")
	check("msg_new_unpublished", newPriv, newJWK, 401, "bad_server_signature")
	publishAndRefresh(oldJWK, newJWK)
	check("msg_old_overlap", oldPriv, oldJWK, 200, "")
	check("msg_new_overlap", newPriv, newJWK, 200, "")
	publishAndRefresh(newJWK)
	check("msg_old_removed", oldPriv, oldJWK, 401, "bad_server_signature")
	check("msg_new_only", newPriv, newJWK, 200, "")
	if enqueued != 4 {
		t.Fatalf("enqueued %d messages, want 4", enqueued)
	}
}

func TestGateChallenge(t *testing.T) {
	const principal, callback, ttl = "subscriber", "https://hooks.example.test/x", time.Minute
	client := webhook.NewDeliveryClient(webhook.DeliveryConfig{
		Resolver: webhook.ResolverFunc(func(context.Context, string) ([]string, error) {
			return nil, errors.New("no well-known document available")
		}),
	})
	gate, err := webhook.NewGate(webhook.GateConfig{Client: client, Now: func() int64 { return testNow }})
	if err != nil {
		t.Fatal(err)
	}
	if refusal := gate.Covers(t.Context(), principal, callback, ttl); refusal == nil || refusal.Reason != "no_route" {
		t.Fatalf("Covers before challenge = %v, want no_route", refusal)
	}
	if gate.Fresh(principal, callback) {
		t.Fatal("fresh verdict before challenge")
	}
	nonce, refusal := gate.Begin(principal, callback)
	if refusal != nil || !webhook.NonceOK(nonce) {
		t.Fatalf("Begin = %q, %v; want a valid nonce", nonce, refusal)
	}
	r, secret, _ := newTestReceiver(t, discardMessage)
	body := `{"type":"verification","challenge":"` + nonce + `"}`
	res := r.Handle(signDelivery(secret, "msg_verification_test", testSub, testNow, testNow, body))
	if refusal := webhook.ChallengeEcho(res.Status, string(res.Body), nonce); refusal != nil {
		t.Fatalf("receiver challenge echo: %v", refusal)
	}
	var echo struct {
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal(res.Body, &echo); err != nil {
		t.Fatal(err)
	}
	if refusal := gate.Accept(principal, callback, nonce, echo.Challenge, ttl); refusal != nil {
		t.Fatal(refusal)
	}
	if !gate.Fresh(principal, callback) {
		t.Fatal("accepted challenge did not cache a fresh verdict")
	}
	if refusal := gate.Covers(t.Context(), principal, callback, ttl); refusal != nil {
		t.Fatalf("Covers after challenge = %v, want cached consent", refusal)
	}
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
	r, key, _ := newTestReceiver(t, discardMessage)
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
	r, key, encoded := newTestReceiver(t, discardMessage)
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
