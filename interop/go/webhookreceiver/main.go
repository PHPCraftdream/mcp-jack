package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/PHPCraftdream/mcp-jack/webhook"
)

type fileClock struct {
	path string
}

func (c fileClock) Now() int64 {
	b, e := os.ReadFile(c.path)
	if e != nil {
		panic(e)
	}
	n, e := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if e != nil {
		panic(e)
	}
	return n
}

func fatal(f string, a ...any) {
	fmt.Fprintf(os.Stderr, f+"\n", a...)
	os.Exit(1)
}

func usageError(f string, a ...any) {
	fmt.Fprintf(os.Stderr, f+"\n", a...)
	os.Exit(2)
}
func out(v any) {
	b, e := json.Marshal(v)
	if e != nil {
		fatal("json: %v", e)
	}
	fmt.Println(string(b))
}
func main() {
	fs := flag.NewFlagSet("webhook_receiver", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	port := fs.Int("port", -1, "port")
	cert := fs.String("tls-cert", "", "TLS certificate")
	key := fs.String("tls-key", "", "TLS key")
	clockPath := fs.String("clock-file", "", "clock")
	seed := fs.String("secret-seed", "", "secret seed")
	sub := fs.String("subscription-id", "", "subscription id")
	callback := fs.String("callback-url", "", "callback URL")
	aud := fs.String("aud", "", "audience")
	pending := fs.Bool("pending-secret", false, "pending secret")
	cardPath := fs.String("card-file", "", "card JSON")
	cardURL := fs.String("card-mcp-url", "", "MCP URL")
	enforce := fs.Bool("enforce-server-identity", false, "enforce identity")
	requireJack := fs.Bool("require-jack", false, "require w1")
	serverKid := fs.String("mcp-server-kid", "", "server kid")
	enqueueFail := fs.Int("enqueue-fail", 0, "initial enqueue failures")
	if err := fs.Parse(os.Args[1:]); err != nil {
		usageError("%v", err)
	}
	if fs.NArg() != 0 || *port < 0 || *port > 65535 || *cert == "" || *key == "" || *clockPath == "" || *seed == "" || *sub == "" || *callback == "" || *aud == "" || *enqueueFail < 0 {
		usageError("invalid or missing required flags")
	}
	clk := fileClock{*clockPath}
	clockBytes, err := os.ReadFile(clk.path)
	if err != nil {
		fatal("clock: %v", err)
	}
	clockNow, err := strconv.ParseInt(strings.TrimSpace(string(clockBytes)), 10, 64)
	if err != nil {
		fatal("clock: %v", err)
	}
	_ = clockNow
	pair, err := tls.LoadX509KeyPair(*cert, *key)
	if err != nil {
		fatal("TLS files: %v", err)
	}
	secret := sha256.Sum256([]byte(*seed))
	secrets := []webhook.Secret{{Key: secret[:]}}
	routed := []string{*sub}
	if *pending {
		secrets[0].CallbackURL = *callback
		routed = nil
	} else {
		secrets[0].SubscriptionID = *sub
	}
	var keys webhook.KeySource = webhook.StaticKeySource(nil)
	if *cardPath != "" {
		b, e := os.ReadFile(*cardPath)
		if e != nil {
			fatal("card: %v", e)
		}
		elapsed := int64(0)
		decision, refusal := webhook.FetchDecision(webhook.CardFetchInput{MCPURL: *cardURL, CardURL: mustCardURL(*cardURL), Status: 200, Headers: map[string]string{"content-type": "application/mcp-server-card+json"}, Body: b, ElapsedMS: &elapsed, Options: webhook.CardOptions{MCPServerKID: *serverKid}})
		if refusal != nil {
			fatal("card: %v", refusal)
		}
		keys = webhook.StaticKeySource(decision.Keys.Accepted)
	}
	enqueued := 0
	fails := *enqueueFail
	var stateMu sync.Mutex
	var deliveryMu sync.Mutex
	forwarded := make([][]byte, 0)
	var deliveryKind any
	receiver, err := webhook.NewReceiver(webhook.ReceiverConfig{Secrets: secrets, Routed: routed, Keys: keys, EnforceServerIdentity: *enforce, MCPServerKID: *serverKid, Jack: jackConfig(*requireJack, *aud, *sub, *callback), Enqueue: func(m webhook.ReceivedMessage) error {
		stateMu.Lock()
		defer stateMu.Unlock()
		deliveryKind = m.Kind
		if fails > 0 {
			fails--
			return fmt.Errorf("enqueue failure")
		}
		if m.Type == "verification" {
			return nil
		}
		enqueued++
		forwarded = append(forwarded, append([]byte(nil), m.Raw...))
		return nil
	}})
	if err != nil {
		fatal("receiver: %v", err)
	}
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", *port))
	if err != nil {
		fatal("listen: %v", err)
	}
	bound := ln.Addr().(*net.TCPAddr).Port
	out(map[string]any{"ready": true, "role": "receiver", "port": bound, "subscription_id": *sub, "subscription_known": contains(receiver.State().Routed, *sub)})
	seq := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deliveryMu.Lock()
		defer deliveryMu.Unlock()
		if r.Method != "POST" || r.URL.Path != pathOf(*callback) {
			respond(w, 404, map[string]any{"error": map[string]string{"code": "no_route", "message": "not a delivery endpoint"}})
			return
		}
		hdr := make([][2]string, 0)
		for name, values := range r.Header {
			for _, v := range values {
				hdr = append(hdr, [2]string{name, v})
			}
		}
		if r.ContentLength >= 0 {
			hdr = append(hdr, [2]string{"content-length", strconv.FormatInt(r.ContentLength, 10)})
		}
		var body []byte
		var result webhook.ReceiverResult
		deliveryKind = nil
		if r.ContentLength > webhook.MaxBodyBytes {
			// Handle the declared framing limit before touching the request body;
			// its response is the SDK's authoritative refusal.
			result = receiver.Handle(webhook.Delivery{Headers: hdr, Body: nil, Now: clk.Now()})
		} else {
			var readErr error
			body, readErr = io.ReadAll(io.LimitReader(r.Body, webhook.MaxBodyBytes+1))
			if readErr != nil {
				// Never authenticate an incomplete body.
				respond(w, 400, map[string]any{"error": map[string]string{"code": "body_read_failed", "message": "could not read request body"}})
				return
			}
			result = receiver.Handle(webhook.Delivery{Headers: hdr, Body: body, Now: clk.Now()})
		}
		bodyStatus := any(nil)
		var payload map[string]any
		_ = json.Unmarshal(result.Body, &payload)
		if v, ok := payload["status"].(string); ok {
			bodyStatus = v
		}
		if _, ok := payload["challenge"].(string); ok {
			bodyStatus = "challenge"
		}
		kind := deliveryKind
		if result.Code == "subscription_terminated" {
			var decoded map[string]any
			if json.Unmarshal(body, &decoded) == nil {
				if t, ok := decoded["type"].(string); ok {
					kind = t
				} else if decoded["eventId"] != nil {
					kind = "event"
				}
			}
		} else if result.Status == 200 {
			if _, ok := payload["challenge"].(string); ok {
				kind = "verification"
			} else if len(result.Delivered) > 0 {
				var decoded map[string]any
				if json.Unmarshal(result.Delivered[0], &decoded) == nil {
					if t, ok := decoded["type"].(string); ok {
						kind = t
					} else if decoded["eventId"] != nil {
						kind = "event"
					}
				}
			}
		}
		forwardedVals := make([]string, 0)
		for _, b := range result.Delivered {
			forwardedVals = append(forwardedVals, base64.RawURLEncoding.EncodeToString(b))
		}
		values := func(name string) string {
			for _, p := range hdr {
				if strings.EqualFold(p[0], name) {
					return p[1]
				}
			}
			return ""
		}
		challenge := any(nil)
		if v, ok := payload["challenge"].(string); ok {
			challenge = v
		}
		out(map[string]any{"event": "delivery", "seq": seq, "status": result.Status, "code": nullable(result.Code), "body_status": bodyStatus, "kind": kind, "webhook_id": values("webhook-id"), "subscription_id": values("x-mcp-subscription-id"), "webhook_timestamp": values("webhook-timestamp"), "challenge": challenge, "enqueued": enqueued, "forwarded": forwardedVals, "headers": hdr, "body_b64u": base64.RawURLEncoding.EncodeToString(body)})
		seq++
		w.Header().Set("Content-Type", "application/json")
		if result.Status == 401 {
			w.Header().Set("WWW-Authenticate", "Webhook-Signature")
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(result.Body)))
		w.WriteHeader(result.Status)
		_, _ = w.Write(result.Body)
	})
	srv := &http.Server{Handler: handler}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	tlsListener := tls.NewListener(ln, tlsConfig)
	tlsConfig.Certificates = []tls.Certificate{pair}
	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGTERM, syscall.SIGINT)
	stdinEOF := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, os.Stdin)
		close(stdinEOF)
	}()
	serve := make(chan error, 1)
	go func() { serve <- srv.Serve(tlsListener) }()
	select {
	case <-done:
		_ = srv.Close()
	case <-stdinEOF:
		_ = srv.Close()
	case e := <-serve:
		if e != http.ErrServerClosed {
			fatal("serve: %v", e)
		}
	}
}
func respond(w http.ResponseWriter, status int, payload any) {
	b, err := json.Marshal(payload)
	if err != nil {
		fatal("response JSON: %v", err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

func jackConfig(enabled bool, aud, sub, url string) *webhook.JackConfig {
	if !enabled {
		return nil
	}
	return &webhook.JackConfig{Aud: aud, CallbackURLs: map[string]string{sub: url}}
}
func mustCardURL(mcp string) string {
	u, e := webhook.DefaultCardURL(mcp)
	if !e {
		fatal("invalid card MCP URL")
	}
	return u
}
func pathOf(text string) string {
	u, e := http.NewRequest("GET", text, nil)
	if e != nil {
		return ""
	}
	return u.URL.Path
}
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}
func contains(values []string, s string) bool {
	for _, v := range values {
		if v == s {
			return true
		}
	}
	return false
}
