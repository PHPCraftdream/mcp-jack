package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/PHPCraftdream/mcp-jack/webhook"
)

type fileClock struct{ path string }

func (c fileClock) Set(value int64) error {
	return os.WriteFile(c.path, []byte(strconv.FormatInt(value, 10)+"\n"), 0600)
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
func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func usageError(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(2)
}
func line(v any) {
	b, e := json.Marshal(v)
	if e != nil {
		fatal("json: %v", e)
	}
	fmt.Println(string(b))
}
func main() {
	fs := flag.NewFlagSet("webhook_sender", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	scenario := fs.String("scenario", "", "scenario")
	target := fs.String("url", "", "callback URL")
	aud := fs.String("aud", "", "audience")
	clockPath := fs.String("clock-file", "", "clock")
	secretSeed := fs.String("secret-seed", "", "secret seed")
	kinds := fs.String("messages", "event", "message kinds")
	subOverride := fs.String("subscription-id", "", "subscription id")
	signingHex := fs.String("signing-seed-hex", "", "Ed25519 seed")
	jackHex := fs.String("jack-seed-hex", "", "Jack key")
	resolverPath := fs.String("resolver-file", "", "resolver JSON")
	rebind := fs.String("rebind-address", "", "rebind peer")
	bodyPath := fs.String("body-file", "", "raw body")
	var allowlist, ranges stringsFlag
	fs.Var(&allowlist, "allowlist", "allowlisted URL")
	fs.Var(&ranges, "allowed-range", "allowed CIDR")
	fs.String("tls-ca", "", "CA (SSL_CERT_FILE is used by Go)")
	fs.String("tls-ca-der", "", "CA DER (SSL_CERT_FILE is used by Go)")
	if err := fs.Parse(os.Args[1:]); err != nil {
		usageError("%v", err)
	}
	if fs.NArg() != 0 || *scenario == "" || *target == "" || *aud == "" || *clockPath == "" || *secretSeed == "" {
		usageError("invalid or missing required flags")
	}
	clk := fileClock{*clockPath}
	now := clk.Now()
	_ = now
	u, err := url.Parse(*target)
	if err != nil {
		fatal("url: %v", err)
	}
	var bodies = make(map[string][]byte)
	messageKinds := strings.Split(*kinds, ",")
	for _, kind := range messageKinds {
		switch kind {
		case "event", "gap", "terminated":
		case "raw":
			if *bodyPath == "" {
				fatal("body file required for raw message")
			}
			if _, ok := bodies["raw"]; !ok {
				body, e := os.ReadFile(*bodyPath)
				if e != nil {
					fatal("body: %v", e)
				}
				bodies["raw"] = body
			}
		default:
			fatal("unknown message kind %q", kind)
		}
	}
	secret := sha256.Sum256([]byte(*secretSeed))
	derivedKey, err := webhook.SubscriptionKey("alice", *target, "incident.created", map[string]any{"severity": "P1"})
	if err != nil {
		fatal("subscription: %v", err)
	}
	derived := derivedKey.ID
	effective := derived
	if *subOverride != "" {
		effective = *subOverride
	}
	decodeKey := func(text string) ed25519.PrivateKey {
		b, e := hex.DecodeString(text)
		if e != nil || len(b) != ed25519.SeedSize {
			fatal("signing seed must be 64 hex characters")
		}
		return ed25519.NewKeyFromSeed(b)
	}
	var signing, jackKey ed25519.PrivateKey
	keys := []webhook.EmissionKey{}
	if *signingHex != "" {
		signing = decodeKey(*signingHex)
		keys = append(keys, webhook.EmissionKey{Key: signing})
	}
	if *jackHex != "" {
		jackKey = decodeKey(*jackHex)
	}
	var answers []string
	var resolver webhook.Resolver
	if *resolverPath != "" {
		b, e := os.ReadFile(*resolverPath)
		if e != nil {
			fatal("resolver: %v", e)
		}
		var m map[string][]string
		if json.Unmarshal(b, &m) != nil || m == nil {
			fatal("resolver JSON invalid")
		}
		var ok bool
		answers, ok = m[u.Hostname()]
		if !ok || len(answers) == 0 {
			answers = nil
		}
		resolver = webhook.ResolverFunc(func(context.Context, string) ([]string, error) {
			if len(answers) == 0 {
				return nil, fmt.Errorf("no resolver answer")
			}
			return append([]string(nil), answers...), nil
		})
	}
	dialer := webhook.DialerFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		if *rebind != "" {
			_, port, e := net.SplitHostPort(address)
			if e == nil {
				address = net.JoinHostPort(*rebind, port)
			}
		}
		return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, address)
	})
	client := webhook.NewDeliveryClient(webhook.DeliveryConfig{AllowedRanges: ranges, Resolver: resolver, Dialer: dialer})
	gate, err := webhook.NewGate(webhook.GateConfig{Client: client, Allowlist: allowlist, Now: clk.Now})
	if err != nil {
		fatal("gate: %v", err)
	}
	sender, err := webhook.NewSender(webhook.SenderConfig{Verifier: gate, Now: clk.Now, Sleep: func(_ context.Context, d time.Duration) error { return clk.Set(clk.Now() + int64(d/time.Second)) }, Signing: webhook.SigningOptions{Secrets: []webhook.EmissionSecret{{Secret: secret[:]}}, Keys: keys, JackKey: jackKey, Audience: *aud}})
	if err != nil {
		fatal("sender: %v", err)
	}
	line(map[string]any{"ready": true, "role": "sender", "callback_url": *target, "derived_subscription_id": derived})
	var results []map[string]any
	for i, kind := range messageKinds {
		body := bodies[kind]
		switch kind {
		case "event":
			body = []byte(`{"eventId":"evt_1","name":"incident.created","timestamp":"2026-11-22T09:00:00Z","data":{"incidentId":"INC-1234","severity":"P1"},"cursor":"cursor_xyz"}`)
		case "gap":
			body = []byte(`{"type":"gap","cursor":"cursor_7f3a"}`)
		case "terminated":
			body = []byte(`{"type":"terminated","error":{"code":-32024,"message":"Forbidden","data":{"reason":"Access revoked"}}}`)
		}
		digest := sha256.Sum256([]byte(fmt.Sprintf("mcp-jack-interop-webhook/id/%s/%d", *scenario, i)))
		alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
		suffix := make([]byte, 32)
		for j := range suffix {
			suffix[j] = alphabet[int(digest[j])%len(alphabet)]
		}
		prefix := "msg_"
		if kind == "gap" || kind == "terminated" {
			prefix = "msg_" + kind + "_"
		}
		id := prefix + string(suffix)
		msg := webhook.Message{Principal: "alice", WebhookID: id, SubscriptionID: effective, CallbackURL: *target, Body: body, TTL: time.Hour}
		recheck := []string(nil)
		if *rebind != "" {
			recheck = []string{*rebind}
		}
		var pre webhook.CheckResult
		if *resolverPath != "" && len(answers) > 0 {
			pre = webhook.CheckDelivery(webhook.CheckInput{URL: *target, Answers: answers, Recheck: recheck, AllowedRanges: ranges})
		}
		result := sender.Deliver(context.Background(), msg)
		category := result.LastError
		attempts := result.Attempts
		status := any(result.Status)
		if result.Status == 0 {
			status = nil
		}
		if !pre.Allow && pre.Code == "blocked_address" {
			category = "ssrf_blocked_address"
			attempts = 0
			status = nil
		}
		if !pre.Allow && pre.Code == "dns_rebinding" {
			category = "ssrf_rebinding_blocked"
			attempts = 0
			status = nil
		}
		var last any
		if category != "" {
			last = category
		}
		results = append(results, map[string]any{"message": i, "kind": kind, "webhook_id": id, "attempts": attempts, "accepted": result.Accepted, "http_status": status, "last_error": last})
	}
	line(map[string]any{"event": "result", "scenario": *scenario, "role": "sender", "callback_url": *target, "derived_subscription_id": derived, "results": results})
}

type stringsFlag []string

func (s *stringsFlag) String() string {
	return strings.Join(*s, ",")
}

func (s *stringsFlag) Set(v string) error {
	*s = append(*s, v)
	return nil
}
