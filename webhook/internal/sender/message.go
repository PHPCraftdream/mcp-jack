package sender

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"slices"
	"strconv"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/dsig"
	"github.com/PHPCraftdream/mcp-jack/webhook/internal/secret"
	"github.com/PHPCraftdream/mcp-jack/webhook/internal/urlcheck"
	"github.com/PHPCraftdream/mcp-jack/webhook/internal/wire"
)

// SigningOptions contains the current and any still-active previous signing
// material. JackKey is optional; an empty JackKID is derived from its public key.
type SigningOptions struct {
	Secrets  []dsig.EmissionSecret
	Keys     []dsig.EmissionKey
	JackKey  ed25519.PrivateKey
	JackKID  string
	Audience string
}

// Message holds the stable delivery fields and raw JSON across all attempts.
type Message struct {
	WebhookID, SubscriptionID, CallbackURL string
	Body                                   []byte
}

// NewWebhookID generates a per-message, per-subscription ID. A nil reader uses
// crypto/rand.Reader. Keep the returned ID unchanged across retries.
func NewWebhookID(kind string, random io.Reader) (string, error) {
	prefix := "msg_"
	switch kind {
	case "":
	case "gap", "terminated", "verification":
		prefix += kind + "_"
	default:
		return "", errors.New("unknown webhook message kind")
	}
	if random == nil {
		random = rand.Reader
	}
	var buf [32]byte
	if _, err := io.ReadFull(random, buf[:]); err != nil {
		return "", err
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	// Modulo bias still leaves over 181 bits of min-entropy for uniform input.
	for i, b := range buf {
		buf[i] = alphabet[int(b)%len(alphabet)]
	}
	return prefix + string(buf[:]), nil
}

func prepareSigning(opts SigningOptions) (SigningOptions, error) {
	if len(opts.Secrets) == 0 {
		return SigningOptions{}, errors.New("sender requires a webhook secret")
	}
	opts.Secrets = slices.Clone(opts.Secrets)
	for i, entry := range opts.Secrets {
		if len(entry.Secret) == 0 {
			return SigningOptions{}, errors.New("empty webhook secret")
		}
		opts.Secrets[i].Secret = slices.Clone(entry.Secret)
	}
	opts.Keys = slices.Clone(opts.Keys)
	for i, entry := range opts.Keys {
		if len(entry.Key) != ed25519.PrivateKeySize {
			return SigningOptions{}, errors.New("invalid webhook signing key length")
		}
		opts.Keys[i].Key = slices.Clone(entry.Key)
	}
	if opts.JackKey != nil {
		if len(opts.JackKey) != ed25519.PrivateKeySize {
			return SigningOptions{}, errors.New("invalid Jack webhook signing key length")
		}
		opts.JackKey = slices.Clone(opts.JackKey)
		digest := sha256.Sum256(opts.JackKey.Public().(ed25519.PublicKey))
		kid := secret.EncodeURL(digest[:])
		if opts.JackKID != "" && opts.JackKID != kid {
			return SigningOptions{}, errors.New("Jack webhook key ID does not match its public key")
		}
		opts.JackKID = kid
	}
	return opts, nil
}

func (opts SigningOptions) request(ctx context.Context, msg Message, now int64) (*http.Request, string) {
	if _, err := urlcheck.Check(msg.CallbackURL); err != nil {
		return nil, err.Code
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, msg.CallbackURL, bytes.NewReader(msg.Body))
	if err != nil {
		return nil, urlcheck.CodeInvalidCallbackURL
	}
	if !wire.ValidWebhookID(msg.WebhookID) {
		return nil, "malformed_webhook_id"
	}
	if !wire.ValidSubscriptionID(msg.SubscriptionID) {
		return nil, "malformed_subscription_id"
	}
	timestamp := strconv.FormatInt(now, 10)
	if !wire.ValidTimestamp(timestamp) {
		return nil, "malformed_webhook_timestamp"
	}
	signature, err := dsig.EmissionHeader(dsig.Emission{
		WebhookID: msg.WebhookID, Timestamp: timestamp, EndpointID: msg.SubscriptionID,
		Body: msg.Body, Secrets: opts.Secrets, Keys: opts.Keys,
	})
	if err != nil {
		return nil, "signing_failed"
	}
	// Direct assignment preserves the exact R1.1 header spelling on HTTP/1.
	req.Header = http.Header{
		"Content-Type":          {"application/json"},
		"webhook-id":            {msg.WebhookID},
		"webhook-timestamp":     {timestamp},
		"webhook-signature":     {signature},
		"X-MCP-Subscription-Id": {msg.SubscriptionID},
	}
	if opts.JackKey != nil {
		auth, err := dsig.W1Sign(opts.JackKey, opts.JackKID, dsig.W1Parts{
			Aud: opts.Audience, SubscriptionID: msg.SubscriptionID,
			WebhookID: msg.WebhookID, Timestamp: timestamp, CallbackURL: msg.CallbackURL, Body: msg.Body,
		})
		if err != nil {
			return nil, "signing_failed"
		}
		req.Header["Jack-Webhook-Auth"] = []string{auth}
	}
	return req, ""
}
