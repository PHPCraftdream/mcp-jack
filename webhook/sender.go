package webhook

import (
	"context"
	"crypto/ed25519"
	"io"
	"slices"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/delivery"
	"github.com/PHPCraftdream/mcp-jack/webhook/internal/dsig"
	"github.com/PHPCraftdream/mcp-jack/webhook/internal/ipaddr"
	"github.com/PHPCraftdream/mcp-jack/webhook/internal/sender"
	"github.com/PHPCraftdream/mcp-jack/webhook/internal/urlcheck"
)

// SenderConfig configures signing, delivery policy, and retry scheduling.
type SenderConfig = sender.Config

// Sender signs and sends webhook messages.
type Sender struct{ inner *sender.Sender }

// NewSender constructs a sender with a hardened delivery client.
func NewSender(cfg SenderConfig) (*Sender, error) {
	inner, err := sender.New(cfg)
	if err != nil {
		return nil, err
	}
	return &Sender{inner: inner}, nil
}

// AttemptResult reports the results of one delivery attempt.
type AttemptResult = sender.AttemptResult

// SenderResult describes the last attempt made during delivery, if any.
type SenderResult = sender.Result

// Attempt sends the message once, without waiting for suspension or retry.
func (s *Sender) Attempt(ctx context.Context, msg Message) AttemptResult {
	return s.inner.Attempt(ctx, msg)
}

// Deliver sends the message with the profile's retry schedule.
func (s *Sender) Deliver(ctx context.Context, msg Message) SenderResult {
	return s.inner.Deliver(ctx, msg)
}

// RetrySchedule returns the four attempt times as Unix seconds.
func RetrySchedule(t0 int64) [4]int64 { return sender.RetrySchedule(t0) }

// RetryOffsets returns the four attempt offsets in seconds.
func RetryOffsets() [4]int64 { return sender.RetryOffsets() }

// LastError maps an HTTP status to its delivery error category, if any.
func LastError(status int) string { return sender.LastError(status) }

// AttemptInput describes a completed delivery attempt.
type AttemptInput = sender.AttemptInput

// Outcome describes a retry decision.
type Outcome = sender.Outcome

// Decide determines whether a delivery is accepted, retried, or final.
func Decide(in AttemptInput) Outcome { return sender.Decide(in) }

// NewWebhookID generates an ID for an event or control envelope.
func NewWebhookID(kind string, random io.Reader) (string, error) {
	return sender.NewWebhookID(kind, random)
}

// Message holds the outbound target, identifiers, and raw body for a delivery.
type Message = sender.Message

// SigningOptions configures Standard Webhooks and Jack signing.
type SigningOptions = sender.SigningOptions

// EmissionSecret is a current or previous secret for Standard Webhooks signing.
type EmissionSecret = dsig.EmissionSecret

// EmissionKey is a current or previous Ed25519 key for Standard Webhooks signing.
type EmissionKey = dsig.EmissionKey

// Emission supplies the message and signing material for the signature header.
type Emission = dsig.Emission

// JackParts contains the fields covered by the Jack signature.
type JackParts = dsig.W1Parts

// JackHeader signs a delivery and returns the Jack-Webhook-Auth value.
func JackHeader(key ed25519.PrivateKey, kid string, parts JackParts) (string, error) {
	return dsig.W1Sign(key, kid, parts)
}

// EmissionHeader returns the webhook-signature value in profile order.
func EmissionHeader(opts Emission) (string, error) { return dsig.EmissionHeader(opts) }

// DeliveryConfig configures a hardened client and optional network hooks.
type DeliveryConfig = delivery.Config

// DeliveryClient sends requests subject to the profile's network policy.
type DeliveryClient = delivery.Client

// DeliveryResponse is a non-redirect HTTP response with a bounded body.
type DeliveryResponse = delivery.Response

// DeliveryError describes a refused attempt.
type DeliveryError = delivery.Error

// Resolver resolves host names at delivery time.
type Resolver = delivery.Resolver

// ResolverFunc adapts a function to Resolver.
type ResolverFunc = delivery.ResolverFunc

// Dialer opens a connection to a validated literal address.
type Dialer = delivery.Dialer

// DialerFunc adapts a function to Dialer.
type DialerFunc = delivery.DialerFunc

// NewDeliveryClient constructs a hardened outbound HTTP client.
func NewDeliveryClient(cfg DeliveryConfig) *DeliveryClient { return delivery.NewClient(cfg) }

// CheckInput supplies the URL and address evidence for a delivery decision.
type CheckInput = delivery.CheckInput

// CheckResult holds the address policy decision and selected target.
type CheckResult = delivery.CheckResult

// CheckDelivery applies the outbound policy without opening a connection.
func CheckDelivery(in CheckInput) CheckResult { return delivery.Check(in) }

// URL is a checked callback URL and its canonical representation.
type URL = urlcheck.URL

// URLError describes a callback URL policy refusal.
type URLError = urlcheck.Error

// CheckURL validates a callback URL and returns its parsed representation.
func CheckURL(raw string) (URL, *URLError) { return urlcheck.Check(raw) }

// Host is a parsed IP literal or DNS name.
type Host = ipaddr.Host

// ParseHost validates a callback host and returns the refusal reason, if any.
func ParseHost(host string) (Host, string) { return ipaddr.ParseHost(host) }

// AddressVerdict holds an address classification and its reason.
type AddressVerdict = ipaddr.Verdict

// ClassifyAddress classifies an address literal against the profile's tables.
func ClassifyAddress(text string) AddressVerdict { return ipaddr.ClassifyAddress(text) }

// ClassifyWithRanges classifies an address with optional operator overrides.
func ClassifyWithRanges(text string, allowedRanges []string) AddressVerdict {
	return ipaddr.ClassifyWithRanges(text, allowedRanges)
}

// IPv4Block is one row of the IPv4 address table.
type IPv4Block = ipaddr.Block4

// IPv6Block is one row of the IPv6 address table.
type IPv6Block = ipaddr.Block6

// IPV4Blocks is a snapshot of the profile's IPv4 address table.
var IPV4Blocks = slices.Clone(ipaddr.V4Blocks)

// IPV6Blocks is a snapshot of the profile's IPv6 address table.
var IPV6Blocks = slices.Clone(ipaddr.V6Blocks)
