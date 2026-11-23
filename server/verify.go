package server

import (
	"github.com/PHPCraftdream/mcp-jack/server/internal/verify"
	"github.com/PHPCraftdream/mcp-jack/server/internal/webhookkey"
)

// The verifier moved to server/internal/verify; this file is a facade
// re-exporting the public names so the server package API is unchanged.
// This is a file-layout move only; no behavior changed.

// DefaultWindow is the timestamp acceptance window in seconds (spec 01
// section 4 step 6).
const DefaultWindow = verify.DefaultWindow

// Names of the protocol-native tools (spec 03). Tools with the "jack." prefix
// never reach the wrapped handler.
const (
	ToolServerKey         = verify.ToolServerKey
	ToolWebhookKey        = verify.ToolWebhookKey
	ToolEnroll            = verify.ToolEnroll
	ToolWhoAmI            = verify.ToolWhoAmI
	ToolRotateKey         = verify.ToolRotateKey
	ToolAdminUserList     = verify.ToolAdminUserList
	ToolAdminUserGet      = verify.ToolAdminUserGet
	ToolAdminUserCreate   = verify.ToolAdminUserCreate
	ToolAdminUserSetAdmin = verify.ToolAdminUserSetAdmin
	ToolAdminUserRevoke   = verify.ToolAdminUserRevoke
	ToolAdminInviteCreate = verify.ToolAdminInviteCreate
	ToolAdminInviteList   = verify.ToolAdminInviteList
	ToolAdminInviteRevoke = verify.ToolAdminInviteRevoke
)

// IsNativeTool reports whether name is one of the protocol-native tools.
func IsNativeTool(name string) bool { return verify.IsNativeTool(name) }

type (
	// NativeCall is what a protocol-native tool handler receives.
	NativeCall = verify.NativeCall
	// NativeResult is the successful outcome of a native tool.
	NativeResult = verify.NativeResult
	// NativeTools implements the protocol-native tools of spec 03.
	NativeTools = verify.NativeTools
	// Config configures a Verifier.
	Config = verify.Config
	// Verifier authenticates and authorizes requests (spec 01 section 4,
	// spec 02 section 4).
	Verifier = verify.Verifier
	// Request is one HTTP request reduced to what verification needs.
	Request = verify.Request
	// Result is the outcome of Verify.
	Result = verify.Result
)

// WebhookKey is one accepted webhook signing key for jack.server.webhook_key.
type WebhookKey = webhookkey.Key

// WebhookKeyConfig configures the read-only jack.server.webhook_key tool.
type WebhookKeyConfig = webhookkey.Config

// NewWebhookKeyTool returns the opt-in NativeTools implementation for
// jack.server.webhook_key. Assign it to Config.WebhookKeys; without it, a
// verifier answers calls to this tool with 403 operation_denied.
// The configured keys must be a subset of the keys the Server Card publishes (R7.6).
func NewWebhookKeyTool(cfg WebhookKeyConfig) (NativeTools, error) { return webhookkey.New(cfg) }

// NewVerifier validates cfg and returns a Verifier.
func NewVerifier(cfg Config) (*Verifier, error) {
	return verify.NewVerifier(cfg)
}

// HasServerKeys, RawNow and WithIdentity stay unexported in
// server/internal/verify: they are internal helpers of the middleware, not
// part of the public server API.

// maxDurableTimestamp mirrors the internal verify boundary for admission tests.
const maxDurableTimestamp int64 = verify.MaxDurableTimestamp

// AdmissionStateStore moved to server/internal/state; this alias keeps the
// public API unchanged.
type AdmissionStateStore = verify.AdmissionStateStore

// Compile-time checks that both stores satisfy the admission interface.
var (
	_ AdmissionStateStore = (*MemoryState)(nil)
	_ AdmissionStateStore = (*FileState)(nil)
)

type (
	// NonceAdmission is delivered only after successful signature verification.
	NonceAdmission = verify.NonceAdmission
	// NonceReceipt confirms the exact final reservation.
	NonceReceipt = verify.NonceReceipt
	// NonceLease holds the serving epoch until the request completes.
	NonceLease = verify.NonceLease
	// DurableNonceStore is a trusted, application-owned transactional boundary.
	DurableNonceStore = verify.DurableNonceStore
)

// NonceIntentID builds the exact storage identity from the candidate durable-nonce spec.
func NonceIntentID(deployment string, admission NonceAdmission, operation [16]byte) (string, error) {
	return verify.NonceIntentID(deployment, admission, operation)
}
