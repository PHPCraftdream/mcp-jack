package verify

import (
	"encoding/json"
	"errors"
	"math"
	"strings"
	"sync"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	auditimpl "github.com/PHPCraftdream/mcp-jack/server/internal/audit"
	"github.com/PHPCraftdream/mcp-jack/server/internal/invite"
	"github.com/PHPCraftdream/mcp-jack/server/internal/jsonvalue"
	nonceimpl "github.com/PHPCraftdream/mcp-jack/server/internal/nonce"
	"github.com/PHPCraftdream/mcp-jack/server/internal/rpcbody"
	stateimpl "github.com/PHPCraftdream/mcp-jack/server/internal/state"
)

// Local aliases of the internal state and audit types; this is a file-layout
// move only, the concrete definitions live in the internal packages.
type (
	RegistryEntry = stateimpl.RegistryEntry
	StateStore    = stateimpl.StateStore
	AuditEvent    = auditimpl.AuditEvent
	AuditSink     = auditimpl.AuditSink
)

// Audit outcome values.
const (
	AuditSuccess = auditimpl.AuditSuccess
	AuditFailure = auditimpl.AuditFailure
)

// DefaultWindow is the timestamp acceptance window in seconds (spec 01
// section 4 step 6).
const DefaultWindow = 30

// Names of the protocol-native tools (spec 03). Tools with the "jack." prefix
// never reach the wrapped handler.
const (
	ToolServerKey         = "jack.server.key"
	ToolEnroll            = "jack.enroll"
	ToolWhoAmI            = "jack.whoami"
	ToolRotateKey         = "jack.key.rotate"
	ToolAdminUserList     = "jack.admin.user.list"
	ToolAdminUserGet      = "jack.admin.user.get"
	ToolAdminUserCreate   = "jack.admin.user.create"
	ToolAdminUserSetAdmin = "jack.admin.user.set_admin"
	ToolAdminUserRevoke   = "jack.admin.user.revoke"
	ToolAdminInviteCreate = "jack.admin.invite.create"
	ToolAdminInviteList   = "jack.admin.invite.list"
	ToolAdminInviteRevoke = "jack.admin.invite.revoke"
)

var nativeTools = map[string]bool{
	ToolEnroll: true, ToolWhoAmI: true, ToolRotateKey: true,
	ToolAdminUserList: true, ToolAdminUserGet: true, ToolAdminUserCreate: true,
	ToolAdminUserSetAdmin: true, ToolAdminUserRevoke: true,
	ToolAdminInviteCreate: true, ToolAdminInviteList: true, ToolAdminInviteRevoke: true,
}

// IsNativeTool reports whether name is one of the protocol-native tools.
func IsNativeTool(name string) bool { return nativeTools[name] }

// auditedTool reports whether calls to the tool are written to the audit
// sink (spec 03 section 8).
func auditedTool(name string) bool {
	return name == ToolEnroll || name == ToolRotateKey || strings.HasPrefix(name, "jack.admin.")
}

// NativeCall is what a protocol-native tool handler receives.
type NativeCall struct {
	// Tool is the tool name, one of the Tool* constants.
	Tool string
	// Arguments is params.arguments as sent, or nil when absent.
	Arguments json.RawMessage
	// Caller is the registry entry of the authenticated key, or nil when the
	// request is an enrollment signed by a key that is not registered yet.
	Caller *RegistryEntry
	// Kid is the key id from the Jack-Auth header (for enrollment, the hash
	// of the submitted public key).
	Kid string
	// TS is the ts parameter of the Jack-Auth header (rotate proofs bind it).
	TS int64
	// Now is the verifier clock, Unix seconds.
	Now int64
	// Aud is the server audience string.
	Aud string
	// State is the registry and invite store; handlers change it only through
	// State.Update so a change is atomic.
	State StateStore
	// Target is an output: the handler sets it to what the audit event names
	// as the target (a kid, an invite id or a name), even when it fails.
	Target string
}

// NativeResult is the successful outcome of a native tool.
type NativeResult struct {
	// Structured becomes the structuredContent of the MCP CallToolResult.
	Structured any
}

// NativeTools implements the protocol-native tools of spec 03. Call returns a
// *jack.Error for every protocol rejection; the verifier writes the audit
// event and the middleware turns the outcome into an HTTP response.
type NativeTools interface {
	Call(c *NativeCall) (NativeResult, *jack.Error)
}

// Config configures a Verifier.
type Config struct {
	// Aud is the audience identifier signed into every request (spec 01
	// section 3.1). It is compared with this value, never with the Host header.
	Aud string
	// State is the registry and invite store.
	State StateStore
	// Nonces records seen (kid, nonce) pairs.
	Nonces *nonceimpl.NonceStore
	// DurableNonces is selected explicitly instead of the volatile Nonces.
	DurableNonces DurableNonceStore
	// Audit receives audit events for protocol-native admin calls; optional.
	Audit AuditSink
	// Native serves current-v1 tools; nil forbids them, ServerKeys is selected separately.
	Native NativeTools
	// ServerKeys serves only the candidate jack.server.key; the default native allowlist is unchanged.
	ServerKeys NativeTools
	// Window is 0 (default 30) or an integer from 1 through 120 seconds.
	Window int64
	// Now returns the current Unix time in seconds; nil means the wall clock.
	// Tests inject a fixed clock. The Verifier never lets its request time go
	// backwards: a sample below the highest one seen is raised to it.
	// Response timestamps use the raw sample.
	Now func() int64
}

// audHasControl reports whether aud contains a byte below 0x20 or the byte
// 0x7f (spec 01 section 3.1 aud rules).
func audHasControl(aud string) bool {
	for i := 0; i < len(aud); i++ {
		if aud[i] < 0x20 || aud[i] == 0x7f {
			return true
		}
	}
	return false
}

// Verifier authenticates and authorizes requests (spec 01 section 4, spec 02
// section 4). Request decisions use max(clock sample, highest sample seen),
// preventing a backward clock step from reviving expired keys, invites or nonces.
type Verifier struct {
	cfg Config
	mu  sync.Mutex
	// high is the highest clock sample seen; it starts at the minimum so the
	// first sample is used unchanged.
	high int64
}

// RawNow returns the verifier's raw clock sample (the configured Now source,
// which the Verifier defaults to the wall clock). Response timestamps use the
// raw sample; request decisions use the effective time instead.
func RawNow(v *Verifier) int64 { return v.cfg.Now() }

// HasServerKeys reports whether the verifier serves the candidate
// jack.server.key tool through its separate ServerKeys profile.
func HasServerKeys(v *Verifier) bool { return v.cfg.ServerKeys != nil }

// effectiveNow returns max(sample, highest sample seen) and records it.
func (v *Verifier) effectiveNow(sample int64) int64 {
	v.mu.Lock()
	defer v.mu.Unlock()
	if sample > v.high {
		v.high = sample
	}
	return v.high
}

// NewVerifier validates cfg and returns a Verifier.
func NewVerifier(cfg Config) (*Verifier, error) {
	switch {
	case cfg.Aud == "":
		return nil, errors.New("server: Config.Aud must be non-empty")
	case audHasControl(cfg.Aud):
		return nil, errors.New("server: Config.Aud must not contain control characters")
	case cfg.State == nil:
		return nil, errors.New("server: Config.State must be set")
	case cfg.Nonces == nil && cfg.DurableNonces == nil:
		return nil, errors.New("server: Config.Nonces must be set")
	case cfg.Nonces != nil && cfg.DurableNonces != nil:
		return nil, errors.New("server: select exactly one nonce profile")
	}
	if cfg.DurableNonces != nil {
		if _, ok := cfg.State.(AdmissionStateStore); !ok {
			return nil, errors.New("server: durable admission requires coordinated state")
		}
		if cfg.Window < 0 || cfg.Window > 120 {
			return nil, errors.New("server: durable window must be between 1 and 120 seconds")
		}
	} else if cfg.Window < 0 || cfg.Window > 120 {
		return nil, errors.New("server: window must be 0 (default 30) or an integer between 1 and 120 seconds")
	}
	if cfg.Window == 0 {
		cfg.Window = DefaultWindow
	}
	if cfg.Now == nil {
		cfg.Now = func() int64 { return time.Now().Unix() }
	}
	return &Verifier{cfg: cfg, high: math.MinInt64}, nil
}

// Request is one HTTP request reduced to what verification needs.
type Request struct {
	Method string
	// Target is the origin-form request target exactly as received.
	Target string
	// AuthValues holds the values of every Jack-Auth header, in order.
	AuthValues []string
	// Body is the exact request body.
	Body []byte
	// AuthenticateOnly stops after spec 01 section 4 steps 1-8 (authentication
	// and nonce recording) with no body classification or dispatch. It is used
	// for non-POST requests in a non-legacy deployment profile, where the spec
	// 04 era decision runs after authentication.
	AuthenticateOnly bool
	// ClassifyOnly stops after body classification and before dispatch: the
	// request is authenticated and classified (identity, request signature,
	// RPCID, Tool and Native are set) but no native tool runs and the wrapped
	// handler is never reached. The caller completes the request with Dispatch.
	// It is used for POST requests of a non-legacy deployment profile, where the
	// spec 04 rules run before dispatch.
	ClassifyOnly bool
}

// Result is the outcome of Verify.
type Result struct {
	// Accepted is true when the request is authenticated and authorized.
	Accepted bool
	// Kid is the authenticated key id (empty when authentication failed).
	Kid string
	// Identity is the verified caller identity (spec 02 section 3): exactly
	// the {kid, name, admin} of the caller's registry entry at verification
	// time. It is set whenever the caller is a registered key and is handed
	// to the wrapped handler on forwarded accepts; native jack.* calls never
	// reach the wrapped handler.
	Identity Identity
	// HTTPStatus, Code and Message describe a rejection.
	HTTPStatus int
	Code       string
	Message    string
	// NonceRecorded is true when the request consumed its nonce, which is
	// when authentication succeeded (an authorization rejection still counts).
	NonceRecorded bool
	// RequestSig is the sig of the request; the response is bound to it.
	RequestSig string
	// RPCID is the id of the JSON-RPC request, as sent (nil for notifications
	// and non-JSON-RPC requests).
	RPCID json.RawMessage
	// Tool is the tool name of a tools/call request.
	Tool string
	// Native is true when the request called a protocol-native tool.
	Native bool
	// BodyRefusal is the rpcbody reason when body classification refused the
	// body; rpcbody.ReasonNone otherwise.
	BodyRefusal int
	// Structured is the structuredContent of a successful native tool call.
	Structured any
	// Audit is the audit event written for the call, if any.
	Audit *AuditEvent
	// Pending is true when Verify ran with Request.ClassifyOnly and stopped
	// before dispatch: authentication and body classification succeeded,
	// Accepted is false and HTTPStatus is zero. Call Dispatch to finish it.
	Pending   bool
	admission *admissionLease
	pending   *pendingDispatch
}

// pendingDispatch carries the authenticated, classified request to Dispatch.
type pendingDispatch struct {
	auth   jack.RequestAuth
	now    int64
	caller *RegistryEntry
	msg    rpcbody.RPCMessage
}

func rejection(status int, code, message string) Result {
	return Result{HTTPStatus: status, Code: code, Message: message}
}

func rejectionFrom(err error) Result {
	var je *jack.Error
	if errors.As(err, &je) {
		return Result{HTTPStatus: je.HTTPStatus, Code: je.Code, Message: je.Message}
	}
	return rejection(500, "internal_error", "internal error")
}

// EntryActive reports whether now is inside the entry's validity interval
// (spec 02 section 1: not_before <= now < not_after). It was previously the
// unexported server.entryActive; the body is unchanged. It is a package
// function, not a method, so it stays available to the native tools without
// extending the public Verifier method set.
func EntryActive(e RegistryEntry, now int64) bool {
	return (e.NotBefore == nil || *e.NotBefore <= now) && (e.NotAfter == nil || now < *e.NotAfter)
}

// Verify runs the pipeline of spec 01 section 4 and spec 02 section 4 on one
// request. It stops at the first failing step; a rejection never reveals more
// than its code. With Request.ClassifyOnly it runs in two phases: Verify
// authenticates and classifies and hands back a Pending Result, and Dispatch
// runs the native tool call (or marks an ordinary request accepted) once the
// caller has applied its own pre-dispatch rules.
func (v *Verifier) Verify(req Request) Result {
	now := v.cfg.Now()
	effective := v.effectiveNow(now)

	auth, err := jack.ParseRequestAuth(req.AuthValues)
	if err != nil {
		return rejectionFrom(err)
	}

	var verifyKey []byte
	caller, known := v.cfg.State.Lookup(auth.Kid)
	if known {
		if !EntryActive(caller, effective) {
			return rejection(401, jack.CodeKeyInactive, "key is not active")
		}
		key, err := jack.DecodeBase64URLFixed(caller.PublicKey, 32)
		if err != nil {
			return rejection(500, "internal_error", "registry holds an invalid public key")
		}
		verifyKey = key
	} else {
		key, rej, ok := enrollmentKey(req, auth.Kid, v.cfg.State, effective)
		if !ok {
			return rej
		}
		verifyKey = key
	}

	var distance uint64
	if effective < auth.TS {
		distance = uint64(auth.TS) - uint64(effective)
	} else {
		distance = uint64(effective) - uint64(auth.TS)
	}
	if distance > uint64(v.cfg.Window) {
		return rejection(401, jack.CodeTimestampOutOfWindow, "timestamp is outside the acceptance window")
	}

	sig, err := jack.DecodeBase64URLFixed(auth.Sig, 64)
	if err != nil {
		return rejection(401, jack.CodeBadSignature, "malformed signature")
	}
	signing := jack.RequestSigningString(req.Method, req.Target, v.cfg.Aud, auth.Kid, auth.TS, auth.Nonce, req.Body)
	if !jack.Verify(verifyKey, []byte(signing), sig) {
		return rejection(401, jack.CodeBadSignature, "signature does not verify")
	}

	if v.cfg.DurableNonces != nil {
		res, finalNow := v.reserveDurable(auth, signing, caller, known)
		handedOff := false
		defer func() {
			if !handedOff {
				res.Done()
			}
		}()
		if res.HTTPStatus != 0 {
			handedOff = true
			return res
		}
		var callerPtr *RegistryEntry
		if known {
			callerPtr = &caller
		}
		out := v.authorize(req, auth, finalNow, callerPtr, res)
		handedOff = true
		return out
	}

	// The nonce is recorded only after the signature verified, so
	// requests that fail verification cannot fill the cache (spec 01 section 4).
	if v.cfg.Nonces.CheckAndRecord(auth.Kid, auth.Nonce, effective, auth.TS+v.cfg.Window) {
		return rejection(401, jack.CodeReplayedNonce, "nonce was already used")
	}

	res := Result{Kid: auth.Kid, NonceRecorded: true, RequestSig: auth.Sig}
	var callerPtr *RegistryEntry
	if known {
		callerPtr = &caller
	}
	return v.authorize(req, auth, effective, callerPtr, res)
}

// authorize is step 9: body shape, protocol-native tools, the admin gate for
// jack.admin.*, and forwarding of everything else unchanged (spec 02 sections
// 2-3). With req.ClassifyOnly it stops before running the native tool and
// defers that step to Dispatch.
func (v *Verifier) authorize(req Request, auth jack.RequestAuth, now int64, caller *RegistryEntry, res Result) Result {
	if caller != nil {
		res.Identity = snapshotOf(*caller)
	}
	fail := func(status int, code, message string) Result {
		res.HTTPStatus, res.Code, res.Message = status, code, message
		return res
	}
	if req.AuthenticateOnly {
		res.Accepted = true
		return res
	}
	if req.Method == "GET" {
		res.Accepted = true
		return res
	}

	msg, bodyRefusal := rpcbody.ClassifyReason(req.Body)
	if bodyRefusal != rpcbody.ReasonNone {
		res.BodyRefusal = bodyRefusal
		return fail(400, jack.CodeInvalidRequest, "the body is not an acceptable JSON-RPC object")
	}
	res.RPCID = msg.ID
	if msg.Kind == rpcbody.KindResponse {
		res.Accepted = true
		return res
	}
	if msg.HasTool {
		res.Tool = msg.Tool
	}

	if msg.HasTool && strings.HasPrefix(msg.Tool, "jack.") {
		res.Native = true
		native := v.cfg.Native
		if msg.Tool == ToolServerKey {
			native = v.cfg.ServerKeys
		} else if !IsNativeTool(msg.Tool) {
			return fail(403, jack.CodeOperationDenied, "operation is not permitted")
		}
		if native == nil {
			return fail(403, jack.CodeOperationDenied, "operation is not permitted")
		}
		if req.ClassifyOnly {
			res.Pending = true
			res.pending = &pendingDispatch{auth: auth, now: now, caller: caller, msg: msg}
			return res
		}
		return v.runNative(res, auth, now, caller, msg)
	}

	if caller == nil {
		// Unreachable: only a jack.enroll request passes step 4 without a
		// registry entry, and it was handled above.
		return fail(401, jack.CodeUnknownKey, "unknown key")
	}
	if req.ClassifyOnly {
		res.Pending = true
		res.pending = &pendingDispatch{auth: auth, now: now, caller: caller, msg: msg}
		return res
	}
	res.Accepted = true
	return res
}

// runNative runs the protocol-native tool of an authenticated, classified
// request and records its audit event (spec 02 sections 2-3, spec 03 section 8).
func (v *Verifier) runNative(res Result, auth jack.RequestAuth, now int64, caller *RegistryEntry, msg rpcbody.RPCMessage) Result {
	fail := func(status int, code, message string) Result {
		res.HTTPStatus, res.Code, res.Message = status, code, message
		return res
	}
	native := v.cfg.Native
	if msg.Tool == ToolServerKey {
		native = v.cfg.ServerKeys
	}
	call := &NativeCall{
		Tool: msg.Tool, Arguments: msg.Arguments, Caller: caller, Kid: auth.Kid, TS: auth.TS,
		Now: now, Aud: v.cfg.Aud, State: v.cfg.State,
	}
	out, jerr := native.Call(call)
	var event *AuditEvent
	if auditedTool(msg.Tool) {
		event = &AuditEvent{Time: now, Tool: msg.Tool, Outcome: AuditSuccess, ActorKid: auth.Kid, Target: call.Target}
		if caller != nil {
			event.ActorName = caller.Name
		}
		if jerr != nil {
			event.Outcome, event.Code = AuditFailure, jerr.Code
		}
		res.Audit = event
		if v.cfg.Audit != nil {
			_ = v.cfg.Audit.Record(*event)
		}
	}
	if jerr != nil {
		return fail(jerr.HTTPStatus, jerr.Code, jerr.Message)
	}
	res.Accepted = true
	res.Structured = out.Structured
	return res
}

// Dispatch runs the deferred step of a Request.ClassifyOnly verification: the
// native tool call and its audit event, or marks an ordinary request accepted
// for forwarding. It is a no-op when the result is not Pending. The nonce
// lease is still held by the Result and is released by Done after the caller
// has answered.
func (v *Verifier) Dispatch(res Result) Result {
	p := res.pending
	if p == nil {
		return res
	}
	res.pending = nil
	res.Pending = false
	if p.msg.HasTool && strings.HasPrefix(p.msg.Tool, "jack.") {
		return v.runNative(res, p.auth, p.now, p.caller, p.msg)
	}
	res.Accepted = true
	return res
}

// enrollmentKey implements the one exception to "unknown key is rejected"
// (spec 01 section 4, spec 03 section 3.2): an unregistered kid is accepted
// for a POST tools/call of jack.enroll whose submitted public key is valid and
// hashes to kid and whose code names a live invite. The request is then
// verified against that submitted key. The invite lookup is read-only and runs
// before any nonce is recorded; a dead invite looks like any unknown kid.
func enrollmentKey(req Request, kid string, state StateStore, now int64) ([]byte, Result, bool) {
	unknown := rejection(401, jack.CodeUnknownKey, "unknown key")
	if req.Method != "POST" {
		return nil, unknown, false
	}
	msg, ok := rpcbody.Classify(req.Body)
	if !ok || msg.Kind != rpcbody.KindRequest || msg.Method != "tools/call" || !msg.HasTool || msg.Tool != ToolEnroll {
		return nil, unknown, false
	}
	var args map[string]json.RawMessage
	if err := json.Unmarshal(msg.Arguments, &args); err != nil || args == nil {
		return nil, unknown, false
	}
	if !liveInvite(state, args["code"], now) {
		return nil, unknown, false
	}
	submitted, ok := jsonvalue.String(args["public_key"])
	if !ok {
		return nil, unknown, false
	}
	key, err := jack.DecodeBase64URLFixed(submitted, 32)
	if err != nil || jack.ValidatePublicKey(key) != nil {
		return nil, rejection(400, jack.CodeKeyRejected, "public key is not acceptable"), false
	}
	if jack.KeyID(key) != kid {
		return nil, unknown, false
	}
	return key, Result{}, true
}

// liveInvite reports whether rawCode is a JSON string holding a canonical
// invite code that names a stored invite not yet expired at now. The jack.enroll
// tool re-checks and consumes the invite atomically.
func liveInvite(state StateStore, rawCode json.RawMessage, now int64) bool {
	code, ok := jsonvalue.String(rawCode)
	if !ok {
		return false
	}
	codeBytes, err := jack.DecodeBase64URLFixed(code, 32)
	if err != nil {
		return false
	}
	inviteRec, found := state.LookupInvite(invite.InviteIDOf(codeBytes))
	return found && now < inviteRec.ExpiresAt
}
