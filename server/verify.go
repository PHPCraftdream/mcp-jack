package server

import (
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	jack "github.com/PHPCraftdream/mcp-jack"
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
	Nonces *NonceStore
	// DurableNonces выбирается явно вместо volatile Nonces.
	DurableNonces DurableNonceStore
	// Audit receives audit events for protocol-native admin calls; optional.
	Audit AuditSink
	// Native — current-v1 tools; nil запрещает их, ServerKeys выбирается отдельно.
	Native NativeTools
	// ServerKeys включает только candidate jack.server.key; default native allowlist неизменен.
	ServerKeys NativeTools
	// Window is the timestamp window in seconds; zero means DefaultWindow.
	Window int64
	// Now returns the current Unix time in seconds; nil means the wall clock.
	// Tests inject a fixed clock.
	Now func() int64
}

// Verifier authenticates and authorizes requests (spec 01 section 4, spec 02
// section 4).
type Verifier struct{ cfg Config }

// NewVerifier validates cfg and returns a Verifier.
func NewVerifier(cfg Config) (*Verifier, error) {
	switch {
	case cfg.Aud == "":
		return nil, errors.New("server: Config.Aud must be non-empty")
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
	}
	if cfg.Window <= 0 {
		cfg.Window = DefaultWindow
	}
	if cfg.Now == nil {
		cfg.Now = func() int64 { return time.Now().Unix() }
	}
	return &Verifier{cfg: cfg}, nil
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
	// Structured is the structuredContent of a successful native tool call.
	Structured any
	// Audit is the audit event written for the call, if any.
	Audit     *AuditEvent
	admission *admissionLease
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

// entryActive reports whether now is inside the entry's validity interval
// (spec 02 section 1: not_before <= now < not_after).
func entryActive(e RegistryEntry, now int64) bool {
	return (e.NotBefore == nil || *e.NotBefore <= now) && (e.NotAfter == nil || now < *e.NotAfter)
}

// Verify runs the pipeline of spec 01 section 4 and spec 02 section 4 on one
// request. It stops at the first failing step; a rejection never reveals more
// than its code.
func (v *Verifier) Verify(req Request) Result {
	now := v.cfg.Now()

	auth, err := jack.ParseRequestAuth(req.AuthValues)
	if err != nil {
		return rejectionFrom(err)
	}

	var verifyKey []byte
	caller, known := v.cfg.State.Lookup(auth.Kid)
	if known {
		if !entryActive(caller, now) {
			return rejection(401, jack.CodeKeyInactive, "key is not active")
		}
		key, err := jack.DecodeBase64URLFixed(caller.PublicKey, 32)
		if err != nil {
			return rejection(500, "internal_error", "registry holds an invalid public key")
		}
		verifyKey = key
	} else {
		key, rej, ok := enrollmentKey(req, auth.Kid)
		if !ok {
			return rej
		}
		verifyKey = key
	}

	var distance uint64
	if now < auth.TS {
		distance = uint64(auth.TS) - uint64(now)
	} else {
		distance = uint64(now) - uint64(auth.TS)
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
	// unauthenticated requests cannot fill the cache (spec 01 section 4).
	if v.cfg.Nonces.CheckAndRecord(auth.Kid, auth.Nonce, now, auth.TS+v.cfg.Window) {
		return rejection(401, jack.CodeReplayedNonce, "nonce was already used")
	}

	res := Result{Kid: auth.Kid, NonceRecorded: true, RequestSig: auth.Sig}
	var callerPtr *RegistryEntry
	if known {
		callerPtr = &caller
	}
	return v.authorize(req, auth, now, callerPtr, res)
}

// authorize is step 9: body shape, protocol-native tools, the admin gate for
// jack.admin.*, and forwarding of everything else unchanged (spec 02 sections
// 2-3).
func (v *Verifier) authorize(req Request, auth jack.RequestAuth, now int64, caller *RegistryEntry, res Result) Result {
	if caller != nil {
		res.Identity = snapshotOf(*caller)
	}
	fail := func(status int, code, message string) Result {
		res.HTTPStatus, res.Code, res.Message = status, code, message
		return res
	}
	if req.Method == "GET" {
		res.Accepted = true
		return res
	}

	msg, ok := classifyBody(req.Body)
	if !ok {
		return fail(400, jack.CodeInvalidRequest, "the body is not an acceptable JSON-RPC object")
	}
	res.RPCID = msg.id
	if msg.kind == kindResponse {
		res.Accepted = true
		return res
	}
	if msg.hasTool {
		res.Tool = msg.tool
	}

	if msg.hasTool && strings.HasPrefix(msg.tool, "jack.") {
		res.Native = true
		native := v.cfg.Native
		if msg.tool == ToolServerKey {
			native = v.cfg.ServerKeys
		} else if !IsNativeTool(msg.tool) {
			return fail(403, jack.CodeOperationDenied, "operation is not permitted")
		}
		if native == nil {
			return fail(403, jack.CodeOperationDenied, "operation is not permitted")
		}
		call := &NativeCall{
			Tool: msg.tool, Arguments: msg.arguments, Caller: caller, Kid: auth.Kid, TS: auth.TS,
			Now: now, Aud: v.cfg.Aud, State: v.cfg.State,
		}
		out, jerr := native.Call(call)
		var event *AuditEvent
		if auditedTool(msg.tool) {
			event = &AuditEvent{Time: now, Tool: msg.tool, Outcome: AuditSuccess, ActorKid: auth.Kid, Target: call.Target}
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

	if caller == nil {
		// Unreachable: only a jack.enroll request passes step 4 without a
		// registry entry, and it was handled above.
		return fail(401, jack.CodeUnknownKey, "unknown key")
	}
	res.Accepted = true
	return res
}

// enrollmentKey implements the one exception to "unknown key is rejected"
// (spec 01 section 4, spec 03 section 3.2): an unregistered kid is accepted
// for a POST tools/call of jack.enroll whose submitted public key is valid and
// hashes to kid. The request is then verified against that submitted key.
func enrollmentKey(req Request, kid string) ([]byte, Result, bool) {
	unknown := rejection(401, jack.CodeUnknownKey, "unknown key")
	if req.Method != "POST" {
		return nil, unknown, false
	}
	msg, ok := classifyBody(req.Body)
	if !ok || msg.kind != kindRequest || msg.method != "tools/call" || !msg.hasTool || msg.tool != ToolEnroll {
		return nil, unknown, false
	}
	var args map[string]json.RawMessage
	if err := json.Unmarshal(msg.arguments, &args); err != nil || args == nil {
		return nil, unknown, false
	}
	submitted, ok := jsonString(args["public_key"])
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

const (
	kindRequest  = 1 // a request or a notification
	kindResponse = 2 // a client answer to a server-initiated request
)

// rpcMessage is the part of a JSON-RPC object the verifier needs.
type rpcMessage struct {
	kind      int
	id        json.RawMessage
	method    string
	tool      string
	hasTool   bool
	arguments json.RawMessage
}

// classifyBody implements the body rules of spec 02 section 4. UTF-8 is
// validated before decoding because encoding/json silently replaces invalid
// bytes, and members are looked up through a map because encoding/json would
// match struct fields case-insensitively.
func classifyBody(body []byte) (rpcMessage, bool) {
	if !utf8.Valid(body) {
		return rpcMessage{}, false
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil || m == nil {
		return rpcMessage{}, false
	}
	if version, ok := jsonString(m["jsonrpc"]); !ok || version != "2.0" {
		return rpcMessage{}, false
	}

	rawMethod, hasMethod := m["method"]
	if !hasMethod {
		_, hasID := m["id"]
		_, hasResult := m["result"]
		_, hasError := m["error"]
		if hasID && hasResult != hasError {
			return rpcMessage{kind: kindResponse, id: m["id"]}, true
		}
		return rpcMessage{}, false
	}
	method, ok := jsonString(rawMethod)
	if !ok {
		return rpcMessage{}, false
	}
	msg := rpcMessage{kind: kindRequest, id: m["id"], method: method}
	if method == "tools/call" {
		var params map[string]json.RawMessage
		if err := json.Unmarshal(m["params"], &params); err != nil || params == nil {
			return rpcMessage{}, false
		}
		name, ok := jsonString(params["name"])
		if !ok {
			return rpcMessage{}, false
		}
		msg.tool, msg.hasTool, msg.arguments = name, true, params["arguments"]
	}
	return msg, true
}
