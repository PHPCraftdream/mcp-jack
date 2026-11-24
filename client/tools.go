package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/client/internal/modern"
)

// HTTPError reports a non-2xx response whose verified body is
// {"error":{"code":...,"message":...}}.
type HTTPError struct {
	Status  int
	Code    string
	Message string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("jack client: http %d %s: %s", e.Status, e.Code, e.Message)
}

// RPCError reports the JSON-RPC error member of an otherwise successful call.
type RPCError struct {
	Code    int
	Message string
	Data    json.RawMessage
}

func (e *RPCError) Error() string {
	return fmt.Sprintf("jack client: rpc error %d: %s", e.Code, e.Message)
}

// ToolError reports an MCP result with isError true.
type ToolError struct {
	Message    string
	Structured json.RawMessage
}

func (e *ToolError) Error() string {
	return fmt.Sprintf("jack client: tool error: %s", e.Message)
}

// wireError mirrors the tolerant error envelope of spec 01 section 5
// (unsigned 401 bodies) and verified non-2xx bodies.
type wireError struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// parseErrorBody decodes {"error":{"code":string,"message":string}} tolerantly:
// any unknown shape yields empty strings.
func parseErrorBody(body []byte) (code, message string) {
	var w wireError
	if err := json.Unmarshal(body, &w); err != nil {
		return "", ""
	}
	return w.Error.Code, w.Error.Message
}

// Protocol-native tool names (spec 03).
const (
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

// Entry is one registry key entry (spec 03 sections 3.3).
type Entry struct {
	KID       string `json:"kid"`
	PublicKey string `json:"public_key"`
	Name      string `json:"name"`
	Admin     bool   `json:"admin"`
	NotBefore *int64 `json:"not_before"`
	NotAfter  *int64 `json:"not_after"`
}

// WhoAmIResult describes the calling key (spec 03 section 3.3).
type WhoAmIResult struct {
	KID       string `json:"kid"`
	Name      string `json:"name"`
	Admin     bool   `json:"admin"`
	NotBefore *int64 `json:"not_before"`
	NotAfter  *int64 `json:"not_after"`
}

// EnrollResult describes the key just enrolled via an invite (spec 03 section 3.2).
type EnrollResult struct {
	KID   string `json:"kid"`
	Name  string `json:"name"`
	Admin bool   `json:"admin"`
}

// KidResult reports the kid of the affected registry entry.
type KidResult struct {
	KID string `json:"kid"`
}

// InviteCreateResult carries a freshly minted invite (spec 03 section 3.2).
type InviteCreateResult struct {
	InviteID  string `json:"invite_id"`
	Code      string `json:"code"`
	ExpiresAt int64  `json:"expires_at"`
}

// InviteListEntry is one live invite (spec 03 section 3.3).
type InviteListEntry struct {
	InviteID  string `json:"invite_id"`
	Admin     bool   `json:"admin"`
	CreatedBy string `json:"created_by"`
	CreatedAt int64  `json:"created_at"`
	ExpiresAt int64  `json:"expires_at"`
}

// InviteRevokeResult confirms a revoked invite.
type InviteRevokeResult struct {
	InviteID string `json:"invite_id"`
}

// UserCreateParams are the arguments of jack.admin.user.create.
type UserCreateParams struct {
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
	Admin     *bool  `json:"admin,omitempty"`
	NotBefore *int64 `json:"not_before,omitempty"`
	NotAfter  *int64 `json:"not_after,omitempty"`
}

// InviteCreateParams are the arguments of jack.admin.invite.create.
type InviteCreateParams struct {
	Admin         *bool  `json:"admin,omitempty"`
	TTLSeconds    *int64 `json:"ttl_seconds,omitempty"`
	KeyTTLSeconds *int64 `json:"key_ttl_seconds,omitempty"`
}

// enrollArguments is ordered code,name,public_key (spec 03 section 3.2).
type enrollArguments struct {
	Code      string `json:"code"`
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
}

// rotateArguments is ordered public_key,proof (spec 03 section 3.1).
type rotateArguments struct {
	PublicKey string `json:"public_key"`
	Proof     string `json:"proof"`
}

// Enroll enrolls a NEW key with an invite code; the WHOLE request is signed
// by the new key (spec 03 section 3.2).
func (c *Client) Enroll(ctx context.Context, code, name string, newSigner Signer) (EnrollResult, error) {
	if newSigner == nil {
		return EnrollResult{}, fmt.Errorf("jack client: nil new signer for enroll")
	}
	args := enrollArguments{
		Code:      code,
		Name:      name,
		PublicKey: jack.EncodeBase64URL(newSigner.PublicKey()),
	}
	var out EnrollResult
	if err := c.call(ctx, newSigner, ToolEnroll, args, &out); err != nil {
		return EnrollResult{}, err
	}
	return out, nil
}

// WhoAmI asks the server to describe the calling key.
func (c *Client) WhoAmI(ctx context.Context) (WhoAmIResult, error) {
	var out WhoAmIResult
	if err := c.call(ctx, nil, ToolWhoAmI, nil, &out); err != nil {
		return WhoAmIResult{}, err
	}
	return out, nil
}

// RotateKey rotates from the client's current key to newSigner: the new key
// signs the rotate proof, the CURRENT key signs the request, and the proof ts
// must equal the header ts, so the signing clock is pinned (spec 03 section 3.1).
func (c *Client) RotateKey(ctx context.Context, newSigner Signer) (KidResult, error) {
	if newSigner == nil {
		return KidResult{}, fmt.Errorf("jack client: nil new signer for rotation")
	}
	now := c.now()
	ts := now.Unix()
	proof, err := newSigner.Sign([]byte(jack.RotateProofString(c.aud, c.signer.KID(), newSigner.KID(), ts)))
	if err != nil {
		return KidResult{}, fmt.Errorf("jack client: signing rotate proof: %w", err)
	}
	args := rotateArguments{
		PublicKey: jack.EncodeBase64URL(newSigner.PublicKey()),
		Proof:     jack.EncodeBase64URL(proof),
	}
	var out KidResult
	ctx = withFixedNow(WithRequestSigner(ctx, c.signer), now)
	if err := c.call(ctx, c.signer, ToolRotateKey, args, &out); err != nil {
		return KidResult{}, err
	}
	return out, nil
}

// userListWrapper decodes the {"users":[...]} envelope.
type userListWrapper struct {
	Users []Entry `json:"users"`
}

// inviteListWrapper decodes the {"invites":[...]} envelope.
type inviteListWrapper struct {
	Invites []InviteListEntry `json:"invites"`
}

// AdminUserList lists all registry entries.
func (c *Client) AdminUserList(ctx context.Context) ([]Entry, error) {
	var w userListWrapper
	if err := c.call(ctx, nil, ToolAdminUserList, nil, &w); err != nil {
		return nil, err
	}
	return w.Users, nil
}

// AdminUserGet returns one registry entry by kid.
func (c *Client) AdminUserGet(ctx context.Context, kid string) (Entry, error) {
	args := map[string]string{"kid": kid}
	var out Entry
	if err := c.call(ctx, nil, ToolAdminUserGet, args, &out); err != nil {
		return Entry{}, err
	}
	return out, nil
}

// AdminUserCreate registers a key directly as an admin operation.
func (c *Client) AdminUserCreate(ctx context.Context, p UserCreateParams) (KidResult, error) {
	var out KidResult
	if err := c.call(ctx, nil, ToolAdminUserCreate, p, &out); err != nil {
		return KidResult{}, err
	}
	return out, nil
}

// AdminUserSetAdmin sets the admin flag of one entry (spec 03 section 3.3).
// The admin argument is REQUIRED on the wire: it marshals always.
func (c *Client) AdminUserSetAdmin(ctx context.Context, kid string, admin bool) (Entry, error) {
	args := struct {
		Kid   string `json:"kid"`
		Admin bool   `json:"admin"`
	}{Kid: kid, Admin: admin}
	var out Entry
	if err := c.call(ctx, nil, ToolAdminUserSetAdmin, args, &out); err != nil {
		return Entry{}, err
	}
	return out, nil
}

// AdminUserRevoke revokes one registry entry.
func (c *Client) AdminUserRevoke(ctx context.Context, kid string) (KidResult, error) {
	args := map[string]string{"kid": kid}
	var out KidResult
	if err := c.call(ctx, nil, ToolAdminUserRevoke, args, &out); err != nil {
		return KidResult{}, err
	}
	return out, nil
}

// AdminInviteCreate mints an invite.
func (c *Client) AdminInviteCreate(ctx context.Context, p InviteCreateParams) (InviteCreateResult, error) {
	var out InviteCreateResult
	if err := c.call(ctx, nil, ToolAdminInviteCreate, p, &out); err != nil {
		return InviteCreateResult{}, err
	}
	return out, nil
}

// AdminInviteList lists all invites.
func (c *Client) AdminInviteList(ctx context.Context) ([]InviteListEntry, error) {
	var w inviteListWrapper
	if err := c.call(ctx, nil, ToolAdminInviteList, nil, &w); err != nil {
		return nil, err
	}
	return w.Invites, nil
}

// AdminInviteRevoke revokes one invite.
func (c *Client) AdminInviteRevoke(ctx context.Context, inviteID string) (InviteRevokeResult, error) {
	args := map[string]string{"invite_id": inviteID}
	var out InviteRevokeResult
	if err := c.call(ctx, nil, ToolAdminInviteRevoke, args, &out); err != nil {
		return InviteRevokeResult{}, err
	}
	return out, nil
}

// The modern-era projected call flow (spec 04 section 6, C5/C6 and C10-C12).
//
// CallModernTool and CallModernEvent are modern-only helpers: they always
// speak the modern era at modern.ModernMin and Config.Era does not affect
// them. CallTool shares this exact flow when its era is modern.

// The definition list methods and the events methods of the modern-era
// projected flow.
const (
	modernMethodToolsList         = "tools/list"
	modernMethodToolsCall         = "tools/call"
	modernMethodEventsList        = "events/list"
	modernMethodEventsPoll        = "events/poll"
	modernMethodEventsStream      = "events/stream"
	modernMethodEventsSubscribe   = "events/subscribe"
	modernMethodEventsUnsubscribe = "events/unsubscribe"
)

// jackToolPrefix is the name prefix of the protocol-native jack.* tools: they
// are not in tools/list and carry no x-mcp-header annotations, so a projected
// tools/call skips the definition fetch and the projection for them.
const jackToolPrefix = "jack."

// modernToolsPlan is the tools plan: validated against tools/list and sent as
// tools/call.
var modernToolsPlan = modernCallPlan{
	listMethod: modernMethodToolsList,
	callMethod: modernMethodToolsCall,
	kind:       "tool",
}

// modernEventsPlan is the events plan: validated against events/list, and its
// callMethod is replaced by the requested events method.
var modernEventsPlan = modernCallPlan{
	listMethod: modernMethodEventsList,
	kind:       "event type",
}

// modernRefusalCodeHeaderMismatch is the JSON-RPC -32020 header-mismatch
// refusal that the C10 and C12 resync reacts to.
const modernRefusalCodeHeaderMismatch = -32020

// modernWireRequest is one generic modern-era JSON-RPC request: params is a
// map so the caller decides which members it carries (C1 `_meta` alone for a
// definition list, name, arguments and `_meta` for a projected call). Its
// field order is not part of any wire contract.
type modernWireRequest struct {
	JSONRPC string         `json:"jsonrpc"`
	ID      int64          `json:"id"`
	Method  string         `json:"method"`
	Params  map[string]any `json:"params"`
}

// marshalModernWireRequest marshals the body of one signed modern-era request.
func marshalModernWireRequest(id int64, method string, params map[string]any) ([]byte, error) {
	return json.Marshal(modernWireRequest{JSONRPC: "2.0", ID: id, Method: method, Params: params})
}

// modernListEntry is one tool or event type descriptor of a tools/list or
// events/list result: the name and the raw inputSchema that carries the
// x-mcp-header annotations.
type modernListEntry struct {
	Name        string          `json:"name"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

// modernToolsListResult is the result of a tools/list answer.
type modernToolsListResult struct {
	Tools []modernListEntry `json:"tools"`
}

// modernEventsListResult is the result of an events/list answer, in the Events
// extension descriptor shape.
type modernEventsListResult struct {
	Events []modernListEntry `json:"events"`
}

// modernListResponse is the JSON-RPC envelope of a tools/list or events/list
// answer. The result is kept raw because its shape is method-specific.
type modernListResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *jsonrpcError   `json:"error"`
}

// decodeModernListResult decodes a verified 2xx tools/list or events/list
// answer into out. As for decodeCallResponse a JSON-RPC error member is an
// *RPCError, and a missing (absent or null) or malformed result is an error.
func decodeModernListResult(raw []byte, out any) error {
	var wire modernListResponse
	if err := json.Unmarshal(raw, &wire); err != nil {
		return fmt.Errorf("jack client: decoding json-rpc response: %w", err)
	}
	if wire.Error != nil {
		return &RPCError{Code: wire.Error.Code, Message: wire.Error.Message, Data: wire.Error.Data}
	}
	result := bytes.TrimSpace(wire.Result)
	if len(result) == 0 || bytes.Equal(result, []byte("null")) {
		return fmt.Errorf("jack client: json-rpc response has no result")
	}
	if err := json.Unmarshal(result, out); err != nil {
		return fmt.Errorf("jack client: decoding json-rpc result: %w", err)
	}
	return nil
}

// argumentsOrEmpty returns args, or the empty JSON object when args is nil:
// nil arguments mean {} for both projection and the wire.
func argumentsOrEmpty(args json.RawMessage) json.RawMessage {
	if args == nil {
		return json.RawMessage("{}")
	}
	return args
}

// modernFetchDefinitions performs one signed modern-era tools/list or
// events/list request at version and returns the definitions that pass the
// C5/C11 validation; an excluded definition is dropped, not an error (C5).
//
// The request carries params._meta only (C1) and no Mcp-Name, since neither
// method has an S6 name source (C2). It is signed by signer, or by the
// client's default signer when signer is nil. A non-2xx answer is an
// *HTTPError, a JSON-RPC error member an *RPCError, and a missing or malformed
// result an error.
func (c *Client) modernFetchDefinitions(ctx context.Context, signer Signer, version, listMethod string) ([]modern.Definition, error) {
	rm, err := modern.BuildRequestMirrors(version, listMethod, nil, modernClientInfo())
	if err != nil {
		return nil, err
	}
	body, err := marshalModernWireRequest(c.nextRequestID(), listMethod, map[string]any{"_meta": rm.Meta})
	if err != nil {
		return nil, err
	}
	status, _, raw, err := c.roundTrip(ctx, signer, body, rm.Headers)
	if err != nil {
		return nil, err
	}
	if status < 200 || status > 299 {
		return nil, decodeVerifiedCall(status, raw, nil)
	}
	var entries []modernListEntry
	switch listMethod {
	case modernMethodToolsList:
		var res modernToolsListResult
		if err := decodeModernListResult(raw, &res); err != nil {
			return nil, err
		}
		entries = res.Tools
	case modernMethodEventsList:
		var res modernEventsListResult
		if err := decodeModernListResult(raw, &res); err != nil {
			return nil, err
		}
		entries = res.Events
	default:
		return nil, fmt.Errorf("jack client: %q is not a definition list method", listMethod)
	}
	defs := make([]modern.Definition, 0, len(entries))
	for _, e := range entries {
		defs = append(defs, modern.Definition{Name: e.Name, InputSchema: e.InputSchema})
	}
	kept, _ := modern.FilterDefinitions(defs)
	return kept, nil
}

// modernFindDefinition returns the kept definition whose Name equals name
// exactly. A definition excluded by validation is not found.
func modernFindDefinition(defs []modern.Definition, name string) (modern.Definition, bool) {
	for _, def := range defs {
		if def.Name == name {
			return def, true
		}
	}
	return modern.Definition{}, false
}

// modernNoDefinitionError names the tool or event type whose definition is
// absent from, or was excluded by the C5/C11 validation of, its list result.
func modernNoDefinitionError(kind, name string) error {
	return fmt.Errorf("jack client: %s %q has no valid x-mcp-header definition", kind, name)
}

// modernSendProjectedCall performs one signed modern-era call at version whose
// params are name, arguments and the same C1 _meta object. The headers are the
// C2 mirror headers of the method, Mcp-Name included for its S6 name source,
// followed by the projected Mcp-Param-* headers (C6). It is signed by signer,
// or by the client's default signer when signer is nil.
func (c *Client) modernSendProjectedCall(ctx context.Context, signer Signer, version, method, name string, args json.RawMessage, projected []modern.Header) (int, []byte, error) {
	rm, err := modern.BuildRequestMirrors(version, method, map[string]any{"name": name}, modernClientInfo())
	if err != nil {
		return 0, nil, err
	}
	headers := make([]modern.Header, 0, len(rm.Headers)+len(projected))
	headers = append(headers, rm.Headers...)
	headers = append(headers, projected...)
	params := map[string]any{
		"name":      name,
		"arguments": args,
		"_meta":     rm.Meta,
	}
	body, err := marshalModernWireRequest(c.nextRequestID(), method, params)
	if err != nil {
		return 0, nil, err
	}
	status, _, raw, err := c.roundTrip(ctx, signer, body, headers)
	return status, raw, err
}

// modernCallPlan names the definition list a projected call is validated
// against, the wire method of the call, and the noun used when the definition
// is missing.
type modernCallPlan struct {
	listMethod string
	callMethod string
	kind       string
}

// callProjected is the shared C5/C6 (and C11) flow at one protocol version:
// fetch the definition list, keep the valid definitions, find the named one,
// project the arguments into Mcp-Param-* headers, send the call, and after a
// signed -32020 refusal refetch, re-project and retry once (C10/C12). It
// returns the final verified status and body without decoding. Native jack.*
// tools are not listed by tools/list and carry no annotations, so they skip the
// definition fetch and projection and are sent once with the mirrors only.
func (c *Client) callProjected(ctx context.Context, signer Signer, plan modernCallPlan, version, name string, args json.RawMessage) (int, []byte, error) {
	// nil arguments mean {} for both projection and the wire.
	args = argumentsOrEmpty(args)
	if plan.callMethod == modernMethodToolsCall && strings.HasPrefix(name, jackToolPrefix) {
		body, headers, err := buildModernCallBody(c.nextRequestID(), name, args, version)
		if err != nil {
			return 0, nil, err
		}
		status, _, raw, err := c.roundTrip(ctx, signer, body, headers)
		return status, raw, err
	}
	defs, err := c.modernFetchDefinitions(ctx, signer, version, plan.listMethod)
	if err != nil {
		return 0, nil, err
	}
	def, ok := modernFindDefinition(defs, name)
	if !ok {
		return 0, nil, modernNoDefinitionError(plan.kind, name)
	}
	projected, err := modern.ProjectArguments(def.InputSchema, args)
	if err != nil {
		// Returned unwrapped so errors.Is finds the sentinel; no request is
		// sent.
		return 0, nil, err
	}
	status, raw, err := c.modernSendProjectedCall(ctx, signer, version, plan.callMethod, name, args, projected)
	if err != nil {
		return 0, nil, err
	}
	if status == 400 {
		if code, _, recognised := modern.RecognisedError(raw); recognised && code == modernRefusalCodeHeaderMismatch {
			// C10/C12 (SHOULD): the inputSchema may have changed, so
			// refetch the definitions once, re-project and retry once.
			defs, err = c.modernFetchDefinitions(ctx, signer, version, plan.listMethod)
			if err != nil {
				return 0, nil, err
			}
			def, ok = modernFindDefinition(defs, name)
			if !ok {
				return 0, nil, modernNoDefinitionError(plan.kind, name)
			}
			projected, err = modern.ProjectArguments(def.InputSchema, args)
			if err != nil {
				return 0, nil, err
			}
			status, raw, err = c.modernSendProjectedCall(ctx, signer, version, plan.callMethod, name, args, projected)
			if err != nil {
				return 0, nil, err
			}
		}
	}
	// The last answer is returned as-is: a second -32020, any other status and
	// any other error is not retried again.
	return status, raw, nil
}

// CallModernTool performs one modern-era tools/call with x-mcp-header
// projection (spec 04 C5/C6): it fetches tools/list, drops definitions with an
// annotation violation (the other tools are unaffected; C5), finds the tool,
// projects its annotated arguments into Mcp-Param-* headers after the C2
// mirrors, sends the call, and after a signed -32020 refusal refetches
// tools/list once, re-projects and retries once (C10, SHOULD). Projection runs
// before signing; the headers are not signed.
//
// It shares the exact projected flow of CallTool with EraModern: one
// implementation (callProjected), two entry points. That includes the jack.*
// skip (native tools are not in tools/list, so they are sent with the mirrors
// only) and the single C10 retry.
//
// It always speaks the modern era at modern.ModernMin, whatever Config.Era
// says. arguments is the raw JSON of params.arguments; nil sends and projects
// `{}`. out is passed to json.Unmarshal over the verified structuredContent of
// the final answer, exactly as CallTool does.
//
// Errors: a missing or excluded tool is an error naming it, and the call is
// not sent; a projection mismatch is returned unwrapped, so
// errors.Is(err, modern.ErrHeaderProjectionInvalidValue) holds (the call is not
// sent); a non-2xx answer is a *HTTPError, a JSON-RPC error a *RPCError, a
// result with isError a *ToolError; transport and verification errors pass
// through unchanged and are never retried.
func (c *Client) CallModernTool(ctx context.Context, tool string, arguments json.RawMessage, out any) error {
	status, raw, err := c.callProjected(ctx, nil, modernToolsPlan, modern.ModernMin, tool, argumentsOrEmpty(arguments))
	if err != nil {
		return err
	}
	return decodeVerifiedCall(status, raw, out)
}

// CallModernEvent performs one modern-era Events request (events/poll,
// events/stream, events/subscribe or events/unsubscribe) with the same
// projection over the event type's inputSchema and the events/list resync of
// C11/C12 (SHOULD).
//
// It shares the exact projected flow of CallModernTool and of CallTool with
// EraModern: one implementation (callProjected), two entry points. The jack.*
// skip of that flow is specific to tools/call, so every events method goes
// through events/list, projection and the single C11/C12 retry.
//
// It always speaks the modern era at modern.ModernMin, whatever Config.Era
// says. method is one of the four events methods and event is the event type
// name, sent as params.name. arguments is the raw JSON of params.arguments;
// nil sends and projects `{}`. out is passed to json.Unmarshal over the
// verified structuredContent of the final answer.
//
// Errors: a method outside the four events methods is rejected before any
// request; a missing or excluded event type is an error naming it, and the
// call is not sent; a projection mismatch is returned unwrapped, so
// errors.Is(err, modern.ErrHeaderProjectionInvalidValue) holds (the call is not
// sent); a non-2xx answer is a *HTTPError, a JSON-RPC error a *RPCError, a
// result with isError a *ToolError; transport and verification errors pass
// through unchanged and are never retried.
func (c *Client) CallModernEvent(ctx context.Context, method, event string, arguments json.RawMessage, out any) error {
	switch method {
	case modernMethodEventsPoll, modernMethodEventsStream, modernMethodEventsSubscribe, modernMethodEventsUnsubscribe:
	default:
		return fmt.Errorf("jack client: events method must be events/poll, events/stream, events/subscribe or events/unsubscribe")
	}
	plan := modernEventsPlan
	plan.callMethod = method
	status, raw, err := c.callProjected(ctx, nil, plan, modern.ModernMin, event, argumentsOrEmpty(arguments))
	if err != nil {
		return err
	}
	return decodeVerifiedCall(status, raw, out)
}

// Call sends one signed arbitrary JSON-RPC request using the configured era.
// It returns the exact verified response body as json.RawMessage. Modern
// requests add mandatory _meta and mirror headers without tool schema projection.
// The method must be non-empty and contain no control characters; params must
// be JSON-marshalable. EraAuto applies the existing C9 probe/fallback/retry.
func (c *Client) Call(ctx context.Context, method string, params map[string]any) (json.RawMessage, error) {
	if method == "" || strings.IndexFunc(method, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return nil, fmt.Errorf("jack client: invalid JSON-RPC method")
	}
	if params == nil {
		params = map[string]any{}
	}
	// Marshal now to fail closed on unsupported values, before any probe or
	// request is sent. The verified response itself is never re-marshaled.
	if _, err := json.Marshal(params); err != nil {
		return nil, fmt.Errorf("jack client: marshal params: %w", err)
	}
	switch c.currentEra() {
	case EraLegacy:
		return c.rawLegacyCall(ctx, nil, method, params)
	case EraModern:
		_, raw, err := c.rawModernCall(ctx, nil, modern.ModernMin, method, params)
		if err != nil {
			return nil, err
		}
		return json.RawMessage(raw), nil
	default:
		return c.rawCallAuto(ctx, nil, method, params)
	}
}

func (c *Client) rawModernCall(ctx context.Context, signer Signer, version, method string, params map[string]any) (int, []byte, error) {
	mirrors, err := modern.BuildRequestMirrors(version, method, params, modernClientInfo())
	if err != nil {
		return 0, nil, err
	}
	wireParams := make(map[string]any, len(params)+1)
	for k, v := range params {
		wireParams[k] = v
	}
	wireParams["_meta"] = mirrors.Meta
	body, err := marshalModernWireRequest(c.nextRequestID(), method, wireParams)
	if err != nil {
		return 0, nil, err
	}
	headers := append([]modern.Header(nil), mirrors.Headers...)
	if field, ok := modern.NameSource(method); ok {
		value, valid := params[field].(string)
		if !valid {
			return 0, nil, fmt.Errorf("jack client: %s requires a string params.%s", method, field)
		}
		headers = append(headers, modern.Header{Name: "Mcp-Name", Value: modern.EncodeHeaderValue(value)})
	}
	status, _, raw, err := c.roundTrip(ctx, signer, body, headers)
	return status, raw, err
}

func (c *Client) rawLegacyCall(ctx context.Context, signer Signer, method string, params map[string]any) (json.RawMessage, error) {
	body, err := marshalModernWireRequest(c.nextRequestID(), method, params)
	if err != nil {
		return nil, err
	}
	version, session := c.legacyState()
	status, _, raw, err := c.roundTrip(ctx, signer, body, legacySessionHeaders(version, session))
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound && session != "" {
		v := version
		if v == "" {
			v = legacyProtocolVersion
		}
		if err := c.recoverLegacySession(ctx, signer, session, v); err != nil {
			return nil, fmt.Errorf("jack client: legacy session recovery: %w", err)
		}
	}
	return json.RawMessage(raw), nil
}

func (c *Client) rawCallAuto(ctx context.Context, signer Signer, method string, params map[string]any) (json.RawMessage, error) {
	status, raw, err := c.probeEra(ctx, signer, modern.ModernMin)
	if err != nil {
		return nil, err
	}
	return c.finishAutoRaw(ctx, signer, modern.ModernMin, status, raw, method, params)
}

func (c *Client) finishAutoRaw(ctx context.Context, signer Signer, attempted string, status int, raw []byte, method string, params map[string]any) (json.RawMessage, error) {
	if status >= 200 && status <= 299 {
		c.setEra(EraModern)
		if method == "server/discover" {
			// The discover response is itself the caller's requested raw result
			// and the deterministic C9 probe; do not send it twice.
			return json.RawMessage(raw), nil
		}
		return c.runRawModern(ctx, signer, attempted, method, params)
	}
	decision := modern.DetectEraAttempt(status, true, raw, c.implementedVersions(), attempted)
	switch decision.Action {
	case modern.ActionStayModern:
		c.setEra(EraModern)
		if method == "server/discover" {
			return json.RawMessage(raw), nil
		}
		return c.runRawModern(ctx, signer, attempted, method, params)
	case modern.ActionFallbackInitialize:
		if err := c.legacyHandshake(ctx, signer, legacyProtocolVersion); err != nil {
			return nil, err
		}
		c.setEra(EraLegacy)
		if method == "server/discover" {
			return json.RawMessage(raw), nil
		}
		return c.rawLegacyCall(ctx, signer, method, params)
	case modern.ActionRetryWithSupported:
		if len(decision.Supported) > 0 {
			v := decision.Supported[0]
			if v == modern.ModernMin {
				status, raw, err := c.probeEra(ctx, signer, v)
				if err != nil {
					return nil, err
				}
				retry := modern.DetectEraAttempt(status, true, raw, c.implementedVersions(), v)
				if status >= 200 && status <= 299 || retry.Action == modern.ActionStayModern {
					c.setEra(EraModern)
					return c.runRawModern(ctx, signer, v, method, params)
				}
				if retry.Action == modern.ActionFallbackInitialize {
					if err := c.legacyHandshake(ctx, signer, legacyProtocolVersion); err != nil {
						return nil, err
					}
					c.setEra(EraLegacy)
					return c.rawLegacyCall(ctx, signer, method, params)
				}
				return json.RawMessage(raw), decodeVerifiedCall(status, raw, nil)
			}
			if err := c.legacyHandshake(ctx, signer, v); err != nil {
				return nil, err
			}
			c.setEra(EraLegacy)
			if method == "server/discover" {
				return json.RawMessage(raw), nil
			}
			return c.rawLegacyCall(ctx, signer, method, params)
		}
	}
	return json.RawMessage(raw), decodeVerifiedCall(status, raw, nil)
}

func (c *Client) runRawModern(ctx context.Context, signer Signer, version, method string, params map[string]any) (json.RawMessage, error) {
	_, raw, err := c.rawModernCall(ctx, signer, version, method, params)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(raw), nil
}
