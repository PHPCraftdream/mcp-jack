package server

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"sort"

	jack "github.com/PHPCraftdream/mcp-jack"
)

// NativeOptions configures NewNativeTools.
type NativeOptions struct {
	// RandomBytes returns n bytes from a CSPRNG; nil means crypto/rand. Invite
	// codes come from it, so tests may inject a deterministic source but
	// production must not.
	RandomBytes func(n int) ([]byte, error)
}

// Native implements the protocol-native tools of spec 03: enrollment, key
// rotation, whoami and user and invite administration. Every state change is
// one StateStore.Update, so it is atomic (spec 03 section 9).
type Native struct {
	random func(n int) ([]byte, error)
}

var _ NativeTools = (*Native)(nil)

// NewNativeTools returns the native tool implementation.
func NewNativeTools(opts NativeOptions) *Native {
	random := opts.RandomBytes
	if random == nil {
		random = func(n int) ([]byte, error) {
			b := make([]byte, n)
			_, err := rand.Read(b)
			return b, err
		}
	}
	return &Native{random: random}
}

func perr(status int, code, message string) *jack.Error {
	return &jack.Error{HTTPStatus: status, Code: code, Message: message}
}

func invalidParams() *jack.Error {
	return perr(400, jack.CodeInvalidParams, "an argument is missing, mistyped or out of range")
}

func keyRejected() *jack.Error {
	return perr(400, jack.CodeKeyRejected, "the public key is not acceptable")
}

// asJackError turns an error returned from a StateStore.Update callback back
// into a protocol rejection; anything else is an internal failure (for
// example a file store that could not write).
func asJackError(err error) *jack.Error {
	var je *jack.Error
	if errors.As(err, &je) {
		return je
	}
	return perr(500, "internal_error", "internal error")
}

// argMap is params.arguments looked up by exact member name.
type argMap map[string]json.RawMessage

// parseArgs decodes params.arguments: absent means no arguments, anything but
// an object (null included) is invalid.
func parseArgs(raw json.RawMessage) (argMap, *jack.Error) {
	if len(raw) == 0 {
		return argMap{}, nil
	}
	if isJSONNull(raw) {
		return nil, invalidParams()
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return nil, invalidParams()
	}
	return argMap(m), nil
}

func (a argMap) str(key string) (string, bool) { return jsonString(a[key]) }

// intFrom decodes a JSON number that holds an integer within [min, max]. The
// JSON text must be an integer literal with no fraction and no exponent
// (spec 03 section 3): decoding into int64 rejects 1.0 and 1e3, reads -0 as 0
// and avoids float64 rounding above 2^53.
func intFrom(raw json.RawMessage, min, max int64) (int64, bool) {
	if len(raw) == 0 || isJSONNull(raw) {
		return 0, false
	}
	var v int64
	if err := json.Unmarshal(raw, &v); err != nil || v < min || v > max {
		return 0, false
	}
	return v, true
}

// timeFrom decodes an optional validity bound: absent or null is unbounded.
func timeFrom(raw json.RawMessage) (*int64, bool) {
	if len(raw) == 0 || isJSONNull(raw) {
		return nil, true
	}
	v, ok := intFrom(raw, 0, 999999999999)
	if !ok {
		return nil, false
	}
	return &v, true
}

// isJSONNull reports whether raw is the JSON null literal.
func isJSONNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

// jsonString decodes raw only when it is a JSON string; encoding/json would
// also accept null for a string target, which the protocol must not.
func jsonString(raw json.RawMessage) (string, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '"' {
		return "", false
	}
	var s string
	if err := json.Unmarshal(trimmed, &s); err != nil {
		return "", false
	}
	return s, true
}

// adminFrom decodes an optional admin flag (spec 03 section 3): absent is
// false; when present it must be a strict JSON boolean — null, a string or a
// number is invalid.
func adminFrom(raw json.RawMessage) (bool, bool) {
	trimmed := bytes.TrimSpace(raw)
	switch {
	case len(raw) == 0:
		return false, true
	case bytes.Equal(trimmed, []byte("true")):
		return true, true
	case bytes.Equal(trimmed, []byte("false")):
		return false, true
	}
	return false, false
}

// publicKeyFrom decodes a submitted public key and applies the validity rules
// of spec 03 section 2.
func publicKeyFrom(raw json.RawMessage) ([]byte, *jack.Error) {
	s, ok := jsonString(raw)
	if !ok {
		return nil, invalidParams()
	}
	key, err := jack.DecodeBase64URLFixed(s, 32)
	if err != nil || jack.ValidatePublicKey(key) != nil {
		return nil, keyRejected()
	}
	return key, nil
}

type inviteView struct {
	InviteID  string `json:"invite_id"`
	Admin     bool   `json:"admin"`
	CreatedBy string `json:"created_by"`
	CreatedAt int64  `json:"created_at"`
	ExpiresAt int64  `json:"expires_at"`
}

// activeAdmins counts entries with admin that are active at now (spec 03
// section 4 rule 2).
func activeAdmins(keys []RegistryEntry, now int64) int {
	n := 0
	for _, k := range keys {
		if k.Admin && entryActive(k, now) {
			n++
		}
	}
	return n
}

func inviteIDOf(rawCode []byte) string {
	sum := sha256.Sum256(rawCode)
	return jack.EncodeBase64URL(sum[:])
}

// Call dispatches one protocol-native tool.
func (n *Native) Call(c *NativeCall) (NativeResult, *jack.Error) {
	switch c.Tool {
	case ToolEnroll:
		return n.enroll(c)
	case ToolWhoAmI:
		return n.whoami(c)
	case ToolRotateKey:
		return n.rotate(c)
	case ToolAdminUserList, ToolAdminUserGet, ToolAdminUserCreate, ToolAdminUserSetAdmin, ToolAdminUserRevoke,
		ToolAdminInviteCreate, ToolAdminInviteList, ToolAdminInviteRevoke:
		return n.admin(c)
	}
	return NativeResult{}, perr(403, jack.CodeOperationDenied, "operation is not permitted")
}

// enroll registers the key that signed the request, using an invite (spec 03
// section 3.2). The verifier has already checked steps 1-4 of the enrollment
// procedure.
func (n *Native) enroll(c *NativeCall) (NativeResult, *jack.Error) {
	if c.Caller != nil {
		return NativeResult{}, perr(409, jack.CodeKeyExists, "the key is already registered")
	}
	args, jerr := parseArgs(c.Arguments)
	if jerr != nil {
		return NativeResult{}, jerr
	}
	code, okCode := args.str("code")
	name, okName := args.str("name")
	publicKey, okKey := args.str("public_key")
	if !okCode || !okName || !okKey || !jack.ValidName(name) {
		return NativeResult{}, invalidParams()
	}
	c.Target = name

	rawCode, err := jack.DecodeBase64URLFixed(code, 32)
	if err != nil {
		return NativeResult{}, perr(403, jack.CodeInvalidInvite, "the invite is not valid")
	}
	inviteID := inviteIDOf(rawCode)

	var enrolled RegistryEntry
	err = c.State.Update(func(e *StateEdit) error {
		invite, ok := e.Invite(inviteID)
		if !ok || c.Now >= invite.ExpiresAt {
			return perr(403, jack.CodeInvalidInvite, "the invite is not valid")
		}
		if _, taken := e.KeyByName(name); taken {
			return perr(409, jack.CodeNameTaken, "the name is already used")
		}
		if _, exists := e.Key(c.Kid); exists {
			return perr(409, jack.CodeKeyExists, "the key is already registered")
		}
		enrolled = RegistryEntry{
			Kid: c.Kid, PublicKey: publicKey, Name: name, Admin: invite.Admin,
		}
		if invite.KeyTTLSeconds != nil {
			notAfter := c.Now + *invite.KeyTTLSeconds
			enrolled.NotAfter = &notAfter
		}
		e.PutKey(enrolled)
		e.RemoveInvite(inviteID)
		return nil
	})
	if err != nil {
		return NativeResult{}, asJackError(err)
	}
	return NativeResult{Structured: map[string]any{
		"kid": enrolled.Kid, "name": enrolled.Name, "admin": enrolled.Admin,
	}}, nil
}

func (n *Native) whoami(c *NativeCall) (NativeResult, *jack.Error) {
	if c.Caller == nil {
		return NativeResult{}, perr(401, jack.CodeUnknownKey, "unknown key")
	}
	if _, jerr := parseArgs(c.Arguments); jerr != nil {
		return NativeResult{}, jerr
	}
	v := *c.Caller
	return NativeResult{Structured: map[string]any{
		"kid": v.Kid, "name": v.Name, "admin": v.Admin,
		"not_before": v.NotBefore, "not_after": v.NotAfter,
	}}, nil
}

// rotate replaces the caller's key (spec 03 section 3.1). The proof is checked
// before the new key's existence so a caller cannot learn which keys are
// registered without holding the matching private key.
func (n *Native) rotate(c *NativeCall) (NativeResult, *jack.Error) {
	if c.Caller == nil {
		return NativeResult{}, perr(401, jack.CodeUnknownKey, "unknown key")
	}
	args, jerr := parseArgs(c.Arguments)
	if jerr != nil {
		return NativeResult{}, jerr
	}
	publicKey, okKey := args.str("public_key")
	proof, okProof := args.str("proof")
	if !okKey || !okProof {
		return NativeResult{}, invalidParams()
	}
	raw, jerr := publicKeyFrom(args["public_key"])
	if jerr != nil {
		return NativeResult{}, jerr
	}
	newKid := jack.KeyID(raw)
	c.Target = newKid

	sig, err := jack.DecodeBase64URLFixed(proof, 64)
	signing := jack.RotateProofString(c.Aud, c.Caller.Kid, newKid, c.TS)
	if err != nil || !jack.Verify(raw, []byte(signing), sig) {
		return NativeResult{}, perr(400, jack.CodeInvalidProof, "the proof does not verify")
	}

	err = c.State.Update(func(e *StateEdit) error {
		if _, exists := e.Key(newKid); exists {
			return perr(409, jack.CodeKeyExists, "the key is already registered")
		}
		current, ok := e.Key(c.Caller.Kid)
		if !ok {
			return perr(401, jack.CodeUnknownKey, "unknown key")
		}
		e.RemoveKey(current.Kid)
		current.Kid, current.PublicKey = newKid, publicKey
		e.PutKey(current)
		return nil
	})
	if err != nil {
		return NativeResult{}, asJackError(err)
	}
	return NativeResult{Structured: map[string]any{"kid": newKid}}, nil
}

// admin runs the user and invite administration tools in the check order of
// spec 03 section 4: admin flag, arguments, key validity, target, conflicts,
// last administrator, then the atomic change.
func (n *Native) admin(c *NativeCall) (NativeResult, *jack.Error) {
	if c.Caller == nil {
		return NativeResult{}, perr(401, jack.CodeUnknownKey, "unknown key")
	}
	if !c.Caller.Admin {
		return NativeResult{}, perr(403, jack.CodeAdminRequired, "the caller is not an administrator")
	}
	args, jerr := parseArgs(c.Arguments)
	if jerr != nil {
		return NativeResult{}, jerr
	}

	switch c.Tool {
	case ToolAdminUserList:
		keys := c.State.View().Keys
		sort.Slice(keys, func(i, j int) bool { return keys[i].Name < keys[j].Name })
		return NativeResult{Structured: map[string]any{"users": keys}}, nil

	case ToolAdminUserGet:
		kid, ok := args.str("kid")
		if !ok {
			return NativeResult{}, invalidParams()
		}
		c.Target = kid
		entry, found := c.State.Lookup(kid)
		if !found {
			return NativeResult{}, perr(404, jack.CodeUnknownTarget, "no such key")
		}
		return NativeResult{Structured: entry}, nil

	case ToolAdminUserCreate:
		return n.userCreate(c, args)
	case ToolAdminUserSetAdmin:
		return n.userSetAdmin(c, args)
	case ToolAdminUserRevoke:
		return n.userRevoke(c, args)
	case ToolAdminInviteCreate:
		return n.inviteCreate(c, args)
	case ToolAdminInviteList:
		return n.inviteList(c)
	case ToolAdminInviteRevoke:
		return n.inviteRevoke(c, args)
	}
	return NativeResult{}, perr(403, jack.CodeOperationDenied, "operation is not permitted")
}

// currentAdmin re-reads the calling administrator inside a transaction, so a
// concurrent change to its admin flag is honored (spec 03 section 9).
func currentAdmin(e *StateEdit, c *NativeCall) (RegistryEntry, *jack.Error) {
	caller, ok := e.Key(c.Caller.Kid)
	if !ok {
		return RegistryEntry{}, perr(401, jack.CodeUnknownKey, "unknown key")
	}
	if !caller.Admin {
		return RegistryEntry{}, perr(403, jack.CodeAdminRequired, "the caller is not an administrator")
	}
	return caller, nil
}

func (n *Native) userCreate(c *NativeCall, args argMap) (NativeResult, *jack.Error) {
	name, ok := args.str("name")
	if !ok || !jack.ValidName(name) {
		return NativeResult{}, invalidParams()
	}
	admin, okAdmin := adminFrom(args["admin"])
	if !okAdmin {
		return NativeResult{}, invalidParams()
	}
	notBefore, okFrom := timeFrom(args["not_before"])
	notAfter, okTo := timeFrom(args["not_after"])
	if !okFrom || !okTo || (notBefore != nil && notAfter != nil && *notBefore >= *notAfter) {
		return NativeResult{}, invalidParams()
	}
	if len(args["public_key"]) == 0 {
		return NativeResult{}, invalidParams()
	}
	raw, jerr := publicKeyFrom(args["public_key"])
	if jerr != nil {
		return NativeResult{}, jerr
	}
	publicKey, _ := args.str("public_key")
	kid := jack.KeyID(raw)
	c.Target = name

	err := c.State.Update(func(e *StateEdit) error {
		if _, jerr := currentAdmin(e, c); jerr != nil {
			return jerr
		}
		if _, taken := e.KeyByName(name); taken {
			return perr(409, jack.CodeNameTaken, "the name is already used")
		}
		if _, exists := e.Key(kid); exists {
			return perr(409, jack.CodeKeyExists, "the key is already registered")
		}
		e.PutKey(RegistryEntry{Kid: kid, PublicKey: publicKey, Name: name, Admin: admin, NotBefore: notBefore, NotAfter: notAfter})
		return nil
	})
	if err != nil {
		return NativeResult{}, asJackError(err)
	}
	return NativeResult{Structured: map[string]any{"kid": kid}}, nil
}

// userSetAdmin implements jack.admin.user.set_admin (spec 03 section 3.3):
// the admin argument is REQUIRED — absent, null or non-boolean is
// invalid_params — and the last-administrator rule is evaluated against the
// registry as it would be after the change (spec 03 section 4 rule 2).
func (n *Native) userSetAdmin(c *NativeCall, args argMap) (NativeResult, *jack.Error) {
	kid, okKid := args.str("kid")
	admin, okAdmin := adminFrom(args["admin"])
	if !okKid || !okAdmin || len(args["admin"]) == 0 {
		return NativeResult{}, invalidParams()
	}
	c.Target = kid

	var updated RegistryEntry
	err := c.State.Update(func(e *StateEdit) error {
		if _, jerr := currentAdmin(e, c); jerr != nil {
			return jerr
		}
		target, found := e.Key(kid)
		if !found {
			return perr(404, jack.CodeUnknownTarget, "no such key")
		}
		target.Admin = admin
		after := e.Keys()
		for i := range after {
			if after[i].Kid == kid {
				after[i] = target
			}
		}
		if activeAdmins(after, c.Now) < 1 {
			return perr(409, jack.CodeLastAdmin, "the change would leave no active administrator")
		}
		e.PutKey(target)
		updated = target
		return nil
	})
	if err != nil {
		return NativeResult{}, asJackError(err)
	}
	return NativeResult{Structured: updated}, nil
}

func (n *Native) userRevoke(c *NativeCall, args argMap) (NativeResult, *jack.Error) {
	kid, ok := args.str("kid")
	if !ok {
		return NativeResult{}, invalidParams()
	}
	c.Target = kid

	err := c.State.Update(func(e *StateEdit) error {
		if _, jerr := currentAdmin(e, c); jerr != nil {
			return jerr
		}
		if _, found := e.Key(kid); !found {
			return perr(404, jack.CodeUnknownTarget, "no such key")
		}
		var rest []RegistryEntry
		for _, k := range e.Keys() {
			if k.Kid != kid {
				rest = append(rest, k)
			}
		}
		if activeAdmins(rest, c.Now) < 1 {
			return perr(409, jack.CodeLastAdmin, "the change would leave no active administrator")
		}
		e.RemoveKey(kid)
		return nil
	})
	if err != nil {
		return NativeResult{}, asJackError(err)
	}
	return NativeResult{Structured: map[string]any{"kid": kid}}, nil
}

const (
	defaultInviteTTL = 3600
	maxInviteTTL     = 604800
	maxKeyTTL        = 31536000
)

// newInviteCode draws a 32-byte invite code and returns it with its invite id.
func (n *Native) newInviteCode() (code, inviteID string, err error) {
	raw, err := n.random(32)
	if err != nil || len(raw) != 32 {
		return "", "", errors.New("server: no randomness for the invite code")
	}
	return jack.EncodeBase64URL(raw), inviteIDOf(raw), nil
}

func (n *Native) inviteCreate(c *NativeCall, args argMap) (NativeResult, *jack.Error) {
	admin, ok := adminFrom(args["admin"])
	if !ok {
		return NativeResult{}, invalidParams()
	}
	ttl := int64(defaultInviteTTL)
	if raw, present := args["ttl_seconds"]; present {
		if ttl, ok = intFrom(raw, 1, maxInviteTTL); !ok {
			return NativeResult{}, invalidParams()
		}
	}
	var keyTTL *int64
	if raw, present := args["key_ttl_seconds"]; present {
		v, ok := intFrom(raw, 1, maxKeyTTL)
		if !ok {
			return NativeResult{}, invalidParams()
		}
		keyTTL = &v
	}

	code, inviteID, err := n.newInviteCode()
	if err != nil {
		return NativeResult{}, perr(500, "internal_error", "internal error")
	}
	c.Target = inviteID

	expiresAt := c.Now + ttl
	err = c.State.Update(func(e *StateEdit) error {
		caller, jerr := currentAdmin(e, c)
		if jerr != nil {
			return jerr
		}
		e.PutInvite(InviteRecord{
			InviteID: inviteID, Admin: admin, CreatedBy: caller.Kid,
			CreatedAt: c.Now, ExpiresAt: expiresAt, KeyTTLSeconds: keyTTL,
		})
		return nil
	})
	if err != nil {
		return NativeResult{}, asJackError(err)
	}
	return NativeResult{Structured: map[string]any{"invite_id": inviteID, "code": code, "expires_at": expiresAt}}, nil
}

func (n *Native) inviteList(c *NativeCall) (NativeResult, *jack.Error) {
	var live []InviteRecord
	for _, i := range c.State.View().Invites {
		if c.Now < i.ExpiresAt {
			live = append(live, i)
		}
	}
	sort.Slice(live, func(a, b int) bool {
		if live[a].CreatedAt != live[b].CreatedAt {
			return live[a].CreatedAt < live[b].CreatedAt
		}
		return live[a].InviteID < live[b].InviteID
	})
	out := make([]inviteView, len(live))
	for i, v := range live {
		out[i] = inviteView{
			InviteID: v.InviteID, Admin: v.Admin, CreatedBy: v.CreatedBy,
			CreatedAt: v.CreatedAt, ExpiresAt: v.ExpiresAt,
		}
	}
	return NativeResult{Structured: map[string]any{"invites": out}}, nil
}

func (n *Native) inviteRevoke(c *NativeCall, args argMap) (NativeResult, *jack.Error) {
	inviteID, ok := args.str("invite_id")
	if !ok {
		return NativeResult{}, invalidParams()
	}
	c.Target = inviteID

	err := c.State.Update(func(e *StateEdit) error {
		if _, jerr := currentAdmin(e, c); jerr != nil {
			return jerr
		}
		invite, found := e.Invite(inviteID)
		if !found || c.Now >= invite.ExpiresAt {
			return perr(404, jack.CodeUnknownTarget, "no such invite")
		}
		e.RemoveInvite(inviteID)
		return nil
	})
	if err != nil {
		return NativeResult{}, asJackError(err)
	}
	return NativeResult{Structured: map[string]any{"invite_id": inviteID}}, nil
}

// BootstrapAdmin creates the first administrator's invite out of band (spec 03
// section 5): one single-use admin invite, valid for ttlSeconds. It returns
// the invite code, which exists nowhere else.
// It is a local operation, not an MCP tool; call it from the service's own
// start-up or an operator command, never from a network handler.
func BootstrapAdmin(state StateStore, now, ttlSeconds int64, opts NativeOptions) (string, error) {
	if ttlSeconds < 1 || ttlSeconds > maxInviteTTL {
		return "", errors.New("server: bootstrap ttl must be between 1 and 604800 seconds")
	}
	n := NewNativeTools(opts)
	code, inviteID, err := n.newInviteCode()
	if err != nil {
		return "", err
	}
	err = state.Update(func(e *StateEdit) error {
		e.PutInvite(InviteRecord{
			InviteID: inviteID, Admin: true, CreatedBy: "bootstrap",
			CreatedAt: now, ExpiresAt: now + ttlSeconds,
		})
		return nil
	})
	if err != nil {
		return "", err
	}
	return code, nil
}
