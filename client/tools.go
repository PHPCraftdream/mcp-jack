package client

import (
	"context"
	"fmt"

	jack "github.com/PHPCraftdream/mcp-jack"
)

// Protocol-native tool names (spec 03).
const (
	ToolEnroll             = "jack.enroll"
	ToolWhoAmI             = "jack.whoami"
	ToolRotateKey          = "jack.key.rotate"
	ToolAdminUserList      = "jack.admin.user.list"
	ToolAdminUserGet       = "jack.admin.user.get"
	ToolAdminUserCreate    = "jack.admin.user.create"
	ToolAdminUserSetScopes = "jack.admin.user.set_scopes"
	ToolAdminUserRevoke    = "jack.admin.user.revoke"
	ToolAdminInviteCreate  = "jack.admin.invite.create"
	ToolAdminInviteList    = "jack.admin.invite.list"
	ToolAdminInviteRevoke  = "jack.admin.invite.revoke"
)

// Entry is one registry key entry (spec 03 sections 3.3).
type Entry struct {
	KID       string   `json:"kid"`
	PublicKey string   `json:"public_key"`
	Name      string   `json:"name"`
	Kind      string   `json:"kind"`
	Scopes    []string `json:"scopes"`
	NotBefore *int64   `json:"not_before"`
	NotAfter  *int64   `json:"not_after"`
}

// WhoAmIResult describes the calling key (spec 03 section 3.3).
type WhoAmIResult struct {
	KID       string   `json:"kid"`
	Name      string   `json:"name"`
	Kind      string   `json:"kind"`
	Scopes    []string `json:"scopes"`
	NotBefore *int64   `json:"not_before"`
	NotAfter  *int64   `json:"not_after"`
}

// EnrollResult describes the key just enrolled via an invite (spec 03 section 3.2).
type EnrollResult struct {
	KID    string   `json:"kid"`
	Name   string   `json:"name"`
	Kind   string   `json:"kind"`
	Scopes []string `json:"scopes"`
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
	InviteID  string   `json:"invite_id"`
	Scopes    []string `json:"scopes"`
	Kind      string   `json:"kind"`
	CreatedBy string   `json:"created_by"`
	CreatedAt int64    `json:"created_at"`
	ExpiresAt int64    `json:"expires_at"`
}

// InviteRevokeResult confirms a revoked invite.
type InviteRevokeResult struct {
	InviteID string `json:"invite_id"`
}

// UserCreateParams are the arguments of jack.admin.user.create.
type UserCreateParams struct {
	Name      string   `json:"name"`
	PublicKey string   `json:"public_key"`
	Scopes    []string `json:"scopes"`
	Kind      string   `json:"kind,omitempty"`
	NotBefore *int64   `json:"not_before,omitempty"`
	NotAfter  *int64   `json:"not_after,omitempty"`
}

// InviteCreateParams are the arguments of jack.admin.invite.create.
type InviteCreateParams struct {
	Scopes        []string `json:"scopes"`
	Kind          string   `json:"kind,omitempty"`
	TTLSeconds    *int64   `json:"ttl_seconds,omitempty"`
	KeyTTLSeconds *int64   `json:"key_ttl_seconds,omitempty"`
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

// AdminUserSetScopes replaces the scopes of one entry.
func (c *Client) AdminUserSetScopes(ctx context.Context, kid string, scopes []string) (Entry, error) {
	args := struct {
		Kid    string   `json:"kid"`
		Scopes []string `json:"scopes"`
	}{Kid: kid, Scopes: scopes}
	var out Entry
	if err := c.call(ctx, nil, ToolAdminUserSetScopes, args, &out); err != nil {
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
