package client

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
)

// adminAPIRecorder records the bodies of native calls seen by the stub server.
type adminAPIRecorder struct {
	mu     sync.Mutex
	bodies [][]byte
}

func (r *adminAPIRecorder) add(body []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.bodies = append(r.bodies, append([]byte(nil), body...))
}

func (r *adminAPIRecorder) at(i int) []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	if i >= len(r.bodies) {
		return nil
	}
	return r.bodies[i]
}

// count returns the number of captured bodies under the recorder mutex.
func (r *adminAPIRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.bodies)
}

// decodeAdminArguments decodes the tools/call params of a captured request.
func decodeAdminArguments(t *testing.T, body []byte) (tool string, args map[string]json.RawMessage) {
	t.Helper()
	var req struct {
		Method string `json:"method"`
		Params struct {
			Name      string                     `json:"name"`
			Arguments map[string]json.RawMessage `json:"arguments"`
		} `json:"params"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("decode request body %q: %v", body, err)
	}
	return req.Params.Name, req.Params.Arguments
}

// adminArgIs asserts one argument member carries exactly the given JSON text.
func adminArgIs(t *testing.T, args map[string]json.RawMessage, key, want string) {
	t.Helper()
	raw, ok := args[key]
	if !ok {
		t.Fatalf("arguments lack %q, want %s", key, want)
	}
	if string(raw) != want {
		t.Fatalf("arguments[%q] = %s, want %s", key, raw, want)
	}
}

// adminArgAbsent asserts an optional argument member was NOT serialized.
func adminArgAbsent(t *testing.T, args map[string]json.RawMessage, key string) {
	t.Helper()
	if raw, ok := args[key]; ok {
		t.Fatalf("arguments carry %q = %s, want the member absent", key, raw)
	}
}

// TestAdminUserSetAdminWireAndDecode drives the migrated typed API: admin is
// REQUIRED on the wire, so an explicit false must serialize (an omitempty or
// drop-when-false implementation fails), the tool name must be
// jack.admin.user.set_admin, and the result admin flag must decode into
// Entry.Admin per call (a decoder that silently ignored the member would
// decode false), together with the other result fields.
func TestAdminUserSetAdminWireAndDecode(t *testing.T) {
	srv := newTestServer(t)
	rec := &adminAPIRecorder{}
	srv.Handle = func(w http.ResponseWriter, auth jack.RequestAuth, body []byte) {
		rec.add(body)
		var result string
		switch rec.count() {
		case 1:
			result = `{"kid":"k1","public_key":"p1","name":"alice","admin":false,"not_before":null,"not_after":null}`
		default:
			result = `{"kid":"k1","public_key":"p1","name":"alice","admin":true,"not_before":null,"not_after":null}`
		}
		srv.writeSignedJSON(w, auth, http.StatusOK, rpcResultBody(json.RawMessage(result)))
	}
	client := newFixtureClient(t, srv, seedSignerByName(t, "root"), callToolNonce, callToolNonce)

	entry, err := client.AdminUserSetAdmin(context.Background(), "k1", false)
	if err != nil {
		t.Fatalf("AdminUserSetAdmin(false): %v", err)
	}
	tool, args := decodeAdminArguments(t, rec.at(0))
	if tool != "jack.admin.user.set_admin" {
		t.Fatalf("tool = %q, want %q", tool, "jack.admin.user.set_admin")
	}
	adminArgIs(t, args, "kid", `"k1"`)
	adminArgIs(t, args, "admin", `false`)
	if entry.Admin {
		t.Fatalf("Entry.Admin = true, want false (the result carried admin false)")
	}
	if entry.KID != "k1" || entry.Name != "alice" {
		t.Fatalf("Entry = %+v, want kid k1 name alice", entry)
	}

	entry, err = client.AdminUserSetAdmin(context.Background(), "k1", true)
	if err != nil {
		t.Fatalf("AdminUserSetAdmin(true): %v", err)
	}
	_, args = decodeAdminArguments(t, rec.at(1))
	adminArgIs(t, args, "admin", `true`)
	if !entry.Admin {
		t.Fatalf("Entry.Admin = false, want true")
	}
	if entry.KID != "k1" || entry.Name != "alice" {
		t.Fatalf("Entry = %+v, want kid k1 name alice", entry)
	}
}

// TestAdminUserCreateAdminNilVsExplicitFalse discriminates the OPTIONAL admin
// argument of jack.admin.user.create: nil omits the member entirely, and an
// explicit &false serializes `"admin":false` (spec 03 section 3: present
// members are read by exact name; only an explicit member can be mistyped).
func TestAdminUserCreateAdminNilVsExplicitFalse(t *testing.T) {
	srv := newTestServer(t)
	rec := &adminAPIRecorder{}
	srv.Handle = func(w http.ResponseWriter, auth jack.RequestAuth, body []byte) {
		rec.add(body)
		kid := "new-kid"
		if rec.count() > 1 {
			kid = "new-kid-2"
		}
		srv.writeSignedJSON(w, auth, http.StatusOK, rpcResultBody(json.RawMessage(`{"kid":"`+kid+`"}`)))
	}
	client := newFixtureClient(t, srv, seedSignerByName(t, "root"), callToolNonce, callToolNonce)

	falseVal := false
	res, err := client.AdminUserCreate(context.Background(), UserCreateParams{Name: "newbie", PublicKey: "pk-new", Admin: &falseVal})
	if err != nil {
		t.Fatalf("AdminUserCreate(admin explicit false): %v", err)
	}
	if res.KID != "new-kid" {
		t.Fatalf("res.KID = %q, want %q", res.KID, "new-kid")
	}
	tool, args := decodeAdminArguments(t, rec.at(0))
	if tool != "jack.admin.user.create" {
		t.Fatalf("tool = %q, want %q", tool, "jack.admin.user.create")
	}
	adminArgIs(t, args, "name", `"newbie"`)
	adminArgIs(t, args, "public_key", `"pk-new"`)
	adminArgIs(t, args, "admin", `false`)

	res, err = client.AdminUserCreate(context.Background(), UserCreateParams{Name: "newbie2", PublicKey: "pk-new2"})
	if err != nil {
		t.Fatalf("AdminUserCreate(admin nil): %v", err)
	}
	if res.KID != "new-kid-2" {
		t.Fatalf("res.KID = %q, want %q", res.KID, "new-kid-2")
	}
	tool, args = decodeAdminArguments(t, rec.at(1))
	if tool != "jack.admin.user.create" {
		t.Fatalf("tool = %q, want %q", tool, "jack.admin.user.create")
	}
	adminArgAbsent(t, args, "admin")
	adminArgIs(t, args, "name", `"newbie2"`)
}

// TestAdminInviteCreateOptionalMembers discriminates the optional members of
// jack.admin.invite.create: an empty params object serializes no optional
// members, set pointers serialize their exact values, and an explicit
// &false admin serializes `"admin":false`. Every result is fully decoded and
// asserted.
func TestAdminInviteCreateOptionalMembers(t *testing.T) {
	srv := newTestServer(t)
	rec := &adminAPIRecorder{}
	srv.Handle = func(w http.ResponseWriter, auth jack.RequestAuth, body []byte) {
		rec.add(body)
		srv.writeSignedJSON(w, auth, http.StatusOK, rpcResultBody(json.RawMessage(
			`{"invite_id":"iv1","code":"c0de","expires_at":1767229200}`)))
	}
	client := newFixtureClient(t, srv, seedSignerByName(t, "root"), callToolNonce, callToolNonce, callToolNonce)

	wantResult := func(stage string, res InviteCreateResult) {
		t.Helper()
		if res.InviteID != "iv1" {
			t.Fatalf("%s: res.InviteID = %q, want %q", stage, res.InviteID, "iv1")
		}
		if res.Code != "c0de" {
			t.Fatalf("%s: res.Code = %q, want %q", stage, res.Code, "c0de")
		}
		if res.ExpiresAt != 1767229200 {
			t.Fatalf("%s: res.ExpiresAt = %d, want %d", stage, res.ExpiresAt, 1767229200)
		}
	}

	res, err := client.AdminInviteCreate(context.Background(), InviteCreateParams{})
	if err != nil {
		t.Fatalf("AdminInviteCreate(empty): %v", err)
	}
	wantResult("empty", res)
	tool, args := decodeAdminArguments(t, rec.at(0))
	if tool != "jack.admin.invite.create" {
		t.Fatalf("tool = %q, want %q", tool, "jack.admin.invite.create")
	}
	adminArgAbsent(t, args, "admin")
	adminArgAbsent(t, args, "ttl_seconds")
	adminArgAbsent(t, args, "key_ttl_seconds")

	adminTrue := true
	ttl := int64(3600)
	keyTTL := int64(60)
	res, err = client.AdminInviteCreate(context.Background(), InviteCreateParams{Admin: &adminTrue, TTLSeconds: &ttl, KeyTTLSeconds: &keyTTL})
	if err != nil {
		t.Fatalf("AdminInviteCreate(full): %v", err)
	}
	wantResult("full", res)
	_, args = decodeAdminArguments(t, rec.at(1))
	adminArgIs(t, args, "admin", `true`)
	adminArgIs(t, args, "ttl_seconds", `3600`)
	adminArgIs(t, args, "key_ttl_seconds", `60`)

	falseVal := false
	res, err = client.AdminInviteCreate(context.Background(), InviteCreateParams{Admin: &falseVal})
	if err != nil {
		t.Fatalf("AdminInviteCreate(admin explicit false): %v", err)
	}
	wantResult("explicit false", res)
	_, args = decodeAdminArguments(t, rec.at(2))
	adminArgIs(t, args, "admin", `false`)
	adminArgAbsent(t, args, "ttl_seconds")
	adminArgAbsent(t, args, "key_ttl_seconds")
}
