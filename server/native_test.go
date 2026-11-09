package server

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
)

func TestBootstrapAdminThenEnroll(t *testing.T) {
	st := NewMemoryState()
	const now = testNow

	if _, err := BootstrapAdmin(st, now, 0, NativeOptions{}); err == nil {
		t.Fatal("BootstrapAdmin accepted a zero ttl")
	}
	if _, err := BootstrapAdmin(st, now, maxInviteTTL+1, NativeOptions{}); err == nil {
		t.Fatal("BootstrapAdmin accepted a ttl above the maximum")
	}

	code, err := BootstrapAdmin(st, now, 600, NativeOptions{})
	if err != nil {
		t.Fatalf("BootstrapAdmin: %v", err)
	}
	if len(st.View().Invites) != 1 {
		t.Fatalf("invites = %d, want 1", len(st.View().Invites))
	}

	n := NewNativeTools(NativeOptions{})
	enrollAs := func(keyName, name string) (NativeResult, *jack.Error) {
		pub := testPrivateKey(t, keyName).Public().(ed25519.PublicKey)
		args := json.RawMessage(fmt.Sprintf(`{"code":%q,"name":%q,"public_key":%q}`, code, name, jack.EncodeBase64URL(pub)))
		return n.Call(&NativeCall{Tool: ToolEnroll, Arguments: args, Kid: jack.KeyID(pub), TS: now, Now: now, Aud: "aud", State: st})
	}

	if _, jerr := enrollAs("newbie", "first"); jerr != nil {
		t.Fatalf("enroll with the bootstrap invite: %v", jerr)
	}
	kid := jack.KeyID(testPrivateKey(t, "newbie").Public().(ed25519.PublicKey))
	entry, ok := st.Lookup(kid)
	if !ok || !entry.Admin {
		t.Fatalf("enrolled entry = %+v (found %v), want an admin entry", entry, ok)
	}
	if len(st.View().Invites) != 0 {
		t.Fatal("the bootstrap invite must be consumed")
	}

	if _, jerr := enrollAs("newbie2", "second"); jerr == nil || jerr.Code != jack.CodeInvalidInvite {
		t.Fatalf("reusing the invite: %v, want invalid_invite", jerr)
	}
}

func TestInviteCodeIsNeverStored(t *testing.T) {
	st := NewMemoryState()
	admin := stateTestKey("admin-1", "admin1")
	admin.Admin = true
	if err := st.Update(func(e *StateEdit) error { e.PutKey(admin); return nil }); err != nil {
		t.Fatalf("seed: %v", err)
	}

	n := NewNativeTools(NativeOptions{})
	res, jerr := n.Call(&NativeCall{
		Tool: ToolAdminInviteCreate, Arguments: json.RawMessage("{}"),
		Caller: &admin, Kid: admin.Kid, Now: testNow, State: st,
	})
	if jerr != nil {
		t.Fatalf("invite.create: %v", jerr)
	}
	structured, ok := res.Structured.(map[string]any)
	if !ok {
		t.Fatalf("structured result is %T", res.Structured)
	}
	code, _ := structured["code"].(string)
	if len(code) != 43 {
		t.Fatalf("code = %q, want 43 characters", code)
	}

	stored, err := json.Marshal(st.View())
	if err != nil {
		t.Fatalf("marshal state: %v", err)
	}
	if strings.Contains(string(stored), code) {
		t.Fatal("the invite code appears in the stored state")
	}
}

// TestLastAdministratorSurvivesConcurrentRevokes has two administrators try to
// revoke each other at the same time: whichever order the transactions take,
// one administrator must remain (spec 03 sections 4 and 9).
func TestLastAdministratorSurvivesConcurrentRevokes(t *testing.T) {
	n := NewNativeTools(NativeOptions{})
	for round := 0; round < 50; round++ {
		st := NewMemoryState()
		a := stateTestKey("admin-a", "admina")
		b := stateTestKey("admin-b", "adminb")
		a.Admin = true
		b.Admin = true
		if err := st.Update(func(e *StateEdit) error { e.PutKey(a); e.PutKey(b); return nil }); err != nil {
			t.Fatalf("seed: %v", err)
		}

		// Each goroutine writes only its own slot before wg.Done; read after Wait.
		errs := make([]*jack.Error, 2)
		revoke := func(i int, caller RegistryEntry, target RegistryEntry, wg *sync.WaitGroup) {
			defer wg.Done()
			args := json.RawMessage(fmt.Sprintf(`{"kid":%q}`, target.Kid))
			_, errs[i] = n.Call(&NativeCall{Tool: ToolAdminUserRevoke, Arguments: args, Caller: &caller, Kid: caller.Kid, Now: testNow, State: st})
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go revoke(0, a, b, &wg)
		go revoke(1, b, a, &wg)
		wg.Wait()

		succeeded := 0
		for _, jerr := range errs {
			if jerr == nil {
				succeeded++
			}
		}
		if succeeded != 1 {
			t.Fatalf("round %d: %d concurrent mutual revokes succeeded, want exactly 1", round, succeeded)
		}
		for _, jerr := range errs {
			if jerr == nil {
				continue
			}
			if jerr.Code != jack.CodeUnknownKey {
				t.Fatalf("round %d: loser error code = %v, want unknown_key (the caller was already revoked)", round, jerr.Code)
			}
		}
		if got := activeAdmins(st.View().Keys, testNow); got != 1 {
			t.Fatalf("round %d: %d administrators left, want exactly 1", round, got)
		}
	}
}

// TestConcurrentSelfRevokesKeepOneAdmin has two administrators SELF-revoke
// concurrently. Each invocation individually satisfies the last-administrator
// rule (the other admin is still active), but together they would leave none,
// so serialized evaluation must keep exactly one administrator (spec 03
// sections 4 and 9). Removing the last-admin check lets both succeed and
// leaves no administrator, so this test discriminates the rule itself rather
// than mere caller-removal ordering.
func TestConcurrentSelfRevokesKeepOneAdmin(t *testing.T) {
	n := NewNativeTools(NativeOptions{})
	for round := 0; round < 50; round++ {
		st := NewMemoryState()
		a := stateTestKey("admin-a", "admina")
		b := stateTestKey("admin-b", "adminb")
		a.Admin = true
		b.Admin = true
		if err := st.Update(func(e *StateEdit) error { e.PutKey(a); e.PutKey(b); return nil }); err != nil {
			t.Fatalf("seed: %v", err)
		}

		// Each goroutine writes only its own slot before wg.Done; read after Wait.
		errs := make([]*jack.Error, 2)
		selfRevoke := func(i int, self RegistryEntry, wg *sync.WaitGroup) {
			defer wg.Done()
			args := json.RawMessage(fmt.Sprintf(`{"kid":%q}`, self.Kid))
			_, errs[i] = n.Call(&NativeCall{Tool: ToolAdminUserRevoke, Arguments: args, Caller: &self, Kid: self.Kid, Now: testNow, State: st})
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go selfRevoke(0, a, &wg)
		go selfRevoke(1, b, &wg)
		wg.Wait()

		succeeded := 0
		for _, jerr := range errs {
			if jerr == nil {
				succeeded++
			}
		}
		if succeeded != 1 {
			t.Fatalf("round %d: %d concurrent self-revokes succeeded, want exactly 1 (the last-admin rule must stop the second)", round, succeeded)
		}
		for _, jerr := range errs {
			if jerr == nil {
				continue
			}
			if jerr.Code != jack.CodeLastAdmin {
				t.Fatalf("round %d: loser error code = %v, want last_admin", round, jerr.Code)
			}
		}
		if got := activeAdmins(st.View().Keys, testNow); got != 1 {
			t.Fatalf("round %d: %d administrators left, want exactly 1", round, got)
		}
	}
}

func TestAdminToolsRequireAdminBeforeArguments(t *testing.T) {
	st := NewMemoryState()
	reader := stateTestKey("reader", "reader")
	if err := st.Update(func(e *StateEdit) error { e.PutKey(reader); return nil }); err != nil {
		t.Fatalf("seed: %v", err)
	}
	n := NewNativeTools(NativeOptions{})
	// Malformed arguments must not be reported to a caller that may not use the tool.
	_, jerr := n.Call(&NativeCall{
		Tool: ToolAdminUserList, Arguments: json.RawMessage(`7`),
		Caller: &reader, Kid: reader.Kid, Now: testNow, State: st,
	})
	if jerr == nil || jerr.Code != jack.CodeAdminRequired {
		t.Fatalf("error = %v, want admin_required", jerr)
	}
}
