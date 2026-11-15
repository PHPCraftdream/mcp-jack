package cli

import (
	"encoding/json"
	"errors"
	"strconv"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/server"
)

func TestBoundedGatewayStatePreservesAdmissionGate(t *testing.T) {
	state := server.NewMemoryState()
	expires := int64(130)
	if err := state.Update(func(edit *server.StateEdit) error {
		edit.PutKey(server.RegistryEntry{Kid: "test-kid", Name: "caller", NotAfter: &expires})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	bounded := boundedState{state}
	rejected := errors.New("public admission refusal")
	calls := 0
	err := bounded.WithAdmission("test-kid", func(entry server.RegistryEntry, known bool) error {
		calls++
		if !known || entry.Kid != "test-kid" || entry.Name != "caller" || entry.NotAfter == nil || *entry.NotAfter != 130 {
			t.Fatal("gateway lost coordinated registry snapshot")
		}
		*entry.NotAfter = 1
		return rejected
	})
	if !errors.Is(err, rejected) || calls != 1 {
		t.Fatalf("admission result was replaced: %v calls=%d", err, calls)
	}
	entry, known := state.Lookup("test-kid")
	if !known || entry.NotAfter == nil || *entry.NotAfter != 130 {
		t.Fatal("admission snapshot aliased registry")
	}
}

func TestBoundedGatewayStateKeepsAtomicInviteLimit(t *testing.T) {
	state := server.NewMemoryState()
	bounded := boundedState{state}
	if err := bounded.Update(func(edit *server.StateEdit) error {
		for index := 0; index < 1024; index++ {
			edit.PutInvite(server.InviteRecord{InviteID: strconv.Itoa(index)})
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := bounded.Update(func(edit *server.StateEdit) error {
		edit.PutKey(server.RegistryEntry{Kid: "must-not-commit"})
		edit.PutInvite(server.InviteRecord{InviteID: "overflow"})
		return nil
	}); !errors.Is(err, errConfig) {
		t.Fatalf("invite capacity not enforced: %v", err)
	}
	if len(state.View().Invites) != 1024 || len(state.View().Keys) != 0 {
		t.Fatal("overflow partially committed registry edits")
	}
}

func TestBoundedGatewayStateKeepsAtomicKeyLimit(t *testing.T) {
	state := server.NewMemoryState()
	bounded := boundedState{state}
	if err := bounded.Update(func(edit *server.StateEdit) error {
		for index := 0; index < 1024; index++ {
			edit.PutKey(server.RegistryEntry{Kid: strconv.Itoa(index)})
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := bounded.Update(func(edit *server.StateEdit) error {
		edit.PutKey(server.RegistryEntry{Kid: "overflow"})
		return nil
	}); !errors.Is(err, errConfig) {
		t.Fatalf("key capacity not enforced: %v", err)
	}
	if len(state.View().Keys) != 1024 {
		t.Fatal("failed bounded update partially committed")
	}
	if err := bounded.WithAdmission("overflow", func(_ server.RegistryEntry, known bool) error {
		if known {
			t.Fatal("rejected key became visible to admission")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestBoundedGatewayStateCountsInvitesAfterPurge(t *testing.T) {
	state := server.NewMemoryState()
	if err := state.Update(func(edit *server.StateEdit) error {
		edit.PutKey(server.RegistryEntry{Kid: "admin-kid", Name: "admin", Admin: true})
		for index := 0; index < 1024; index++ {
			edit.PutInvite(server.InviteRecord{InviteID: strconv.Itoa(index), CreatedBy: "old", ExpiresAt: 1})
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	bounded := boundedState{state}
	n := server.NewNativeTools(server.NativeOptions{})
	caller := server.RegistryEntry{Kid: "admin-kid", Name: "admin", Admin: true}
	if _, jerr := n.Call(&server.NativeCall{
		Tool: server.ToolAdminInviteCreate, Arguments: json.RawMessage("{}"),
		Caller: &caller, Kid: caller.Kid, Now: 1767225600, State: bounded,
	}); jerr != nil {
		t.Fatalf("invite.create at the cap with only expired invites: %v", jerr)
	}
	if got := len(state.View().Invites); got != 1 {
		t.Fatalf("stored invites = %d, want 1: the expired invites must be purged before the cap counts", got)
	}
}
