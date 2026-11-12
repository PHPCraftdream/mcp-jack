//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/client"
	"github.com/PHPCraftdream/mcp-jack/server"
	"github.com/PHPCraftdream/mcp-jack/userkey"
)

func TestProcessAdminLifecycle(t *testing.T) {
	var forwarded atomic.Int32
	config, _, state := signedFixtureWithNative(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded.Add(1)
		w.WriteHeader(500)
	}), server.NewNativeTools(server.NativeOptions{}))
	caller := state.View().Keys[0]
	caller.Admin = true
	if err := state.Update(func(e *server.StateEdit) error { e.PutKey(caller); return nil }); err != nil {
		t.Fatal(err)
	}
	invoke := func(success bool, args ...string) ([]byte, string) {
		t.Helper()
		process, in, out, diagnostics := childArgs(t, args...)
		if err := in.Close(); err != nil {
			t.Fatal("child input close failed")
		}
		reply, err := io.ReadAll(io.LimitReader(out, maxBody+1))
		if err != nil || len(reply) > maxBody {
			t.Fatal("child output unreadable or unbounded")
		}
		waitErr := process.Wait()
		if success && waitErr != nil || !success && waitErr == nil {
			t.Fatalf("unexpected CLI process outcome: %s", diagnostics.String())
		}
		return reply, diagnostics.String()
	}
	directory := privateDir(t)
	secretPath, publicPath := filepath.Join(directory, "user.seed"), filepath.Join(directory, "user.public")
	if reply, _ := invoke(true, "keygen", "user", "--secret", secretPath, "--public", publicPath); len(reply) != 0 {
		t.Fatal("keygen exposed key material on stdout")
	}
	publicDocument, err := readPrivate(publicPath, 4096)
	if err != nil {
		t.Fatal(err)
	}
	public, err := userkey.ImportServerPublicEnvelope(publicDocument)
	if err != nil {
		t.Fatal(err)
	}
	created, _ := invoke(true, "user-create", "--config", config, "--public", publicPath, "--name", "binary-user", "--admin", "false")
	var ack client.KidResult
	if json.Unmarshal(created, &ack) != nil || ack.KID != public.KID() {
		t.Fatal("binary created the wrong public identity")
	}
	entryBody, _ := invoke(true, "user-get", "--config", config, "--kid", ack.KID)
	var entry client.Entry
	if json.Unmarshal(entryBody, &entry) != nil || entry.KID != ack.KID || entry.Name != "binary-user" || entry.Admin {
		t.Fatal("binary user get lost identity or admin=false")
	}
	for _, value := range []string{"true", "false"} {
		reply, _ := invoke(true, "user-set-admin", "--config", config, "--kid", ack.KID, "--admin", value)
		var changed struct {
			KID   string `json:"kid"`
			Admin *bool  `json:"admin"`
		}
		if json.Unmarshal(reply, &changed) != nil || changed.KID != ack.KID || changed.Admin == nil || *changed.Admin != (value == "true") {
			t.Fatal("binary privilege change lost explicit boolean")
		}
	}
	listed, _ := invoke(true, "user-list", "--config", config)
	var users []client.Entry
	if json.Unmarshal(listed, &users) != nil || len(users) != 2 {
		t.Fatal("binary user list malformed")
	}
	invitePath := filepath.Join(directory, "invite")
	invited, _ := invoke(true, "invite-create", "--config", config, "--invite-file", invitePath, "--admin", "false")
	var invitation client.InviteCreateResult
	if json.Unmarshal(invited, &invitation) != nil || invitation.InviteID == "" || invitation.Code != "" {
		t.Fatal("binary invite receipt malformed or exposes code")
	}
	code, err := readPrivate(invitePath, 43)
	if err != nil || len(code) != 43 || strings.Contains(string(invited), string(code)) {
		t.Fatal("binary private invite output missing or exposed")
	}
	invites, _ := invoke(true, "invite-list", "--config", config)
	var pending []client.InviteListEntry
	if json.Unmarshal(invites, &pending) != nil || len(pending) != 1 || pending[0].InviteID != invitation.InviteID || strings.Contains(string(invites), string(code)) {
		t.Fatal("binary invite list malformed or exposes code")
	}
	invoke(true, "invite-revoke", "--config", config, "--invite-id", invitation.InviteID)
	invoke(true, "user-revoke", "--config", config, "--kid", ack.KID)
	refused, diagnostics := invoke(false, "user-revoke", "--config", config, "--kid", caller.Kid)
	if len(refused) != 0 || !strings.Contains(diagnostics, "authenticated HTTP 409") || len(state.View().Keys) != 1 || len(state.View().Invites) != 0 || forwarded.Load() != 0 {
		t.Fatal("binary native lifecycle violated last-admin or forwarding boundary")
	}
}
