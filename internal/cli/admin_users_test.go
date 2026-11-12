//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/client"
	"github.com/PHPCraftdream/mcp-jack/server"
	"github.com/PHPCraftdream/mcp-jack/userkey"
)

func TestCLIUserReadAndRevokeUseNativeAuthorization(t *testing.T) {
	var forwarded atomic.Int32
	config, _, state := signedFixtureWithNative(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded.Add(1)
		w.WriteHeader(500)
	}), server.NewNativeTools(server.NativeOptions{}))
	caller := state.View().Keys[0]
	_, public, err := userkey.IssueLocalPair()
	if err != nil {
		t.Fatal(err)
	}
	target := server.RegistryEntry{Kid: public.KID(), PublicKey: jack.EncodeBase64URL(public.PublicKey()), Name: "zulu"}
	run := func(command, kid string) (int, []byte, string) {
		t.Helper()
		args := []string{command, "--config", config}
		if kid != "" {
			args = append(args, "--kid", kid)
		}
		var out adminTestOutput
		var diagnostics bytes.Buffer
		status := Run(context.Background(), args, IO{Out: &out, Err: &diagnostics})
		if out.closed || bytes.Contains(diagnostics.Bytes(), []byte(config)) {
			t.Fatal("caller output closed or private config path disclosed")
		}
		return status, append([]byte(nil), out.Bytes()...), diagnostics.String()
	}
	if status, out, message := run("user-list", ""); status == 0 || len(out) != 0 || message != "jack: authenticated HTTP 403; no retry performed\n" {
		t.Fatal("non-admin list was not refused by native authorization")
	}
	caller.Admin = true
	if err := state.Update(func(e *server.StateEdit) error {
		e.PutKey(caller)
		e.PutKey(target)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	status, out, message := run("user-list", "")
	var entries []client.Entry
	if status != 0 || json.Unmarshal(out, &entries) != nil || len(entries) != 2 || entries[0].KID != caller.Kid || entries[1].KID != target.Kid {
		t.Fatalf("native ordered list not returned: %s", message)
	}
	status, out, message = run("user-get", target.Kid)
	var entry client.Entry
	if status != 0 || json.Unmarshal(out, &entry) != nil || entry.KID != target.Kid || entry.PublicKey != target.PublicKey || entry.Name != target.Name || entry.Admin {
		t.Fatalf("native entry not returned: %s", message)
	}
	status, out, message = run("user-revoke", target.Kid)
	var ack client.KidResult
	if status != 0 || json.Unmarshal(out, &ack) != nil || ack.KID != target.Kid {
		t.Fatalf("revocation not acknowledged: %s", message)
	}
	if _, found := state.Lookup(target.Kid); found {
		t.Fatal("acknowledged key remains registered")
	}
	if status, out, message := run("user-get", target.Kid); status == 0 || len(out) != 0 || message != "jack: authenticated HTTP 404; no retry performed\n" {
		t.Fatal("revoked target remained readable or produced unsigned success output")
	}
	before, err := json.Marshal(state.View())
	if err != nil {
		t.Fatal(err)
	}
	if status, out, message := run("user-revoke", caller.Kid); status == 0 || len(out) != 0 || message != "jack: authenticated HTTP 409; no retry performed\n" {
		t.Fatal("last-admin revocation was not refused")
	}
	after, err := json.Marshal(state.View())
	if err != nil || !bytes.Equal(before, after) || forwarded.Load() != 0 {
		t.Fatal("native operations forwarded or last-admin refusal mutated state")
	}
}

func TestCLIUserCommandsValidateBeforeConfigIO(t *testing.T) {
	for _, command := range []string{"user-list", "user-get", "user-revoke"} {
		if err := userCommand(context.Background(), command, "not-read", "bad-kid", nil); err != errConfig {
			t.Fatal("missing output accepted before operation")
		}
		if command == "user-list" {
			continue
		}
		var out adminTestOutput
		if err := userCommand(context.Background(), command, "not-read", "bad-kid", &out); err != errConfig || out.Len() != 0 {
			t.Fatal("invalid target accepted")
		}
	}
	for _, args := range [][]string{
		{"user-list", "--config", "not-read", "--kid", "unexpected"},
		{"user-get", "--config", "not-read"},
		{"user-revoke", "--config", "not-read"},
	} {
		var out adminTestOutput
		if Run(context.Background(), args, IO{Out: &out}) == 0 || out.Len() != 0 {
			t.Fatal("invalid command shape accepted")
		}
	}
}
