//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/client"
	"github.com/PHPCraftdream/mcp-jack/userkey"
)

func TestGatewayNativeAdminOptInHTTP(t *testing.T) {
	testGatewayBootstrapEnrollNoNativeForward(t, func(config *gatewayConfig) { config.NativeAdmin = true })
}

func testGatewayNativeAdminLifecycle(t *testing.T, config string) {
	t.Helper()
	invoke := func(args ...string) []byte {
		t.Helper()
		var out adminTestOutput
		var diagnostics bytes.Buffer
		if Run(context.Background(), args, IO{Out: &out, Err: &diagnostics}) != 0 {
			t.Fatalf("gateway admin CLI failed: %s", diagnostics.String())
		}
		return append([]byte(nil), out.Bytes()...)
	}
	issued, public, err := userkey.IssueLocalPair()
	if err != nil {
		t.Fatal(err)
	}
	document, err := userkey.ExportPublicEnvelope(public)
	if err != nil {
		t.Fatal(err)
	}
	publicPath := save(t, privateDir(t), "member.public", document)
	created := invoke("user-create", "--config", config, "--public", publicPath, "--name", "member", "--admin", "false")
	var ack client.KidResult
	if json.Unmarshal(created, &ack) != nil || ack.KID != public.KID() {
		t.Fatal("gateway created wrong public identity")
	}
	var memberConfig clientConfig
	if decodeConfig(config, &memberConfig) != nil {
		t.Fatal("client fixture configuration invalid")
	}
	memberConfig.KeyFile = save(t, privateDir(t), "member.seed", issued.Secret())
	memberConfig.KeyFormat = "raw-seed"
	memberPath := saveJSON(t, privateDir(t), "member.json", memberConfig)
	var memberOut adminTestOutput
	var memberDiagnostics bytes.Buffer
	if Run(context.Background(), []string{"user-list", "--config", memberPath}, IO{Out: &memberOut, Err: &memberDiagnostics}) == 0 || memberOut.Len() != 0 || memberDiagnostics.String() != "jack: authenticated HTTP 403; no retry performed\n" {
		t.Fatal("gateway native opt-in bypassed non-admin authorization")
	}
	for _, value := range []string{"true", "false"} {
		invoke("user-set-admin", "--config", config, "--kid", ack.KID, "--admin", value)
	}
	var entry client.Entry
	if json.Unmarshal(invoke("user-get", "--config", config, "--kid", ack.KID), &entry) != nil || entry.Admin || entry.KID != ack.KID {
		t.Fatal("gateway lost explicit admin=false")
	}
	invoke("user-list", "--config", config)
	invitePath := filepath.Join(privateDir(t), "issued.invite")
	var invitation client.InviteCreateResult
	if json.Unmarshal(invoke("invite-create", "--config", config, "--invite-file", invitePath, "--admin", "false"), &invitation) != nil || invitation.InviteID == "" || invitation.Code != "" {
		t.Fatal("gateway invite receipt invalid or secret-bearing")
	}
	invoke("invite-list", "--config", config)
	invoke("invite-revoke", "--config", config, "--invite-id", invitation.InviteID)
	invoke("user-revoke", "--config", config, "--kid", ack.KID)
	conn, err := loadConnection(config)
	if err != nil {
		t.Fatal(err)
	}
	var refused adminTestOutput
	var diagnostics bytes.Buffer
	if Run(context.Background(), []string{"user-revoke", "--config", config, "--kid", conn.signer.KID()}, IO{Out: &refused, Err: &diagnostics}) == 0 || refused.Len() != 0 || diagnostics.String() != "jack: authenticated HTTP 409; no retry performed\n" {
		t.Fatal("gateway bypassed last-admin guard")
	}
	for _, tool := range []string{"jack.whoami", "jack.key.rotate", "jack.server.key", "jack.admin.future"} {
		if _, err := conn.nativeResult(context.Background(), tool, map[string]string{}); err == nil {
			t.Fatal("native admin opt-in expanded unrelated tools")
		}
	}
}
