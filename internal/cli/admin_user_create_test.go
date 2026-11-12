//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/client"
	"github.com/PHPCraftdream/mcp-jack/server"
	"github.com/PHPCraftdream/mcp-jack/userkey"
)

func TestCLIUserCreatePublicEnvelopeAndValidity(t *testing.T) {
	var forwarded atomic.Int32
	config, _, state := signedFixtureWithNative(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded.Add(1)
		w.WriteHeader(500)
	}), server.NewNativeTools(server.NativeOptions{}))
	caller := state.View().Keys[0]
	for index, admin := range []string{"false", "true"} {
		_, public, err := userkey.IssueLocalPair()
		if err != nil {
			t.Fatal(err)
		}
		document, err := userkey.ExportPublicEnvelope(public)
		if err != nil {
			t.Fatal(err)
		}
		path := save(t, privateDir(t), "user.public", document)
		name := "created" + admin
		args := []string{"user-create", "--config", config, "--public", path, "--name", name, "--admin", admin}
		if index == 1 {
			args = append(args, "--not-before", "0", "--not-after", "999999999999")
		}
		if index == 0 {
			var denied adminTestOutput
			var diagnostics bytes.Buffer
			if Run(context.Background(), args, IO{Out: &denied, Err: &diagnostics}) == 0 || denied.Len() != 0 || len(state.View().Keys) != 1 || diagnostics.String() != "jack: authenticated HTTP 403; no retry performed\n" {
				t.Fatal("non-admin created a user")
			}
			caller.Admin = true
			if err := state.Update(func(e *server.StateEdit) error { e.PutKey(caller); return nil }); err != nil {
				t.Fatal(err)
			}
		}
		var out adminTestOutput
		var diagnostics bytes.Buffer
		if Run(context.Background(), args, IO{Out: &out, Err: &diagnostics}) != 0 {
			t.Fatalf("user creation failed: %s", diagnostics.String())
		}
		var ack client.KidResult
		if json.Unmarshal(out.Bytes(), &ack) != nil || ack.KID != public.KID() || out.closed {
			t.Fatal("wrong user acknowledgement or caller output closed")
		}
		stored, found := state.Lookup(public.KID())
		if !found || stored.PublicKey != jack.EncodeBase64URL(public.PublicKey()) || stored.Name != name || stored.Admin != (admin == "true") {
			t.Fatal("public identity/name/admin changed")
		}
		if index == 0 && (stored.NotBefore != nil || stored.NotAfter != nil) || index == 1 && (stored.NotBefore == nil || *stored.NotBefore != 0 || stored.NotAfter == nil || *stored.NotAfter != 999999999999) {
			t.Fatal("unset and explicit validity bounds confused")
		}
		before, err := json.Marshal(state.View())
		if err != nil {
			t.Fatal(err)
		}
		var duplicate adminTestOutput
		if Run(context.Background(), args, IO{Out: &duplicate}) == 0 || duplicate.Len() != 0 {
			t.Fatal("duplicate user overwritten")
		}
		after, err := json.Marshal(state.View())
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("duplicate creation mutated registry")
		}
	}
	if forwarded.Load() != 0 {
		t.Fatal("native user creation forwarded to application")
	}
}

func TestCLIUserCreateRejectsPrivateEnvelopeBeforeNetwork(t *testing.T) {
	_, cfg, _ := signedFixture(t, http.NotFoundHandler())
	var calls atomic.Int32
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(500)
	}))
	defer remote.Close()
	cfg.Endpoint = remote.URL + "/mcp"
	config := saveJSON(t, privateDir(t), "client.json", cfg)
	issued, public, err := userkey.IssueLocalPair()
	if err != nil {
		t.Fatal(err)
	}
	document, err := userkey.ExportPublicEnvelope(public)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(document, &fields); err != nil {
		t.Fatal(err)
	}
	fields["type"] = "user-key/private"
	fields["d"] = jack.EncodeBase64URL(issued.Secret())
	privateDocument, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := userkey.ImportClientPrivateEnvelope(privateDocument); err != nil {
		t.Fatal("private-role positive control is invalid")
	}
	path := save(t, privateDir(t), "private.envelope", privateDocument)
	var out adminTestOutput
	var diagnostics bytes.Buffer
	if Run(context.Background(), []string{"user-create", "--config", config, "--public", path, "--name", "created", "--admin", "false"}, IO{Out: &out, Err: &diagnostics}) == 0 || calls.Load() != 0 || out.Len() != 0 {
		t.Fatal("private material accepted or uploaded")
	}
	for _, secret := range [][]byte{privateDocument, []byte(fields["d"].(string)), []byte(path)} {
		if bytes.Contains(diagnostics.Bytes(), secret) {
			t.Fatal("private material or supplied path disclosed")
		}
	}
}

func TestCLIUserCreateRejectsInvalidPolicyBeforeNetwork(t *testing.T) {
	_, cfg, _ := signedFixture(t, http.NotFoundHandler())
	var calls atomic.Int32
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(500)
	}))
	defer remote.Close()
	cfg.Endpoint = remote.URL + "/mcp"
	config := saveJSON(t, privateDir(t), "client.json", cfg)
	_, public, err := userkey.IssueLocalPair()
	if err != nil {
		t.Fatal(err)
	}
	document, err := userkey.ExportPublicEnvelope(public)
	if err != nil {
		t.Fatal(err)
	}
	path := save(t, privateDir(t), "user.public", document)
	base := []string{"user-create", "--config", config, "--public", path, "--name", "created"}
	for _, extra := range [][]string{
		nil,
		{"--admin", "1"},
		{"--admin", "false", "--not-before", "-1"},
		{"--admin", "false", "--not-after", "1000000000000"},
		{"--admin", "false", "--not-before", "10", "--not-after", "10"},
		{"--admin", "false", "--not-before", "11", "--not-after", "10"},
	} {
		args := append(append([]string(nil), base...), extra...)
		var out adminTestOutput
		if Run(context.Background(), args, IO{Out: &out}) == 0 || out.Len() != 0 || calls.Load() != 0 {
			t.Fatal("invalid creation policy accepted or reached network")
		}
	}
	var out adminTestOutput
	valid := append(append([]string(nil), base...), "--admin", "false")
	if Run(context.Background(), valid, IO{Out: &out}) == 0 || out.Len() != 0 || calls.Load() != 1 {
		t.Fatal("valid-policy network control did not reach unsigned responder once")
	}
}
