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
	"github.com/PHPCraftdream/mcp-jack/server"
	"github.com/PHPCraftdream/mcp-jack/userkey"
)

type adminTestOutput struct {
	bytes.Buffer
	closed bool
}

func (output *adminTestOutput) Close() error { output.closed = true; return nil }

func TestCLISetAdminExplicitFalseAndLastAdmin(t *testing.T) {
	var forwarded atomic.Int32
	config, _, state := signedFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded.Add(1)
		w.WriteHeader(500)
	}))
	caller := state.View().Keys[0]
	_, other, err := userkey.IssueLocalPair()
	if err != nil {
		t.Fatal(err)
	}
	target := server.RegistryEntry{Kid: other.KID(), PublicKey: jack.EncodeBase64URL(other.PublicKey()), Name: "target", Admin: true}
	if err := state.Update(func(e *server.StateEdit) error {
		e.PutKey(target)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	run := func(kid, value string) (int, string, string) {
		t.Helper()
		var out adminTestOutput
		var diagnostics bytes.Buffer
		status := Run(context.Background(), []string{"user-set-admin", "--config", config, "--kid", kid, "--admin", value}, IO{Out: &out, Err: &diagnostics})
		if out.closed {
			t.Fatal("admin command closed caller output")
		}
		if bytes.Contains(diagnostics.Bytes(), []byte(config)) || bytes.Contains(diagnostics.Bytes(), []byte(kid)) {
			t.Fatal("diagnostic disclosed supplied values")
		}
		return status, out.String(), diagnostics.String()
	}
	if status, out, _ := run(target.Kid, "false"); status == 0 || out != "" {
		t.Fatal("non-admin caller changed privileges or received success output")
	}
	caller.Admin = true
	if err := state.Update(func(e *server.StateEdit) error {
		e.PutKey(caller)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"false", "true", "false"} {
		status, out, diagnostics := run(target.Kid, value)
		if status != 0 {
			t.Fatalf("admin change failed: %s", diagnostics)
		}
		var ack struct {
			KID   string `json:"kid"`
			Admin *bool  `json:"admin"`
		}
		if json.Unmarshal([]byte(out), &ack) != nil || ack.KID != target.Kid || ack.Admin == nil || *ack.Admin != (value == "true") {
			t.Fatal("missing or mismatched authenticated acknowledgement")
		}
		found := false
		for _, entry := range state.View().Keys {
			if entry.Kid == target.Kid {
				found = true
				if entry.Admin != (value == "true") {
					t.Fatal("wire admin value was omitted or changed")
				}
			}
		}
		if !found {
			t.Fatal("target removed")
		}
	}
	before, err := json.Marshal(state.View())
	if err != nil {
		t.Fatal(err)
	}
	if status, out, _ := run(caller.Kid, "false"); status == 0 || out != "" {
		t.Fatal("last-admin demotion accepted")
	}
	after, err := json.Marshal(state.View())
	if err != nil || !bytes.Equal(before, after) || forwarded.Load() != 0 {
		t.Fatal("refused native operation mutated registry or reached application")
	}
}

func TestCLISetAdminRefusesUnsignedSuccessWithoutRetry(t *testing.T) {
	_, cfg, _ := signedFixture(t, http.NotFoundHandler())
	var calls atomic.Int32
	unsigned := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"isError":false,"structuredContent":{"admin":false}}}`))
	}))
	defer unsigned.Close()
	cfg.Endpoint = unsigned.URL + "/mcp"
	config := saveJSON(t, privateDir(t), "client.json", cfg)
	var out adminTestOutput
	var diagnostics bytes.Buffer
	kid := jack.EncodeBase64URL(make([]byte, 32))
	if Run(context.Background(), []string{"user-set-admin", "--config", config, "--kid", kid, "--admin", "false"}, IO{Out: &out, Err: &diagnostics}) == 0 || out.Len() != 0 || calls.Load() != 1 {
		t.Fatal("unsigned success accepted or call retried")
	}
}

func TestCLISetAdminRequiresExactBooleanBeforeConfigIO(t *testing.T) {
	kid := jack.EncodeBase64URL(make([]byte, 32))
	for _, value := range []string{"", "0", "1", "FALSE", "True", " false", "false ", "null"} {
		var out adminTestOutput
		var diagnostics bytes.Buffer
		args := []string{"user-set-admin", "--config", "not-read", "--kid", kid}
		if value != "" {
			args = append(args, "--admin", value)
		}
		if Run(context.Background(), args, IO{Out: &out, Err: &diagnostics}) == 0 || out.Len() != 0 || diagnostics.String() != "jack: "+errConfig.Error()+"\n" {
			t.Fatalf("noncanonical boolean accepted: %q", value)
		}
	}
	if err := userSetAdmin(context.Background(), "not-read", kid, "false", nil); err != errConfig {
		t.Fatal("missing output was not refused before mutation")
	}
}
