//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package cli

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/bridge"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/clitest"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/command"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/storage"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/transport"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/wire"
	"github.com/PHPCraftdream/mcp-jack/server"
	"github.com/PHPCraftdream/mcp-jack/userkey"
)

func TestCLIProcessHelper(t *testing.T) {
	if os.Getenv("JACK_CLI_CHILD") != "1" {
		return
	}
	args := os.Args
	for i, arg := range args {
		if arg == "--" {
			os.Exit(RunProcess(context.Background(), args[i+1:]))
		}
	}
	os.Exit(99)
}

func TestProcessLifecycleExactBytes(t *testing.T) {
	calls := make(chan string, 8)
	path, _, _ := clitest.SignedFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		select {
		case calls <- string(b):
		default:
			t.Error("unexpected extra lifecycle request")
			w.WriteHeader(500)
			return
		}
		if r.Header.Get("Accept") != "application/json, text/event-stream" || r.Header.Get("MCP-Protocol-Version") != wire.ProtocolVersion {
			w.WriteHeader(400)
			return
		}
		m, _ := wire.Object(b)
		if wire.Text(m["method"]) == "notifications/initialized" {
			w.WriteHeader(202)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if wire.Text(m["method"]) == "initialize" {
			_, _ = io.WriteString(w, clitest.InitializeReply)
		} else {
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":7,"result":{"tools":[]}}`)
		}
	}))
	cmd, in, out, stderr := clitest.Child(t, path)
	// Split framing without changing a single byte of the signed object.
	clitest.WriteInput(t, in, clitest.InitializeFrame[:17])
	clitest.WriteInput(t, in, clitest.InitializeFrame[17:]+"\n")
	line, err := out.ReadString('\n')
	if err != nil || line != clitest.InitializeReply+"\n" || clitest.Receive(t, calls) != clitest.InitializeFrame {
		t.Fatal("initialize bytes or output framing changed")
	}
	clitest.WriteInput(t, in, clitest.InitializedFrame+"\n")
	if clitest.Receive(t, calls) != clitest.InitializedFrame {
		t.Fatal("hidden handshake or altered notification")
	}
	request := `{"jsonrpc":"2.0","id":7,"method":"tools/list"}`
	clitest.WriteInput(t, in, request+"\n")
	line, err = out.ReadString('\n')
	if err != nil || line != "{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"tools\":[]}}\n" || clitest.Receive(t, calls) != request {
		t.Fatal("notification emitted a response or request correlation failed")
	}
	_ = in.Close()
	if err := cmd.Wait(); err != nil || stderr.Len() != 0 {
		t.Fatal("clean EOF failed")
	}
	if len(calls) != 0 {
		t.Fatal("extra calls")
	}
}

func TestProcessUTF8AndEscapedNewlineExactBytes(t *testing.T) {
	request := strings.Replace(clitest.InitializeFrame, `"test"`, `"客户🙂\nline"`, 1)
	reply := strings.Replace(clitest.InitializeReply, `"fixture"`, `"服务🙂\nline"`, 1)
	calls := make(chan string, 1)
	path, _, _ := clitest.SignedFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(400)
			return
		}
		select {
		case calls <- string(b):
		default:
			t.Error("Unicode request retried")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, reply)
	}))
	cmd, in, out, stderr := clitest.Child(t, path)
	// Deliberately split inside a multibyte UTF-8 encoding.
	split := strings.Index(request, "客") + 1
	clitest.WriteInput(t, in, request[:split])
	clitest.WriteInput(t, in, request[split:]+"\n")
	line, err := out.ReadString('\n')
	if err != nil || line != reply+"\n" || clitest.Receive(t, calls) != request {
		t.Fatal("Unicode/escaped-newline bytes or framing changed")
	}
	if err := in.Close(); err != nil {
		t.Fatal("closing Unicode input failed")
	}
	rest, err := io.ReadAll(out)
	if waitErr := cmd.Wait(); waitErr != nil || err != nil || len(rest) != 0 || stderr.Len() != 0 {
		t.Fatal("Unicode positive control failed")
	}
}

func TestProcessRefusals(t *testing.T) {
	cases := []struct {
		name, content, body string
		status              int
	}{
		{"request-202", "", "", 202},
		{"request-204", "", "", 204},
		{"signed-405", "application/json", `{"error":{"code":"method_not_allowed"}}`, 405},
		{"signed-501", "text/event-stream", "data: ignored\n\n", 200},
		{"multiline", "application/json", strings.Replace(clitest.InitializeReply, ",", ",\n", 1), 200},
		{"wrong-id", "application/json", strings.Replace(clitest.InitializeReply, `"init"`, `"other"`, 1), 200},
		{"wrong-version", "application/json", strings.Replace(clitest.InitializeReply, wire.ProtocolVersion, "2026-07-28", 1), 200},
		{"not-rpc", "application/json", `{"unexpected":true}`, 200},
		{"session-header", "application/json", clitest.InitializeReply, 200},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			path, _, _ := clitest.SignedFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", tc.content)
				if tc.name == "session-header" {
					w.Header().Set("Mcp-Session-Id", "sensitive-session")
				}
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			cmd, in, out, stderr := clitest.Child(t, path)
			clitest.WriteInput(t, in, clitest.InitializeFrame+"\n")
			b, _ := io.ReadAll(out)
			if err := cmd.Wait(); err == nil || len(b) != 0 || stderr.Len() == 0 || calls.Load() != 1 {
				t.Fatal("refusal hidden, output leaked, or request retried")
			}
			want := "jack: unsupported or invalid protocol message\n"
			switch tc.name {
			case "request-204":
				want = "jack: authenticated HTTP 204; no retry performed\n"
			case "signed-405":
				want = "jack: authenticated HTTP 405; no retry performed\n"
			case "signed-501":
				want = "jack: authenticated HTTP 501; no retry performed\n"
			}
			if stderr.String() != want {
				t.Fatal("refusal failed for the wrong reason (including idle timeout)")
			}
		})
	}
}

func TestProcessCancellationAndEOF(t *testing.T) {
	cases := []struct {
		name, input, stderr string
	}{
		{"unsupported-cancellation", `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"init"}}` + "\n", "jack: unsupported or invalid protocol message\n"},
		// EOF cancels the in-flight POST and returns its result, not command.ErrProtocol.
		{"in-flight-eof", "", "jack: remote call failed; no retry performed\n"},
		// Enroll exercises the same connection.post timeout without the bridge's
		// competing idle timer. A silently ignored cancellation must not pass
		// merely because the HTTP call eventually times out.
		{"ordinary-http-timeout", "", "jack: remote call failed; no retry performed\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entered := make(chan struct{})
			left := make(chan error, 1)
			abort := make(chan struct{})
			var calls atomic.Int32
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if calls.Add(1) != 1 {
					t.Error("request retried or unsolicited cancellation forwarded")
					w.WriteHeader(500)
					return
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error("could not read upstream request")
				} else if tc.name == "ordinary-http-timeout" {
					m, err := wire.Object(body)
					if err != nil || wire.Text(m["method"]) != "tools/call" {
						t.Error("timeout control did not reach enrollment POST")
					}
				} else if string(body) != clitest.InitializeFrame {
					t.Error("unexpected upstream request bytes")
				}
				close(entered)
				select {
				case <-r.Context().Done():
					left <- r.Context().Err()
				case <-abort:
					left <- errors.New("fixture aborted without observing cancellation")
				}
			})
			path, cfg, _ := clitest.SignedFixture(t, handler)
			if tc.name == "ordinary-http-timeout" {
				// Stall the real HTTP peer before any response, outside Native
				// dispatch (the signed fixture correctly intercepts jack.enroll).
				peer := httptest.NewServer(handler)
				t.Cleanup(peer.Close)
				cfg.Endpoint = peer.URL + "/mcp"
				path = clitest.SaveJSON(t, clitest.PrivateDir(t), "timeout-client.json", cfg)
			}
			// Release the handler on assertion failure before either server's
			// cleanup. This escape hatch is never a passing observation.
			t.Cleanup(func() { close(abort) })
			var cmd *clitest.ChildProcess
			var in io.WriteCloser
			var out *bufio.Reader
			var stderr *bytes.Buffer
			if tc.name == "ordinary-http-timeout" {
				invite := clitest.Save(t, clitest.PrivateDir(t), "invite", []byte(jack.EncodeBase64URL(make([]byte, 32))))
				cmd, in, out, stderr = clitest.ChildArgs(t, "enroll", "--config", path, "--invite-file", invite, "--name", "alice")
			} else {
				cmd, in, out, stderr = clitest.Child(t, path)
				clitest.WriteInput(t, in, clitest.InitializeFrame+"\n")
			}
			clitest.Receive(t, entered)
			switch tc.name {
			case "in-flight-eof":
				if err := in.Close(); err != nil {
					t.Fatal("could not deliver in-flight EOF")
				}
			case "unsupported-cancellation":
				clitest.WriteInput(t, in, tc.input)
			}
			b, readErr := io.ReadAll(out)
			if cmd.Wait() == nil || readErr != nil || len(b) != 0 || stderr.String() != tc.stderr {
				t.Fatal("wrong failure category, stdout, or exit for cancellation/EOF/HTTP timeout")
			}
			if err := clitest.Receive(t, left); !errors.Is(err, context.Canceled) {
				t.Fatal("real upstream did not observe request cancellation")
			}
			if calls.Load() != 1 {
				t.Fatal("request retried or unsolicited cancellation forwarded")
			}
		})
	}
}

func TestProcessFramingAndIdleDeadline(t *testing.T) {
	for _, input := range []string{"[]\n", "{}", "{\"jsonrpc\":\"2.0\",\"method\":\"initialize\"}\n", string([]byte{0xff, '\n'}), strings.Repeat("x", wire.MaxBody+1) + "\n"} {
		path, _, _ := clitest.SignedFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("invalid frame reached upstream") }))
		cmd, in, out, stderr := clitest.Child(t, path)
		_, _ = io.WriteString(in, input)
		_ = in.Close()
		b, _ := io.ReadAll(out)
		if cmd.Wait() == nil || len(b) != 0 || stderr.String() != "jack: unsupported or invalid protocol message\n" {
			t.Fatal("invalid/truncated frame accepted or failed for the wrong reason")
		}
	}
	path, _, _ := clitest.SignedFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("idle bridge called network") }))
	cmd, _, out, stderr := clitest.Child(t, path)
	b, _ := io.ReadAll(out)
	if cmd.Wait() == nil || len(b) != 0 || stderr.String() != "jack: operation cancelled or deadline exceeded\n" {
		t.Fatal("idle read deadline not enforced")
	}
}

func TestProcessKeygenOverwriteUnchanged(t *testing.T) {
	for _, role := range []string{"server", "user"} {
		t.Run(role, func(t *testing.T) {
			d := clitest.PrivateDir(t)
			secret := filepath.Join(d, "sensitive-secret.seed")
			public := filepath.Join(d, "sensitive-public.json")
			args := []string{"keygen", role, "--secret", secret, "--public", public}
			stdout, stderr, err := clitest.ProcessResult(t, args...)
			if err != nil || len(stdout) != 0 || len(stderr) != 0 {
				t.Fatal("initial process keygen failed")
			}
			seed, err := storage.ReadPrivate(secret, 32)
			if err != nil || len(seed) != 32 {
				t.Fatal("process did not create a raw seed")
			}
			pub, err := storage.ReadPrivate(public, 4096)
			if err != nil {
				t.Fatal("process did not create public identity")
			}
			stdout, stderr, err = clitest.ProcessResult(t, args...)
			if err == nil || len(stdout) != 0 || len(stderr) == 0 {
				t.Fatal("process overwrite accepted or hidden")
			}
			clitest.AssertNoProcessLeak(t, stdout, stderr, seed, []byte(jack.EncodeBase64URL(seed)), []byte(secret), []byte(public))
			afterSeed, _ := storage.ReadPrivate(secret, 32)
			afterPub, _ := storage.ReadPrivate(public, 4096)
			if !bytes.Equal(seed, afterSeed) || !bytes.Equal(pub, afterPub) {
				t.Fatal("process overwrite changed existing files")
			}
			newPublic := filepath.Join(d, "sensitive-new-public.json")
			stdout, stderr, err = clitest.ProcessResult(t, "keygen", role, "--secret", secret, "--public", newPublic)
			if err == nil {
				t.Fatal("process accepted an existing secret with a new public destination")
			}
			clitest.AssertNoProcessLeak(t, stdout, stderr, seed, []byte(secret), []byte(newPublic))
			if _, err := os.Lstat(newPublic); !os.IsNotExist(err) {
				t.Fatal("process left a public reservation after refusal")
			}
			afterSeed, _ = storage.ReadPrivate(secret, 32)
			if !bytes.Equal(seed, afterSeed) {
				t.Fatal("secret changed after partial destination refusal")
			}
		})
	}
}

func TestProcessBootstrapExistingAdminAndCorruptUnchanged(t *testing.T) {
	issued, retained, err := userkey.IssueLocalPair()
	if err != nil {
		t.Fatal(err)
	}
	adminState, err := json.Marshal(struct {
		Version int                    `json:"version"`
		Keys    []server.RegistryEntry `json:"keys"`
		Invites []server.InviteRecord  `json:"invites"`
	}{1, []server.RegistryEntry{{
		Kid: retained.KID(), PublicKey: jack.EncodeBase64URL(retained.PublicKey()), Name: "existing-admin", Admin: true,
	}}, []server.InviteRecord{}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"existing-admin", adminState},
		{"corrupt", []byte(`{"version":1,"sensitive-corrupt-marker":"never reset"`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := clitest.PrivateDir(t)
			state := clitest.Save(t, d, "sensitive-state.json", tc.data)
			invite := clitest.Save(t, d, "sensitive-invite", []byte(jack.EncodeBase64URL(bytes.Repeat([]byte{9}, 32))))
			inviteBefore, _ := storage.ReadPrivate(invite, 43)
			stdout, stderr, err := clitest.ProcessResult(t, "bootstrap", "--state", state, "--invite-file", invite)
			if err == nil || len(stdout) != 0 || len(stderr) == 0 {
				t.Fatal("bootstrap existing-state refusal missing")
			}
			clitest.AssertNoProcessLeak(t, stdout, stderr, tc.data, issued.Secret(), inviteBefore, []byte(state), []byte(invite))
			after, _ := storage.ReadPrivate(state, wire.MaxBody)
			afterInvite, _ := storage.ReadPrivate(invite, 43)
			if !bytes.Equal(after, tc.data) || !bytes.Equal(afterInvite, inviteBefore) {
				t.Fatal("bootstrap process changed existing state or invite")
			}
			unused := filepath.Join(d, "sensitive-unused-invite")
			stdout, stderr, err = clitest.ProcessResult(t, "bootstrap", "--state", state, "--invite-file", unused)
			if err == nil {
				t.Fatal("existing state accepted with absent invite destination")
			}
			clitest.AssertNoProcessLeak(t, stdout, stderr, tc.data, []byte(state), []byte(unused))
			after, _ = storage.ReadPrivate(state, wire.MaxBody)
			if !bytes.Equal(after, tc.data) {
				t.Fatal("bootstrap reset existing state")
			}
			if _, err := os.Lstat(unused); !os.IsNotExist(err) {
				t.Fatal("bootstrap refusal created an invite")
			}
		})
	}
}

func TestProcessCredentialTupleMismatchNoNetworkOrLeak(t *testing.T) {
	d := clitest.PrivateDir(t)
	var calls atomic.Int32
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(500)
	}))
	defer remote.Close()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	seed := bytes.Repeat([]byte{37}, 32)
	expected := userkey.ExpectedIdentity{URL: remote.URL + "/sensitive-endpoint", Aud: "sensitive-audience", ServerPublicKey: pub, ServerKID: jack.KeyID(pub)}
	issued, err := userkey.IssueUserKey(expected, bytes.NewReader(seed))
	if err != nil {
		t.Fatal(err)
	}
	credential := issued.CredentialBytes()
	key := clitest.Save(t, d, "sensitive-credential", credential)
	inviteBytes := []byte(jack.EncodeBase64URL(bytes.Repeat([]byte{71}, 32)))
	invite := clitest.Save(t, d, "sensitive-invite", inviteBytes)
	base := transport.Config{
		Version: 1, Endpoint: expected.URL, Aud: expected.Aud, ServerPublicKey: jack.EncodeBase64URL(pub),
		ServerKID: expected.ServerKID, KeyFile: key, KeyFormat: "credential", CallTimeoutMS: 1000,
	}
	for i, mutate := range []func(*transport.Config){
		func(c *transport.Config) { c.Endpoint += "/different" },
		func(c *transport.Config) { c.Aud += "-different" },
		func(c *transport.Config) { c.ServerPublicKey = jack.EncodeBase64URL(other) },
		func(c *transport.Config) { c.ServerKID = jack.KeyID(other) },
		func(c *transport.Config) {
			c.ServerPublicKey = jack.EncodeBase64URL(other)
			c.ServerKID = jack.KeyID(other)
		},
	} {
		c := base
		mutate(&c)
		config := clitest.SaveJSON(t, d, "sensitive-config-"+strconv.Itoa(i)+".json", c)
		configBefore, _ := storage.ReadPrivate(config, 16384)
		name := "sensitive-user-name"
		stdout, stderr, err := clitest.ProcessResult(t, "enroll", "--config", config, "--invite-file", invite, "--name", name)
		if err == nil || len(stdout) != 0 || len(stderr) == 0 {
			t.Fatal("credential tuple mismatch process accepted or hidden")
		}
		clitest.AssertNoProcessLeak(t, stdout, stderr, credential, seed, []byte(jack.EncodeBase64URL(seed)), inviteBytes,
			[]byte(config), []byte(key), []byte(invite), []byte(name), []byte(c.Endpoint), []byte(c.Aud))
		after, _ := storage.ReadPrivate(config, 16384)
		afterKey, _ := storage.ReadPrivate(key, 4096)
		afterInvite, _ := storage.ReadPrivate(invite, 43)
		if !bytes.Equal(after, configBefore) || !bytes.Equal(afterKey, credential) || !bytes.Equal(afterInvite, inviteBytes) {
			t.Fatal("mismatch process mutated trust or secrets")
		}
	}
	if calls.Load() != 0 {
		t.Fatal("credential mismatch process reached the network")
	}
}

func TestVerifiedStatusErrorMatchAndEnrollmentProcess(t *testing.T) {
	for _, status := range []int{405, 501} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			var matched *transport.VerifiedStatusError
			err := &transport.VerifiedStatusError{Status: status}
			if !errors.Is(err, command.ErrRemote) || !errors.As(err, &matched) || matched.Status != status {
				t.Fatal("verified error lost remote error matching")
			}
			d := clitest.PrivateDir(t)
			pub, priv, _ := ed25519.GenerateKey(rand.Reader)
			var calls atomic.Int32
			remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if _, err := io.Copy(io.Discard, r.Body); err != nil {
					w.WriteHeader(400)
					return
				}
				auth, err := jack.ParseRequestAuth(r.Header.Values("Jack-Auth"))
				if err != nil {
					w.WriteHeader(401)
					return
				}
				body := []byte(`{"error":{"message":"sensitive-remote-body"}}`)
				now := time.Now().Unix()
				sig := ed25519.Sign(priv, []byte(jack.ResponseSigningString(status, auth.Sig, jack.KeyID(pub), now, body)))
				w.Header().Set("Jack-Auth", jack.FormatResponseAuth(jack.ResponseAuth{Kid: jack.KeyID(pub), TS: now, Sig: jack.EncodeBase64URL(sig)}))
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(status)
				_, _ = w.Write(body)
			}))
			defer remote.Close()
			issued, _, _ := userkey.IssueLocalPair()
			key := clitest.Save(t, d, "user.seed", issued.Secret())
			inviteBytes := []byte(jack.EncodeBase64URL(bytes.Repeat([]byte{45}, 32)))
			invite := clitest.Save(t, d, "invite", inviteBytes)
			config := clitest.SaveJSON(t, d, "client.json", transport.Config{
				Version: 1, Endpoint: remote.URL + "/mcp", Aud: "svc", ServerPublicKey: jack.EncodeBase64URL(pub),
				ServerKID: jack.KeyID(pub), KeyFile: key, KeyFormat: "raw-seed", CallTimeoutMS: 1000,
			})
			stdout, stderr, processErr := clitest.ProcessResult(t, "enroll", "--config", config, "--invite-file", invite, "--name", "sensitive-name")
			want := "jack: authenticated HTTP " + strconv.Itoa(status) + "; no retry performed\n"
			if processErr == nil || len(stdout) != 0 || string(stderr) != want || calls.Load() != 1 {
				t.Fatal("enrollment lost authenticated status or retried")
			}
			clitest.AssertNoProcessLeak(t, stdout, stderr, issued.Secret(), inviteBytes, []byte("sensitive-remote-body"), []byte("sensitive-name"), []byte(config))
		})
	}
}

func TestProcessNotification202NonemptyRejected(t *testing.T) {
	for _, nonempty := range []bool{false, true} {
		t.Run(strconv.FormatBool(nonempty), func(t *testing.T) {
			var calls atomic.Int32
			path, _, _ := clitest.SignedFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				b, _ := io.ReadAll(r.Body)
				m, _ := wire.Object(b)
				if wire.Text(m["method"]) == "initialize" {
					w.Header().Set("Content-Type", "application/json")
					_, _ = io.WriteString(w, clitest.InitializeReply)
					return
				}
				w.WriteHeader(202)
				if nonempty {
					_, _ = io.WriteString(w, "sensitive-notification-body")
				}
			}))
			cmd, in, out, stderr := clitest.Child(t, path)
			clitest.WriteInput(t, in, clitest.InitializeFrame+"\n")
			line, err := out.ReadString('\n')
			if err != nil || line != clitest.InitializeReply+"\n" {
				t.Fatal("notification test initialization failed")
			}
			clitest.WriteInput(t, in, clitest.InitializedFrame+"\n")
			// Empty notifications emit no frame; the idle deadline ends the positive control.
			stdout, _ := io.ReadAll(out)
			if cmd.Wait() == nil || len(stdout) != 0 || calls.Load() != 2 {
				t.Fatal("notification emitted a frame or was retried")
			}
			want := "jack: operation cancelled or deadline exceeded\n"
			if nonempty {
				want = "jack: unsupported or invalid protocol message\n"
			}
			if stderr.String() != want {
				t.Fatal("nonempty notification acceptance was not discriminated")
			}
			clitest.AssertNoProcessLeak(t, stdout, stderr.Bytes(), []byte("sensitive-notification-body"))
		})
	}
}

func TestNotification202Not204(t *testing.T) {
	for _, status := range []int{202, 204} {
		path, _, _ := clitest.SignedFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
		c, err := transport.LoadConnection(path)
		if err != nil {
			t.Fatal(err)
		}
		state := 1
		var out bytes.Buffer
		err = bridge.RelayFrame(context.Background(), c, &out, []byte(clitest.InitializedFrame), &state)
		if (err == nil) != (status == 202) || out.Len() != 0 {
			t.Fatal("notification status/framing contract violated")
		}
	}
}
