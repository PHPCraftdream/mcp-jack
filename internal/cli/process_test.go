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
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/server"
	"github.com/PHPCraftdream/mcp-jack/userkey"
)

const initializeFrame = ` {"jsonrpc":"2.0","id":"init","method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}} `
const initializeReply = `{"jsonrpc":"2.0","id":"init","result":{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"fixture","version":"1"}}}`
const initializedFrame = `{"jsonrpc":"2.0","method":"notifications/initialized"}`

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

type childProcess struct {
	*exec.Cmd
	t    *testing.T
	ctx  context.Context
	once sync.Once
	err  error
}

func (c *childProcess) reap() error {
	c.once.Do(func() { c.err = c.Cmd.Wait() })
	return c.err
}

func (c *childProcess) Wait() error {
	c.t.Helper()
	err := c.reap()
	if c.ctx.Err() != nil {
		c.t.Fatal("child watchdog expired; not an expected CLI failure")
	}
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 1 {
			c.t.Fatal("child did not exit with the expected CLI status 1")
		}
	}
	return err
}

func receiveTest[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	select {
	case value := <-ch:
		return value
	case <-timer.C:
		t.Fatal("parent fixture synchronization timed out")
		var zero T
		return zero
	}
}

func writeInput(t *testing.T, in io.Writer, value string) {
	t.Helper()
	if n, err := io.WriteString(in, value); err != nil || n != len(value) {
		t.Fatal("lifecycle input write failed")
	}
}

func child(t *testing.T, config string) (*childProcess, io.WriteCloser, *bufio.Reader, *bytes.Buffer) {
	t.Helper()
	return childArgs(t, "bridge", "--config", config)
}

// JACK_CLI_EXECUTABLE optionally selects an absolute, parent-built artifact.
func childArgs(t *testing.T, args ...string) (*childProcess, io.WriteCloser, *bufio.Reader, *bytes.Buffer) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	t.Cleanup(cancel)
	executable := os.Getenv("JACK_CLI_EXECUTABLE")
	helper := executable == ""
	if helper {
		executable = os.Args[0]
		args = append([]string{"-test.run=^TestCLIProcessHelper$", "--"}, args...)
	} else if !filepath.IsAbs(executable) {
		t.Fatal("JACK_CLI_EXECUTABLE must be an absolute artifact path")
	}
	cmd := exec.CommandContext(ctx, executable, args...)
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "JACK_CLI_CHILD=") {
			cmd.Env = append(cmd.Env, value)
		}
	}
	if helper {
		cmd.Env = append(cmd.Env, "JACK_CLI_CHILD=1")
	}
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	process := &childProcess{Cmd: cmd, t: t, ctx: ctx}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
		}
		_ = process.reap()
	})
	return process, in, bufio.NewReader(out), &stderr
}

func TestProcessLifecycleExactBytes(t *testing.T) {
	calls := make(chan string, 8)
	path, _, _ := signedFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		select {
		case calls <- string(b):
		default:
			t.Error("unexpected extra lifecycle request")
			w.WriteHeader(500)
			return
		}
		if r.Header.Get("Accept") != "application/json, text/event-stream" || r.Header.Get("MCP-Protocol-Version") != protocolVersion {
			w.WriteHeader(400)
			return
		}
		m, _ := object(b)
		if text(m["method"]) == "notifications/initialized" {
			w.WriteHeader(202)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if text(m["method"]) == "initialize" {
			_, _ = io.WriteString(w, initializeReply)
		} else {
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":7,"result":{"tools":[]}}`)
		}
	}))
	cmd, in, out, stderr := child(t, path)
	// Split framing without changing a single byte of the signed object.
	writeInput(t, in, initializeFrame[:17])
	writeInput(t, in, initializeFrame[17:]+"\n")
	line, err := out.ReadString('\n')
	if err != nil || line != initializeReply+"\n" || receiveTest(t, calls) != initializeFrame {
		t.Fatal("initialize bytes or output framing changed")
	}
	writeInput(t, in, initializedFrame+"\n")
	if receiveTest(t, calls) != initializedFrame {
		t.Fatal("hidden handshake or altered notification")
	}
	request := `{"jsonrpc":"2.0","id":7,"method":"tools/list"}`
	writeInput(t, in, request+"\n")
	line, err = out.ReadString('\n')
	if err != nil || line != "{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"tools\":[]}}\n" || receiveTest(t, calls) != request {
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
	request := strings.Replace(initializeFrame, `"test"`, `"客户🙂\nline"`, 1)
	reply := strings.Replace(initializeReply, `"fixture"`, `"服务🙂\nline"`, 1)
	calls := make(chan string, 1)
	path, _, _ := signedFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	cmd, in, out, stderr := child(t, path)
	// Deliberately split inside a multibyte UTF-8 encoding.
	split := strings.Index(request, "客") + 1
	writeInput(t, in, request[:split])
	writeInput(t, in, request[split:]+"\n")
	line, err := out.ReadString('\n')
	if err != nil || line != reply+"\n" || receiveTest(t, calls) != request {
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
		{"multiline", "application/json", strings.Replace(initializeReply, ",", ",\n", 1), 200},
		{"wrong-id", "application/json", strings.Replace(initializeReply, `"init"`, `"other"`, 1), 200},
		{"wrong-version", "application/json", strings.Replace(initializeReply, protocolVersion, "2026-07-28", 1), 200},
		{"not-rpc", "application/json", `{"unexpected":true}`, 200},
		{"session-header", "application/json", initializeReply, 200},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			path, _, _ := signedFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", tc.content)
				if tc.name == "session-header" {
					w.Header().Set("Mcp-Session-Id", "sensitive-session")
				}
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			cmd, in, out, stderr := child(t, path)
			writeInput(t, in, initializeFrame+"\n")
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
		// EOF cancels the in-flight POST and returns its result, not errProtocol.
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
					m, err := object(body)
					if err != nil || text(m["method"]) != "tools/call" {
						t.Error("timeout control did not reach enrollment POST")
					}
				} else if string(body) != initializeFrame {
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
			path, cfg, _ := signedFixture(t, handler)
			if tc.name == "ordinary-http-timeout" {
				// Stall the real HTTP peer before any response, outside Native
				// dispatch (the signed fixture correctly intercepts jack.enroll).
				peer := httptest.NewServer(handler)
				t.Cleanup(peer.Close)
				cfg.Endpoint = peer.URL + "/mcp"
				path = saveJSON(t, privateDir(t), "timeout-client.json", cfg)
			}
			// Release the handler on assertion failure before either server's
			// cleanup. This escape hatch is never a passing observation.
			t.Cleanup(func() { close(abort) })
			var cmd *childProcess
			var in io.WriteCloser
			var out *bufio.Reader
			var stderr *bytes.Buffer
			if tc.name == "ordinary-http-timeout" {
				invite := save(t, privateDir(t), "invite", []byte(jack.EncodeBase64URL(make([]byte, 32))))
				cmd, in, out, stderr = childArgs(t, "enroll", "--config", path, "--invite-file", invite, "--name", "alice")
			} else {
				cmd, in, out, stderr = child(t, path)
				writeInput(t, in, initializeFrame+"\n")
			}
			receiveTest(t, entered)
			switch tc.name {
			case "in-flight-eof":
				if err := in.Close(); err != nil {
					t.Fatal("could not deliver in-flight EOF")
				}
			case "unsupported-cancellation":
				writeInput(t, in, tc.input)
			}
			b, readErr := io.ReadAll(out)
			if cmd.Wait() == nil || readErr != nil || len(b) != 0 || stderr.String() != tc.stderr {
				t.Fatal("wrong failure category, stdout, or exit for cancellation/EOF/HTTP timeout")
			}
			if err := receiveTest(t, left); !errors.Is(err, context.Canceled) {
				t.Fatal("real upstream did not observe request cancellation")
			}
			if calls.Load() != 1 {
				t.Fatal("request retried or unsolicited cancellation forwarded")
			}
		})
	}
}

func TestProcessFramingAndIdleDeadline(t *testing.T) {
	for _, input := range []string{"[]\n", "{}", "{\"jsonrpc\":\"2.0\",\"method\":\"initialize\"}\n", string([]byte{0xff, '\n'}), strings.Repeat("x", maxBody+1) + "\n"} {
		path, _, _ := signedFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("invalid frame reached upstream") }))
		cmd, in, out, stderr := child(t, path)
		_, _ = io.WriteString(in, input)
		_ = in.Close()
		b, _ := io.ReadAll(out)
		if cmd.Wait() == nil || len(b) != 0 || stderr.String() != "jack: unsupported or invalid protocol message\n" {
			t.Fatal("invalid/truncated frame accepted or failed for the wrong reason")
		}
	}
	path, _, _ := signedFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("idle bridge called network") }))
	cmd, _, out, stderr := child(t, path)
	b, _ := io.ReadAll(out)
	if cmd.Wait() == nil || len(b) != 0 || stderr.String() != "jack: operation cancelled or deadline exceeded\n" {
		t.Fatal("idle read deadline not enforced")
	}
}

func processResult(t *testing.T, args ...string) ([]byte, []byte, error) {
	t.Helper()
	cmd, in, out, stderr := childArgs(t, args...)
	_ = in.Close()
	stdout, err := io.ReadAll(out)
	if err != nil {
		t.Fatal("reading child stdout failed")
	}
	waitErr := cmd.Wait()
	return stdout, append([]byte(nil), stderr.Bytes()...), waitErr
}

func assertNoProcessLeak(t *testing.T, stdout, stderr []byte, forbidden ...[]byte) {
	t.Helper()
	for _, value := range forbidden {
		if len(value) != 0 && (bytes.Contains(stdout, value) || bytes.Contains(stderr, value)) {
			t.Fatal("child output disclosed supplied sensitive data")
		}
	}
}

func TestProcessKeygenOverwriteUnchanged(t *testing.T) {
	for _, role := range []string{"server", "user"} {
		t.Run(role, func(t *testing.T) {
			d := privateDir(t)
			secret := filepath.Join(d, "sensitive-secret.seed")
			public := filepath.Join(d, "sensitive-public.json")
			args := []string{"keygen", role, "--secret", secret, "--public", public}
			stdout, stderr, err := processResult(t, args...)
			if err != nil || len(stdout) != 0 || len(stderr) != 0 {
				t.Fatal("initial process keygen failed")
			}
			seed, err := readPrivate(secret, 32)
			if err != nil || len(seed) != 32 {
				t.Fatal("process did not create a raw seed")
			}
			pub, err := readPrivate(public, 4096)
			if err != nil {
				t.Fatal("process did not create public identity")
			}
			stdout, stderr, err = processResult(t, args...)
			if err == nil || len(stdout) != 0 || len(stderr) == 0 {
				t.Fatal("process overwrite accepted or hidden")
			}
			assertNoProcessLeak(t, stdout, stderr, seed, []byte(jack.EncodeBase64URL(seed)), []byte(secret), []byte(public))
			afterSeed, _ := readPrivate(secret, 32)
			afterPub, _ := readPrivate(public, 4096)
			if !bytes.Equal(seed, afterSeed) || !bytes.Equal(pub, afterPub) {
				t.Fatal("process overwrite changed existing files")
			}
			newPublic := filepath.Join(d, "sensitive-new-public.json")
			stdout, stderr, err = processResult(t, "keygen", role, "--secret", secret, "--public", newPublic)
			if err == nil {
				t.Fatal("process accepted an existing secret with a new public destination")
			}
			assertNoProcessLeak(t, stdout, stderr, seed, []byte(secret), []byte(newPublic))
			if _, err := os.Lstat(newPublic); !os.IsNotExist(err) {
				t.Fatal("process left a public reservation after refusal")
			}
			afterSeed, _ = readPrivate(secret, 32)
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
			d := privateDir(t)
			state := save(t, d, "sensitive-state.json", tc.data)
			invite := save(t, d, "sensitive-invite", []byte(jack.EncodeBase64URL(bytes.Repeat([]byte{9}, 32))))
			inviteBefore, _ := readPrivate(invite, 43)
			stdout, stderr, err := processResult(t, "bootstrap", "--state", state, "--invite-file", invite)
			if err == nil || len(stdout) != 0 || len(stderr) == 0 {
				t.Fatal("bootstrap existing-state refusal missing")
			}
			assertNoProcessLeak(t, stdout, stderr, tc.data, issued.Secret(), inviteBefore, []byte(state), []byte(invite))
			after, _ := readPrivate(state, maxBody)
			afterInvite, _ := readPrivate(invite, 43)
			if !bytes.Equal(after, tc.data) || !bytes.Equal(afterInvite, inviteBefore) {
				t.Fatal("bootstrap process changed existing state or invite")
			}
			unused := filepath.Join(d, "sensitive-unused-invite")
			stdout, stderr, err = processResult(t, "bootstrap", "--state", state, "--invite-file", unused)
			if err == nil {
				t.Fatal("existing state accepted with absent invite destination")
			}
			assertNoProcessLeak(t, stdout, stderr, tc.data, []byte(state), []byte(unused))
			after, _ = readPrivate(state, maxBody)
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
	d := privateDir(t)
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
	key := save(t, d, "sensitive-credential", credential)
	inviteBytes := []byte(jack.EncodeBase64URL(bytes.Repeat([]byte{71}, 32)))
	invite := save(t, d, "sensitive-invite", inviteBytes)
	base := clientConfig{
		Version: 1, Endpoint: expected.URL, Aud: expected.Aud, ServerPublicKey: jack.EncodeBase64URL(pub),
		ServerKID: expected.ServerKID, KeyFile: key, KeyFormat: "credential", CallTimeoutMS: 1000,
	}
	for i, mutate := range []func(*clientConfig){
		func(c *clientConfig) { c.Endpoint += "/different" },
		func(c *clientConfig) { c.Aud += "-different" },
		func(c *clientConfig) { c.ServerPublicKey = jack.EncodeBase64URL(other) },
		func(c *clientConfig) { c.ServerKID = jack.KeyID(other) },
		func(c *clientConfig) {
			c.ServerPublicKey = jack.EncodeBase64URL(other)
			c.ServerKID = jack.KeyID(other)
		},
	} {
		c := base
		mutate(&c)
		config := saveJSON(t, d, "sensitive-config-"+strconv.Itoa(i)+".json", c)
		configBefore, _ := readPrivate(config, 16384)
		name := "sensitive-user-name"
		stdout, stderr, err := processResult(t, "enroll", "--config", config, "--invite-file", invite, "--name", name)
		if err == nil || len(stdout) != 0 || len(stderr) == 0 {
			t.Fatal("credential tuple mismatch process accepted or hidden")
		}
		assertNoProcessLeak(t, stdout, stderr, credential, seed, []byte(jack.EncodeBase64URL(seed)), inviteBytes,
			[]byte(config), []byte(key), []byte(invite), []byte(name), []byte(c.Endpoint), []byte(c.Aud))
		after, _ := readPrivate(config, 16384)
		afterKey, _ := readPrivate(key, 4096)
		afterInvite, _ := readPrivate(invite, 43)
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
			var matched *verifiedStatusError
			err := &verifiedStatusError{status: status}
			if !errors.Is(err, errRemote) || !errors.As(err, &matched) || matched.status != status {
				t.Fatal("verified error lost remote error matching")
			}
			d := privateDir(t)
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
			key := save(t, d, "user.seed", issued.Secret())
			inviteBytes := []byte(jack.EncodeBase64URL(bytes.Repeat([]byte{45}, 32)))
			invite := save(t, d, "invite", inviteBytes)
			config := saveJSON(t, d, "client.json", clientConfig{
				Version: 1, Endpoint: remote.URL + "/mcp", Aud: "svc", ServerPublicKey: jack.EncodeBase64URL(pub),
				ServerKID: jack.KeyID(pub), KeyFile: key, KeyFormat: "raw-seed", CallTimeoutMS: 1000,
			})
			stdout, stderr, processErr := processResult(t, "enroll", "--config", config, "--invite-file", invite, "--name", "sensitive-name")
			want := "jack: authenticated HTTP " + strconv.Itoa(status) + "; no retry performed\n"
			if processErr == nil || len(stdout) != 0 || string(stderr) != want || calls.Load() != 1 {
				t.Fatal("enrollment lost authenticated status or retried")
			}
			assertNoProcessLeak(t, stdout, stderr, issued.Secret(), inviteBytes, []byte("sensitive-remote-body"), []byte("sensitive-name"), []byte(config))
		})
	}
}

func TestProcessNotification202NonemptyRejected(t *testing.T) {
	for _, nonempty := range []bool{false, true} {
		t.Run(strconv.FormatBool(nonempty), func(t *testing.T) {
			var calls atomic.Int32
			path, _, _ := signedFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				b, _ := io.ReadAll(r.Body)
				m, _ := object(b)
				if text(m["method"]) == "initialize" {
					w.Header().Set("Content-Type", "application/json")
					_, _ = io.WriteString(w, initializeReply)
					return
				}
				w.WriteHeader(202)
				if nonempty {
					_, _ = io.WriteString(w, "sensitive-notification-body")
				}
			}))
			cmd, in, out, stderr := child(t, path)
			writeInput(t, in, initializeFrame+"\n")
			line, err := out.ReadString('\n')
			if err != nil || line != initializeReply+"\n" {
				t.Fatal("notification test initialization failed")
			}
			writeInput(t, in, initializedFrame+"\n")
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
			assertNoProcessLeak(t, stdout, stderr.Bytes(), []byte("sensitive-notification-body"))
		})
	}
}

func TestNotification202Not204(t *testing.T) {
	for _, status := range []int{202, 204} {
		path, _, _ := signedFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
		c, err := loadConnection(path)
		if err != nil {
			t.Fatal(err)
		}
		state := 1
		var out bytes.Buffer
		err = relayFrame(context.Background(), c, &out, []byte(initializedFrame), &state)
		if (err == nil) != (status == 202) || out.Len() != 0 {
			t.Fatal("notification status/framing contract violated")
		}
	}
}
