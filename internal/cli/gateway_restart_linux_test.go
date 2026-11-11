//go:build linux

package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/client"
	"github.com/PHPCraftdream/mcp-jack/durable"
	"github.com/PHPCraftdream/mcp-jack/rotation"
	"github.com/PHPCraftdream/mcp-jack/userkey"
)

func TestGatewayBinaryDurableCleanAndDirtyRestart(t *testing.T) {
	testGatewayBinaryDurableRestart(t, false)
}

func TestGatewayBinaryRotationCleanAndDirtyRestart(t *testing.T) {
	testGatewayBinaryDurableRestart(t, true)
}

func testGatewayBinaryDurableRestart(t *testing.T, rotationMode bool) {
	t.Helper()
	if os.Getenv("JACK_CLI_EXECUTABLE") == "" {
		t.Skip("shipping executable supplied by the mandatory binary qualification job")
	}
	directory := privateDir(t)
	var upstreamCalls atomic.Int32
	socket := unixUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":41,"result":{"ok":true}}`)
	}))
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listen := reservation.Addr().String()
	if err := reservation.Close(); err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	statePath, invitePath := filepath.Join(directory, "state.json"), filepath.Join(directory, "bootstrap.invite")
	if err := bootstrap(statePath, invitePath); err != nil {
		t.Fatal(err)
	}
	noncePath := filepath.Join(directory, "nonces.db")
	profile := &gatewayDurableConfig{Path: noncePath, DeploymentID: "public-binary-restart-test", Window: 30}
	gatewayConfiguration := gatewayConfig{
		Version: 1, Aud: "svc", ServerSeedFile: save(t, directory, "server.seed", private.Seed()), StateFile: statePath,
		Listen: listen, UpstreamSocket: socket, UpstreamURL: "http://upstream/mcp", CallTimeoutMS: 1000, MaxConcurrent: 4, DurableNonces: profile,
	}
	var serverProfile serverKeyConfig
	var serverProfilePath string
	var ringOptions durable.ServerOptions
	var publication serverKeyPublication
	if rotationMode {
		nextPublic, nextPrivate, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		serverProfile = serverKeyConfig{Version: 1, StoreFile: filepath.Join(directory, "ring.db"), Endpoint: "http://" + listen + "/mcp",
			Aud: "svc", Window: 30, AnchorKID: jack.KeyID(public), AnchorPublicKey: jack.EncodeBase64URL(public), AnchorReference: "binary-anchor",
			Signers: []serverKeySignerConfig{{Reference: "binary-anchor", KID: jack.KeyID(public), SeedFile: gatewayConfiguration.ServerSeedFile},
				{Reference: "binary-next", KID: jack.KeyID(nextPublic), SeedFile: save(t, directory, "next.seed", nextPrivate.Seed())}}}
		serverProfilePath = saveJSON(t, directory, "rotation.json", serverProfile)
		_, ringOptions, err = offlineServerKeyProfile(serverProfilePath)
		if err != nil {
			t.Fatal(err)
		}
		gatewayConfiguration.ServerSeedFile = ""
		gatewayConfiguration.ServerRotationFile = rotationProfilePath(serverProfilePath)
	}
	gatewayPath := saveJSON(t, directory, "gateway.json", gatewayConfiguration)
	invoke := func(args ...string) []byte {
		t.Helper()
		process, in, out, diagnostics := childArgs(t, args...)
		_ = in.Close()
		reply, err := io.ReadAll(io.LimitReader(out, maxBody+1))
		waitErr := process.Wait()
		if err != nil || len(reply) > maxBody || waitErr != nil {
			t.Fatalf("binary setup failed: %s", diagnostics.String())
		}
		return reply
	}
	invoke("nonce-init-unused", "--config", gatewayPath, "--confirm-unused-deployment", profile.DeploymentID)
	if rotationMode {
		invoke(serverKeyInitArgs(serverProfilePath, serverProfile)...)
		if json.Unmarshal(invoke(announceArgs(serverProfilePath, serverProfile.Signers[1])...), &publication) != nil || publication.Ordinal != 1 || publication.StateRevision != 2 || publication.Record == "" {
			t.Fatal("shipping binary did not confirm exact offline publication")
		}
	}
	issued, _, err := userkey.IssueLocalPair()
	if err != nil {
		t.Fatal(err)
	}
	clientPath := saveJSON(t, directory, "client.json", clientConfig{
		Version: 1, Endpoint: "http://" + listen + "/mcp", Aud: "svc", ServerPublicKey: jack.EncodeBase64URL(public), ServerKID: jack.KeyID(public),
		KeyFile: save(t, directory, "client.seed", issued.Secret()), KeyFormat: "raw-seed", CallTimeoutMS: 1000,
	})
	start := func() *childProcess {
		t.Helper()
		process, in, _, _ := childArgs(t, "gateway", "--config", gatewayPath)
		_ = in.Close()
		deadline := time.NewTimer(2 * time.Second)
		defer deadline.Stop()
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			connection, err := net.DialTimeout("tcp", listen, 20*time.Millisecond)
			if err == nil {
				_ = connection.Close()
				return process
			}
			select {
			case <-process.ctx.Done():
				t.Fatal("gateway child watchdog expired before readiness")
			case <-deadline.C:
				t.Fatal("gateway binary did not listen")
			case <-ticker.C:
			}
		}
	}
	stop := func(process *childProcess) {
		t.Helper()
		if err := process.Process.Signal(syscall.SIGTERM); err != nil || process.Wait() != nil {
			t.Fatal("gateway binary did not drain cleanly")
		}
	}
	first := start()
	invoke("enroll", "--config", clientPath, "--invite-file", invitePath, "--name", "first-admin")
	conn, err := loadConnection(clientPath)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"jsonrpc":"2.0","id":41,"method":"tools/call","params":{"name":"app.echo","arguments":{}}}`)
	nonce, err := client.RandomNonce()
	if err != nil {
		t.Fatal(err)
	}
	header, err := client.SignRequest(conn.signer, conn.aud, "POST", "/mcp", body, nonce, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	auth, err := jack.ParseRequestAuth([]string{header})
	if err != nil {
		t.Fatal(err)
	}
	sendExact := func() (int, []byte, []string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		request, err := http.NewRequestWithContext(ctx, "POST", conn.endpoint, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Jack-Auth", header)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("MCP-Protocol-Version", protocolVersion)
		network := directTransport(time.Second)
		defer network.CloseIdleConnections()
		response, err := (oneShot{network}).RoundTrip(request)
		if err != nil {
			t.Fatal("exact request did not reach gateway")
		}
		defer response.Body.Close()
		reply, err := io.ReadAll(io.LimitReader(response.Body, maxBody+1))
		if err != nil || len(reply) > maxBody {
			t.Fatal("gateway response unreadable or unbounded")
		}
		return response.StatusCode, reply, response.Header.Values("Jack-Auth")
	}
	status, reply, responseAuth := sendExact()
	if status != 200 || client.VerifyResponse(conn.pin, status, responseAuth, auth.Sig, reply, time.Now(), 30*time.Second) != nil || upstreamCalls.Load() != 1 {
		t.Fatal("first signed request did not dispatch exactly once")
	}
	expectedLive := 2
	if rotationMode {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		nativeBody := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"jack.server.key","arguments":{"after_ordinal":0,"after_hash":"-"}}}`)
		nativeReply, nativeStatus, nativeErr := conn.post(ctx, nativeBody)
		cancel()
		page, decodeErr := rotation.DecodeResult(nativeReply, json.RawMessage(`1`))
		if nativeErr != nil || nativeStatus != 200 || decodeErr != nil || len(page.Records) != 1 || page.Records[0] != publication.Record || page.Head.Hash != publication.Hash || !page.Complete || upstreamCalls.Load() != 1 {
			t.Fatal("shipping rotating gateway did not deliver the exact native page", nativeErr, decodeErr)
		}
		expectedLive++
	}
	stop(first)
	options := durable.Options{DeploymentID: profile.DeploymentID, Window: profile.Window}
	inspect, err := durable.InspectRecovery(noncePath, options)
	if err != nil || inspect.Dirty || inspect.Unsafe || len(inspect.Live) != expectedLive {
		t.Fatal("clean binary shutdown lost reservations or left dirty owner")
	}
	if rotationMode {
		ring, err := durable.InspectServer(serverProfile.StoreFile, ringOptions)
		if err != nil || ring.Dirty || ring.Unsafe || ring.HeadOrdinal != 1 || ring.HeadHash != publication.Hash || ring.StateRevision != 2 {
			t.Fatal("clean binary shutdown lost ring state or serving fence", err)
		}
		var cliReport durable.ServerInspection
		if json.Unmarshal(invoke("server-key-status", "--config", serverProfilePath), &cliReport) != nil || cliReport != ring {
			t.Fatal("shipping offline status changed ring evidence")
		}
	}
	second := start()
	status, reply, responseAuth = sendExact()
	var refusal struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if status != 401 || json.Unmarshal(reply, &refusal) != nil || refusal.Error.Code != jack.CodeReplayedNonce || len(responseAuth) != 0 || upstreamCalls.Load() != 1 {
		t.Fatal("clean restart replayed exact request or returned a different refusal")
	}
	stop(second)
	third := start()
	if err := third.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := third.reap(); err == nil || third.ctx.Err() != nil {
		t.Fatal("owned gateway child was not stopped by the injected crash")
	}
	dirty, err := durable.InspectRecovery(noncePath, options)
	if err != nil || !dirty.Dirty || len(dirty.Live) != expectedLive {
		t.Fatal("crash lost durable serving fence or reservation history")
	}
	var dirtyRing durable.ServerInspection
	var dirtyRingBytes []byte
	if rotationMode {
		dirtyRing, err = durable.InspectServer(serverProfile.StoreFile, ringOptions)
		if err != nil || !dirtyRing.Dirty || dirtyRing.HeadOrdinal != 1 || dirtyRing.HeadHash != publication.Hash || dirtyRing.StateRevision != 2 {
			t.Fatal("owned process crash lost rotation serving fence or exact publication", err)
		}
		dirtyRingBytes, err = os.ReadFile(serverProfile.StoreFile)
		if err != nil {
			t.Fatal(err)
		}
	}
	// Архивируется только собственный registry lock; durable fences не меняются.
	ownerPath := statePath + ".owner"
	owner, err := readPrivate(ownerPath, 64)
	if err != nil || string(owner) != "jack owner\n" {
		t.Fatal("crashed child registry lock missing or changed")
	}
	if err := os.Rename(ownerPath, ownerPath+".crashed"); err != nil {
		t.Fatal(err)
	}
	closed, in, out, _ := childArgs(t, "gateway", "--config", gatewayPath)
	_ = in.Close()
	output, err := io.ReadAll(io.LimitReader(out, maxBody+1))
	if err != nil || len(output) != 0 || closed.Wait() == nil || upstreamCalls.Load() != 1 {
		t.Fatal("dirty restart served traffic or silently reset history")
	}
	after, err := durable.InspectRecovery(noncePath, options)
	if err != nil || !after.Dirty || after.Hash != dirty.Hash {
		t.Fatal("refused restart changed dirty durable state")
	}
	if rotationMode {
		afterRing, err := durable.InspectServer(serverProfile.StoreFile, ringOptions)
		if err != nil || afterRing != dirtyRing {
			t.Fatal("refused restart cleared or changed ring fence/evidence", err)
		}
		afterBytes, err := os.ReadFile(serverProfile.StoreFile)
		if err != nil || !bytes.Equal(afterBytes, dirtyRingBytes) {
			t.Fatal("refused rotation restart rewrote protected state")
		}
	}
}
