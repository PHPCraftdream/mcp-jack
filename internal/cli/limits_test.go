//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package cli

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PHPCraftdream/mcp-jack/client"
)

type observedPipeOutput struct {
	*os.File
	attempted chan struct{}
	once      sync.Once
}

func (w *observedPipeOutput) Write(p []byte) (int, error) {
	if len(p) > 100000 {
		w.once.Do(func() { close(w.attempted) })
	}
	return w.File.Write(p)
}

func TestOwnedPipeBrokenOutputAndBackpressure(t *testing.T) {
	for _, broken := range []bool{true, false} {
		t.Run(map[bool]string{true: "broken", false: "blocked"}[broken], func(t *testing.T) {
			finalReply := make(chan struct{}, 1)
			path, cfg, _ := signedFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				m, _ := object(b)
				w.Header().Set("Content-Type", "application/json")
				switch text(m["method"]) {
				case "initialize":
					_, _ = io.WriteString(w, initializeReply)
				case "notifications/initialized":
					w.WriteHeader(202)
				case "tools/list":
					select {
					case finalReply <- struct{}{}:
					default:
						t.Error("large response request retried")
					}
					_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":2,"result":{"value":"`+strings.Repeat("x", 900000)+`"}}`)
				default:
					t.Error("unexpected lifecycle call")
					w.WriteHeader(400)
				}
			}))
			cfg.CallTimeoutMS = 2000
			path = saveJSON(t, privateDir(t), "bounded.json", cfg)
			inRead, inWrite, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer inRead.Close()
			defer inWrite.Close()
			outRead, outWrite, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer outRead.Close()
			defer outWrite.Close()
			if inWrite.SetWriteDeadline(time.Now().Add(6*time.Second)) != nil || outRead.SetReadDeadline(time.Now().Add(6*time.Second)) != nil {
				t.Fatal("test pipes lack deadlines")
			}
			observed := &observedPipeOutput{File: outWrite, attempted: make(chan struct{})}
			var stderr bytes.Buffer
			done := make(chan int, 1)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			joined := false
			defer func() {
				cancel()
				_ = inRead.Close()
				_ = outWrite.Close()
				if !joined {
					select {
					case <-done:
					case <-time.After(3 * time.Second):
						t.Error("test bridge failed to join after cleanup")
					}
				}
			}()
			go func() {
				done <- Run(ctx, []string{"bridge", "--config", path}, IO{In: inRead, Out: observed, Err: &stderr})
			}()
			writeInput(t, inWrite, initializeFrame+"\n")
			if line, err := bufio.NewReader(outRead).ReadString('\n'); err != nil || line != initializeReply+"\n" {
				t.Fatal("pipe test initialize failed")
			}
			writeInput(t, inWrite, initializedFrame+"\n")
			if broken {
				_ = outRead.Close()
			}
			writeInput(t, inWrite, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`+"\n")
			receiveTest(t, finalReply)
			receiveTest(t, observed.attempted)
			select {
			case code := <-done:
				joined = true
				want := "jack: operation cancelled or deadline exceeded\n"
				if broken {
					want = "jack: unsupported or invalid protocol message\n"
				}
				if code != 1 || stderr.String() != want {
					t.Fatal("output failure was hidden or failed for the wrong reason")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("blocked owned pipe did not close/join")
			}
		})
	}
}

func TestExactAndPlusOneBodyCaps(t *testing.T) {
	var calls atomic.Int32
	var responsePlusOne atomic.Bool
	socket := unixUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		b, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
		if responsePlusOne.Load() {
			_, _ = io.WriteString(w, " ")
		}
	}))
	base := directTransport(3 * time.Second)
	base.DialContext = unixDial(socket)
	defer base.CloseIdleConnections()
	path, _, _ := signedFixture(t, upstreamHandler(gatewayConfig{UpstreamURL: "http://upstream/mcp"}, base))
	c, err := loadConnection(path)
	if err != nil {
		t.Fatal(err)
	}
	c.timeout = 3 * time.Second
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	body = append(body, bytes.Repeat([]byte(" "), maxBody-len(body))...)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	reply, status, err := c.post(ctx, body)
	if err != nil || status != 200 || !bytes.Equal(reply, body) || len(reply) != maxBody || calls.Load() != 1 {
		t.Fatal("exact request/response cap baseline refused or changed")
	}
	responsePlusOne.Store(true)
	if _, status, err := c.post(ctx, body); err == nil || status != 502 || calls.Load() != 2 {
		t.Fatal("response cap+1 did not produce a verified refusal")
	}
	tooLarge := append(append([]byte(nil), body...), ' ')
	if _, _, err := c.post(ctx, tooLarge); err == nil || calls.Load() != 2 {
		t.Fatal("local request cap+1 reached upstream")
	}
	// Bypass the CLI's local size check to discriminate the SDK HTTP ingress cap.
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(tooLarge))
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := client.RandomNonce()
	if err != nil {
		t.Fatal(err)
	}
	auth, err := client.SignRequest(c.signer, c.aud, r.Method, r.URL.RequestURI(), tooLarge, nonce, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Jack-Auth", auth)
	r.Header.Set("Content-Type", "application/json")
	network := directTransport(3 * time.Second)
	defer network.CloseIdleConnections()
	resp, err := (oneShot{network}).RoundTrip(r)
	if err != nil {
		t.Fatal("ingress cap control failed to reach gateway")
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 413 || len(resp.Header.Values("Jack-Auth")) != 0 || calls.Load() != 2 {
		t.Fatal("oversized HTTP ingress was forwarded or described as signed")
	}
}

func TestGatewayRequestAndResponseCapsAndDeadline(t *testing.T) {
	socket := unixUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		m, _ := object(b)
		if text(m["method"]) == "slow" {
			select {
			case <-r.Context().Done():
			case <-time.After(3 * time.Second):
				t.Error("slow fixture cancellation timed out")
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, strings.Repeat("x", maxBody+1))
	}))
	base := directTransport(200 * time.Millisecond)
	base.DialContext = unixDial(socket)
	t.Cleanup(base.CloseIdleConnections)
	path, _, _ := signedFixture(t, upstreamHandler(gatewayConfig{UpstreamURL: "http://upstream/mcp"}, base))
	c, err := loadConnection(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{"tools/list", "slow"} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		start := time.Now()
		_, status, err := c.post(ctx, []byte(`{"jsonrpc":"2.0","id":1,"method":"`+method+`"}`))
		cancel()
		if err == nil || status != 502 || time.Since(start) > 2*time.Second {
			t.Fatal("cap/deadline failed")
		}
	}
	if _, _, err := c.post(context.Background(), bytes.Repeat([]byte("x"), maxBody+1)); err == nil {
		t.Fatal("oversized request accepted")
	}
}
