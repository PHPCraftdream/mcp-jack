//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package cli

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/clitest"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/transport"
)

func TestProcessSignedResponseAndRequestTampering(t *testing.T) {
	var upstreamCalls atomic.Int32
	_, cfg, _ := clitest.SignedFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, clitest.InitializeReply)
	}))
	var mode atomic.Int32
	var proxyCalls atomic.Int32
	var fixtureError atomic.Bool
	base := transport.DirectTransport(time.Second)
	defer base.CloseIdleConnections()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyCalls.Add(1)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			fixtureError.Store(true)
			w.WriteHeader(500)
			return
		}
		selected := mode.Load()
		if selected == 4 {
			body = bytes.Replace(body, []byte(`"test"`), []byte(`"evil"`), 1)
		}
		req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, cfg.Endpoint, bytes.NewReader(body))
		if err != nil {
			fixtureError.Store(true)
			w.WriteHeader(500)
			return
		}
		req.Header = r.Header.Clone()
		resp, err := (transport.NewOneShot(base)).RoundTrip(req)
		if err != nil {
			fixtureError.Store(true)
			w.WriteHeader(502)
			return
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			fixtureError.Store(true)
			w.WriteHeader(500)
			return
		}
		for k, v := range resp.Header {
			w.Header()[k] = append([]string(nil), v...)
		}
		w.Header().Del("Content-Length")
		status := resp.StatusCode
		switch selected {
		case 1:
			b = bytes.Replace(b, []byte("fixture"), []byte("tampered"), 1)
		case 2:
			status = http.StatusMethodNotAllowed
		case 3:
			auth, err := jack.ParseResponseAuth(resp.Header.Values("Jack-Auth"))
			if err != nil {
				fixtureError.Store(true)
				w.WriteHeader(500)
				return
			}
			sig, err := jack.DecodeBase64URLFixed(auth.Sig, 64)
			if err != nil {
				fixtureError.Store(true)
				w.WriteHeader(500)
				return
			}
			sig[0] ^= 1
			auth.Sig = jack.EncodeBase64URL(sig)
			w.Header().Set("Jack-Auth", jack.FormatResponseAuth(auth))
		case 5, 6:
			w.Header().Del("Jack-Auth")
			status = http.StatusMethodNotAllowed
			if selected == 6 {
				status = http.StatusNotImplemented
			}
		}
		w.WriteHeader(status)
		_, _ = w.Write(b)
	}))
	defer proxy.Close()
	proxyConfig := cfg
	proxyConfig.Endpoint = proxy.URL + "/mcp"
	configPath := clitest.SaveJSON(t, clitest.PrivateDir(t), "proxy-client.json", proxyConfig)
	for _, tc := range []struct {
		name string
		mode int32
	}{
		{"valid-baseline", 0},
		{"response-body", 1},
		{"response-status-to-405", 2},
		{"response-signature", 3},
		{"request-body", 4},
		{"unsigned-405", 5},
		{"unsigned-501", 6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mode.Store(tc.mode)
			beforeUpstream := upstreamCalls.Load()
			beforeProxy := proxyCalls.Load()
			cmd, in, out, stderr := clitest.Child(t, configPath)
			clitest.WriteInput(t, in, clitest.InitializeFrame+"\n")
			if tc.mode == 0 {
				line, err := out.ReadString('\n')
				if err != nil || line != clitest.InitializeReply+"\n" {
					t.Fatal("positive network/process baseline failed")
				}
				_ = in.Close()
				rest, _ := io.ReadAll(out)
				if cmd.Wait() != nil || len(rest) != 0 || stderr.Len() != 0 {
					t.Fatal("positive baseline shutdown failed")
				}
			} else {
				stdout, _ := io.ReadAll(out)
				if cmd.Wait() == nil || len(stdout) != 0 || stderr.String() != "jack: remote call failed; no retry performed\n" {
					t.Fatal("tampering emitted bytes or was described as authenticated")
				}
			}
			wantUpstream := int32(1)
			if tc.mode == 4 {
				wantUpstream = 0
			}
			if fixtureError.Load() || upstreamCalls.Load()-beforeUpstream != wantUpstream || proxyCalls.Load()-beforeProxy != 1 {
				t.Fatal("fixture failed, request tamper reached upstream, or call retried")
			}
		})
	}
}
