package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
)

const callToolNonce = "assryd677-uYrqD4v-7HYw"

// callToolRecorder captures request bodies seen by a test server handler.
type callToolRecorder struct {
	mu     sync.Mutex
	hits   int32
	bodies [][]byte
}

func (r *callToolRecorder) add(body []byte) {
	atomic.AddInt32(&r.hits, 1)
	r.mu.Lock()
	r.bodies = append(r.bodies, append([]byte(nil), body...))
	r.mu.Unlock()
}

func (r *callToolRecorder) last() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.bodies) == 0 {
		return nil
	}
	return r.bodies[len(r.bodies)-1]
}

// callToolServer starts a test server whose handler records the request body
// and delegates the reply to reply.
func callToolServer(t *testing.T, reply func(s *testServer, w http.ResponseWriter, auth jack.RequestAuth)) (*testServer, *callToolRecorder) {
	t.Helper()
	srv := newTestServer(t)
	rec := &callToolRecorder{}
	srv.Handle = func(w http.ResponseWriter, auth jack.RequestAuth, body []byte) {
		rec.add(body)
		reply(srv, w, auth)
	}
	return srv, rec
}

// callToolClient builds a client with n copies of the fixed nonce queued.
func callToolClient(t *testing.T, srv *testServer, n int) *Client {
	t.Helper()
	nonces := make([]string, n)
	for i := range nonces {
		nonces[i] = callToolNonce
	}
	return newFixtureClient(t, srv, seedSignerByName(t, "alice"), nonces...)
}

type callToolRequest struct {
	Method string `json:"method"`
	Params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	} `json:"params"`
}

func callToolDecodeRequest(t *testing.T, body []byte) callToolRequest {
	t.Helper()
	var req callToolRequest
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("decode request body %q: %v", body, err)
	}
	return req
}

func callToolOK(structured string) func(s *testServer, w http.ResponseWriter, auth jack.RequestAuth) {
	return func(s *testServer, w http.ResponseWriter, auth jack.RequestAuth) {
		s.writeSignedJSON(w, auth, http.StatusOK, rpcResultBody(json.RawMessage(structured)))
	}
}

func TestCallToolRoundTrip(t *testing.T) {
	const structured = `{"status":"restarted","count":3,"note":"héllo 世界 🚀","nested":{"ids":[1,2]}}`
	args := map[string]any{
		"name": "héllo 世界 🚀",
		"opts": map[string]any{"retries": 3, "tags": []any{"a", "b"}},
	}
	type result struct {
		Status string `json:"status"`
		Count  int    `json:"count"`
		Note   string `json:"note"`
		Nested struct {
			IDs []int `json:"ids"`
		} `json:"nested"`
	}

	srv, rec := callToolServer(t, callToolOK(structured))
	c := callToolClient(t, srv, 2)

	t.Run("typed", func(t *testing.T) {
		var res result
		if err := c.CallTool(context.Background(), "svc.restart", args, &res); err != nil {
			t.Fatalf("CallTool: %v", err)
		}
		if res.Status != "restarted" || res.Count != 3 || res.Note != "héllo 世界 🚀" || !reflect.DeepEqual(res.Nested.IDs, []int{1, 2}) {
			t.Fatalf("decoded result = %+v", res)
		}
		req := callToolDecodeRequest(t, rec.last())
		if req.Method != "tools/call" || req.Params.Name != "svc.restart" {
			t.Fatalf("request method/name = %q/%q", req.Method, req.Params.Name)
		}
		var got, want any
		if err := json.Unmarshal(req.Params.Arguments, &got); err != nil {
			t.Fatalf("decode arguments: %v", err)
		}
		wantRaw, err := json.Marshal(args)
		if err != nil {
			t.Fatalf("marshal want: %v", err)
		}
		if err := json.Unmarshal(wantRaw, &want); err != nil {
			t.Fatalf("decode want: %v", err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("arguments = %v, want %v", got, want)
		}
	})

	t.Run("raw", func(t *testing.T) {
		var raw json.RawMessage
		if err := c.CallTool(context.Background(), "svc.restart", args, &raw); err != nil {
			t.Fatalf("CallTool: %v", err)
		}
		var gotBuf, wantBuf bytes.Buffer
		if err := json.Compact(&gotBuf, raw); err != nil {
			t.Fatalf("compact raw %q: %v", raw, err)
		}
		if err := json.Compact(&wantBuf, []byte(structured)); err != nil {
			t.Fatalf("compact want: %v", err)
		}
		if !bytes.Equal(gotBuf.Bytes(), wantBuf.Bytes()) {
			t.Fatalf("raw = %s, want %s", gotBuf.Bytes(), wantBuf.Bytes())
		}
	})
}

func TestCallToolNilArgumentsAndNilOut(t *testing.T) {
	cases := []struct {
		name       string
		reply      func(s *testServer, w http.ResponseWriter, auth jack.RequestAuth)
		wantErrSub string
	}{
		{"payload ignored", callToolOK(`{"status":"restarted"}`), ""},
		{"undecodable payload ignored", callToolOK(`[1,"x",{"a":null}]`), ""},
		{"missing structuredContent still errors", func(s *testServer, w http.ResponseWriter, auth jack.RequestAuth) {
			s.writeSignedJSON(w, auth, http.StatusOK, []byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}],"isError":false}}`))
		}, "missing structuredContent"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, rec := callToolServer(t, tc.reply)
			c := callToolClient(t, srv, 1)
			err := c.CallTool(context.Background(), "svc.restart", nil, nil)
			if tc.wantErrSub == "" {
				if err != nil {
					t.Fatalf("CallTool: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantErrSub) {
				t.Fatalf("err = %v, want containing %q", err, tc.wantErrSub)
			}
			req := callToolDecodeRequest(t, rec.last())
			if string(req.Params.Arguments) != "{}" {
				t.Fatalf("arguments = %s, want {}", req.Params.Arguments)
			}
		})
	}
}

// callToolTampered signs body A but sends body B.
func callToolTampered(s *testServer, w http.ResponseWriter, auth jack.RequestAuth) {
	signed := rpcResultBody(json.RawMessage(`{"status":"signed"}`))
	sent := rpcResultBody(json.RawMessage(`{"status":"tampered"}`))
	msg := []byte(jack.ResponseSigningString(http.StatusOK, auth.Sig, s.Kid, s.Now, signed))
	sig := ed25519.Sign(s.Key, msg)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Jack-Auth", jack.FormatResponseAuth(jack.ResponseAuth{Kid: s.Kid, TS: s.Now, Sig: jack.EncodeBase64URL(sig)}))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(sent)
}

func TestCallToolErrors(t *testing.T) {
	signedErr := func(status int, body string) func(s *testServer, w http.ResponseWriter, auth jack.RequestAuth) {
		return func(s *testServer, w http.ResponseWriter, auth jack.RequestAuth) {
			s.writeSignedJSON(w, auth, status, []byte(body))
		}
	}
	cases := []struct {
		name  string
		reply func(s *testServer, w http.ResponseWriter, auth jack.RequestAuth)
		check func(t *testing.T, err error)
	}{
		{"http 403", signedErr(http.StatusForbidden, `{"error":{"code":"insufficient_scope","message":"no"}}`), func(t *testing.T, err error) {
			var he *HTTPError
			if !errors.As(err, &he) {
				t.Fatalf("err = %T (%v), want *HTTPError", err, err)
			}
			if he.Status != http.StatusForbidden || he.Code != "insufficient_scope" {
				t.Fatalf("HTTPError = %+v", he)
			}
		}},
		{"http 500", signedErr(http.StatusInternalServerError, `{"error":{"code":"internal","message":"bad"}}`), func(t *testing.T, err error) {
			var he *HTTPError
			if !errors.As(err, &he) {
				t.Fatalf("err = %T (%v), want *HTTPError", err, err)
			}
			if he.Status != http.StatusInternalServerError || he.Code != "internal" {
				t.Fatalf("HTTPError = %+v", he)
			}
		}},
		{"rpc error", signedErr(http.StatusOK, `{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"bad params"}}`), func(t *testing.T, err error) {
			var re *RPCError
			if !errors.As(err, &re) {
				t.Fatalf("err = %T (%v), want *RPCError", err, err)
			}
			if re.Code != -32602 || re.Message != "bad params" {
				t.Fatalf("RPCError = %+v", re)
			}
		}},
		{"tool error", signedErr(http.StatusOK, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"boom"}],"isError":true,"structuredContent":{"why":"x"}}}`), func(t *testing.T, err error) {
			var te *ToolError
			if !errors.As(err, &te) {
				t.Fatalf("err = %T (%v), want *ToolError", err, err)
			}
			if te.Message != "boom" || string(te.Structured) != `{"why":"x"}` {
				t.Fatalf("ToolError = %+v (structured %s)", te, te.Structured)
			}
		}},
		{"unsigned 200 refused", func(s *testServer, w http.ResponseWriter, _ jack.RequestAuth) {
			s.writeUnsignedJSON(w, http.StatusOK, rpcResultBody(json.RawMessage(`{"status":"unsigned"}`)))
		}, func(t *testing.T, err error) {
			callToolWantJackCode(t, err, jack.CodeMissingAuth)
		}},
		{"tampered body refused", callToolTampered, func(t *testing.T, err error) {
			callToolWantJackCode(t, err, jack.CodeBadSignature)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := callToolServer(t, tc.reply)
			c := callToolClient(t, srv, 1)
			var out json.RawMessage
			err := c.CallTool(context.Background(), "svc.restart", map[string]any{"a": 1}, &out)
			if err == nil {
				t.Fatalf("CallTool succeeded with out=%s", out)
			}
			if len(out) != 0 {
				t.Fatalf("out touched on error: %s", out)
			}
			tc.check(t, err)
		})
	}
}

func callToolWantJackCode(t *testing.T, err error, code string) {
	t.Helper()
	var je *jack.Error
	if !errors.As(err, &je) {
		t.Fatalf("err = %T (%v), want *jack.Error %s", err, err, code)
	}
	if je.Code != code {
		t.Fatalf("jack code = %q, want %q", je.Code, code)
	}
	var he *HTTPError
	var re *RPCError
	var te *ToolError
	if errors.As(err, &he) || errors.As(err, &re) || errors.As(err, &te) {
		t.Fatalf("untrusted response surfaced as application error: %v", err)
	}
}

func TestCallToolLocalFailures(t *testing.T) {
	t.Run("marshal failure", func(t *testing.T) {
		cases := []struct {
			name string
			args any
		}{
			{"channel", map[string]any{"c": make(chan int)}},
			{"func", map[string]any{"f": func() {}}},
			{"NaN", map[string]any{"n": math.NaN()}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				srv, rec := callToolServer(t, callToolOK(`{}`))
				c := callToolClient(t, srv, 1)
				err := c.CallTool(context.Background(), "svc.restart", tc.args, nil)
				if err == nil || !strings.Contains(err.Error(), "marshal arguments") {
					t.Fatalf("err = %v, want marshal arguments error", err)
				}
				if n := atomic.LoadInt32(&rec.hits); n != 0 {
					t.Fatalf("server hit %d times, want 0", n)
				}
			})
		}
	})

	t.Run("decode failure", func(t *testing.T) {
		srv, _ := callToolServer(t, callToolOK(`{"a":1}`))
		c := callToolClient(t, srv, 1)
		var n int
		err := c.CallTool(context.Background(), "svc.restart", nil, &n)
		if err == nil {
			t.Fatal("decode into *int succeeded")
		}
		var ute *json.UnmarshalTypeError
		if !errors.As(err, &ute) {
			t.Fatalf("err = %T (%v), want *json.UnmarshalTypeError", err, err)
		}
		var he *HTTPError
		var te *ToolError
		if errors.As(err, &he) || errors.As(err, &te) {
			t.Fatalf("decode error surfaced as application error: %v", err)
		}
	})

	t.Run("canceled context", func(t *testing.T) {
		srv, rec := callToolServer(t, callToolOK(`{}`))
		c := callToolClient(t, srv, 1)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := c.CallTool(ctx, "svc.restart", nil, nil)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
		if n := atomic.LoadInt32(&rec.hits); n != 0 {
			t.Fatalf("server hit %d times, want 0", n)
		}
	})
}
