//go:build linux

package durable

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/client"
	"github.com/PHPCraftdream/mcp-jack/server"
)

func TestActualHTTPOutcomesKeepNonceConsumedAcrossCleanRestart(t *testing.T) {
	for _, outcome := range []string{"success", "handler-error", "response-overflow", "streaming-refusal", "handler-panic"} {
		t.Run(outcome, func(t *testing.T) {
			now := int64(100)
			owner, path, opts := testOwner(t, &now)
			state := server.NewMemoryState()
			request := signedStorageRequest(t, state, 100, 13)
			auth, err := jack.ParseRequestAuth(request.AuthValues)
			if err != nil {
				t.Fatal(err)
			}
			seed := sha256.Sum256([]byte("mcp-jack public HTTP durable server fixture"))
			serverKey := ed25519.NewKeyFromSeed(seed[:])
			calls := 0
			next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls++
				if outcome == "handler-panic" {
					panic("public handler panic")
				}
				if outcome == "streaming-refusal" {
					w.Header().Set("Content-Type", "text/event-stream")
					_, _ = w.Write([]byte("data: x\n\n"))
					return
				}
				w.Header().Set("Content-Type", "application/json")
				if outcome == "handler-error" {
					w.WriteHeader(http.StatusInternalServerError)
				}
				body := []byte("{}")
				if outcome == "response-overflow" {
					body = []byte("123456789")
				}
				_, _ = w.Write(body)
			})
			wrap := func(storage *Store) http.Handler {
				handler, err := server.NewHandler(server.HandlerConfig{Verifier: actualVerifier(t, storage, state, &now), ServerKey: serverKey, MaxResponseBytes: 8}, next)
				if err != nil {
					t.Fatal(err)
				}
				return handler
			}
			invoke := func(handler http.Handler, target string) *httptest.ResponseRecorder {
				t.Helper()
				r := httptest.NewRequest(http.MethodGet, target, nil)
				for _, value := range request.AuthValues {
					r.Header.Add("Jack-Auth", value)
				}
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, r)
				return response
			}
			handler := wrap(owner)
			bad := invoke(handler, "/tampered")
			if bad.Code != http.StatusUnauthorized || calls != 0 || owner.meta.Live != 0 {
				t.Fatal("HTTP pre-auth refusal consumed nonce or dispatched")
			}
			var response *httptest.ResponseRecorder
			var recovered any
			func() {
				defer func() { recovered = recover() }()
				response = invoke(handler, "/mcp")
			}()
			if outcome == "handler-panic" {
				if recovered != "public handler panic" {
					t.Fatalf("handler panic changed: %v", recovered)
				}
			} else {
				if recovered != nil {
					t.Fatalf("unexpected HTTP panic: %v", recovered)
				}
				want := map[string]int{"success": 200, "handler-error": 500, "response-overflow": 502, "streaming-refusal": 501}[outcome]
				if response.Code != want {
					t.Fatalf("HTTP outcome=%d want=%d", response.Code, want)
				}
				if err := client.VerifyResponse(serverKey.Public().(ed25519.PublicKey), response.Code, response.Header().Values("Jack-Auth"), auth.Sig, response.Body.Bytes(), time.Unix(now, 0), 30*time.Second); err != nil {
					t.Fatal("actual HTTP response was not correctly signed:", err)
				}
			}
			if calls != 1 || owner.meta.Live != 1 || owner.meta.Intents != 0 {
				t.Fatal("post-reservation HTTP outcome undid or duplicated admission")
			}
			// Close дренирует настоящую request lease, включая panic/error branches.
			if err := owner.Close(); err != nil {
				t.Fatal(err)
			}
			now = 101
			reopened, err := Open(path, opts)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			replay := invoke(wrap(reopened), "/mcp")
			if replay.Code != http.StatusUnauthorized || calls != 1 || !bytes.Contains(replay.Body.Bytes(), []byte(jack.CodeReplayedNonce)) || len(replay.Header().Values("Jack-Auth")) != 0 {
				t.Fatalf("restart redelivered HTTP operation: status=%d calls=%d", replay.Code, calls)
			}
		})
	}
}
