package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
)

// delayedClock returns fixtureNow on its first call (consumed by RotateKey)
// and fixtureNow+3600 on every later call (a response arriving "later").
func delayedClock() func() time.Time {
	var mu sync.Mutex
	calls := 0
	return func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if calls == 1 {
			return time.Unix(fixtureNow, 0)
		}
		return time.Unix(fixtureNow+3600, 0)
	}
}

// rotateFreshnessRun performs RotateKey against a server answering with
// response ts respTS and asserts the proof/header ts binding.
func rotateFreshnessRun(t *testing.T, respTS int64) (KidResult, error) {
	t.Helper()
	c := adminCase(t, "rotate-ok")
	if len(c.Steps) == 0 {
		t.Fatalf("case rotate-ok has no steps")
	}
	step := c.Steps[0]

	srv := newTestServer(t)
	srv.Now = respTS
	var mu sync.Mutex
	var gotAuth jack.RequestAuth
	var gotBody []byte
	srv.Handle = func(w http.ResponseWriter, auth jack.RequestAuth, body []byte) {
		mu.Lock()
		gotAuth = auth
		gotBody = body
		mu.Unlock()
		srv.writeSignedJSON(w, auth, http.StatusOK, rpcResultBody(step.Expect.Structured))
	}

	alice := seedSignerByName(t, "alice")
	newbie := seedSignerByName(t, "newbie")
	nonce := fixtureNonce(t, fixtureHeaderValue(t, step.Request, "Jack-Auth"))

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	u.Path = "/mcp"
	client, err := NewClient(Config{
		BaseURL:   u.String(),
		Aud:       fixtureAud,
		Signer:    alice,
		ServerKey: srv.Pub,
		Now:       delayedClock(),
		Window:    30 * time.Second,
		Nonce:     queuedNonce(t, nonce),
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	res, rotErr := client.RotateKey(context.Background(), newbie)

	mu.Lock()
	auth, body := gotAuth, gotBody
	mu.Unlock()
	if auth.TS != fixtureNow {
		t.Errorf("header ts = %d, want %d", auth.TS, fixtureNow)
	}
	var req jsonrpcRequest
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("captured body does not decode: %v", err)
	}
	var args map[string]any
	if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
		t.Fatalf("arguments do not decode: %v", err)
	}
	proof, ok := args["proof"].(string)
	if !ok {
		t.Fatalf("arguments[proof] = %v, want a string", args["proof"])
	}
	proofBytes, err := jack.DecodeBase64URLFixed(proof, 64)
	if err != nil {
		t.Fatalf("DecodeBase64URLFixed(proof): %v", err)
	}
	msg := []byte(jack.RotateProofString(fixtureAud, alice.KID(), newbie.KID(), fixtureNow))
	if !jack.Verify(newbie.PublicKey(), msg, proofBytes) {
		t.Errorf("rotate proof ts differs from header ts %d", fixtureNow)
	}
	return res, rotErr
}

func TestRotateKeyRefusesDelayedStaleResponse(t *testing.T) {
	res, err := rotateFreshnessRun(t, fixtureNow)
	if err == nil {
		t.Fatalf("RotateKey accepted a stale response, result %+v", res)
	}
	var jErr *jack.Error
	if !errors.As(err, &jErr) || jErr.Code != jack.CodeTimestampOutOfWindow {
		t.Fatalf("err = %v, want *jack.Error with code %v", err, jack.CodeTimestampOutOfWindow)
	}
	if res != (KidResult{}) {
		t.Errorf("result = %+v, want zero KidResult", res)
	}
}

func TestRotateKeyAcceptsFreshLaterResponse(t *testing.T) {
	res, err := rotateFreshnessRun(t, fixtureNow+3600)
	if err != nil {
		t.Fatalf("RotateKey refused a fresh response: %v", err)
	}
	if res.KID != "imZX4AkHSrS_UT1wZ5oEPklelGqIooKk4TfK3ht5LYg" {
		t.Errorf("KidResult.KID = %q, want imZX4AkHSrS_UT1wZ5oEPklelGqIooKk4TfK3ht5LYg", res.KID)
	}
}
