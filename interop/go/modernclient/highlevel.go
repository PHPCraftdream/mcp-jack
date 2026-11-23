package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/PHPCraftdream/mcp-jack/client"
)

// nativeEraShape drives the native jack.whoami call through the high-level
// client with the era option (contract 4.1). A protocol-native jack.* tool
// skips the tools/list fetch and the projection (client/tools.go), so the
// pinned single request is exactly what client.CallTool sends and the SDK's
// own era handling signs and verifies it. The recorder stays the base round
// tripper, so the executable only observes the exchange. It is used only for
// the default --json-id, because client.CallTool mints its own ids from 1.
func (c *clientState) nativeEraShape() error {
	era, stepEra := client.EraModern, eraModern
	if c.era == eraLegacy {
		era, stepEra = client.EraLegacy, eraLegacy
	}
	cl, err := client.NewClient(client.Config{
		BaseURL:   c.endpoint,
		Aud:       c.aud,
		Signer:    c.signer,
		ServerKey: c.anchor,
		HTTP:      &http.Client{Transport: c.recorder},
		Now:       func() time.Time { return time.Unix(c.clock.Now(), 0) },
		Nonce:     c.nextNonce,
		Era:       era,
	})
	if err != nil {
		return fmt.Errorf("native-era-shape client: %w", err)
	}
	callErr := cl.CallTool(context.Background(), "jack.whoami", map[string]any{}, nil)
	return c.finishHighLevel("whoami", stepEra, callErr)
}

// finishHighLevel reports the one exchange the high-level call made and
// classifies the SDK's error. A decode error after a verified answer (for
// example a result without structuredContent) cannot change the wire
// verdict, which is what the result line reports (contract 4.2).
func (c *clientState) finishHighLevel(stepName, era string, callErr error) error {
	sent := c.recorder.take()
	if sent == nil {
		// The high-level path serves single-request rows only, so there is
		// never an earlier answer to fall back on: a failure before any
		// answer is a startup failure (contract 4.2).
		return fmt.Errorf("high-level call %s recorded no exchange: %w", stepName, callErr)
	}
	c.steps = append(c.steps, c.stepFromExchange(stepName, sent))
	c.lastEra = era
	if callErr == nil {
		return nil
	}
	code, verification := judgeResponse(callErr, sent.status, sent.body)
	if verification && code == "" {
		// The spec 01 section 5 unsigned-allowed 401 family: a refusal the
		// client may act on, so the recorded step decides the result line.
		return nil
	}
	if !verification {
		// The SDK raised this before it verified the answer (a 200
		// text/event-stream, an unreadable body, a decode error): the run
		// must never report "ok" for it.
		fmt.Fprintf(os.Stderr, "modern-client: %s: %v\n", stepName, callErr)
	}
	c.stop(code, "client_error")
	return errStopScenario
}
