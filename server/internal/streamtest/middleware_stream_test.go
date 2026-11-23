package streamtest

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PHPCraftdream/mcp-jack/server/internal/modern"
	"github.com/PHPCraftdream/mcp-jack/server/internal/testfixture"
	"github.com/PHPCraftdream/mcp-jack/server/internal/transport"
)

// TestStreamDurationCloseWritesFinalResponse covers spec 05 3.4 and 6.3: the
// duration close writes the final response of the opening request and then
// the end frame.
func TestStreamDurationCloseWritesFinalResponse(t *testing.T) {
	var once sync.Once
	handlerDone := make(chan struct{})
	sse := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		once.Do(func() {
			_, _ = w.Write([]byte(progressFrame))
			<-r.Context().Done()
			close(handlerDone)
		})
	})
	h, clk := newHarness(t, modern.ProfileModern, &transport.StreamOptions{MaxStreamDuration: 20 * time.Millisecond}, sse)
	req, sig := signedPost(t, clk, testfixture.PrivateKey(t, "alice"), "/mcp", modernStreamBody(7), 50, "s1")
	modernMirrors(req, "email.received")
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.handler.ServeHTTP(rec, req)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the middleware did not return after the stream duration")
	}
	select {
	case <-handlerDone:
	case <-time.After(10 * time.Second):
		t.Fatal("the handler was not cancelled by the duration close")
	}

	frames := parseFrames(t, rec.Body.Bytes())
	if len(frames) != 3 {
		t.Fatalf("frames = %+v, want progress, final response and end", frames)
	}
	if frames[0].event != "message" || frames[0].data != progressEvent {
		t.Fatalf("frame 0 = %+v, want the progress notification", frames[0])
	}
	if frames[1].event != "message" || frames[1].data != finalEvent {
		t.Fatalf("frame 1 = %+v, want the final response %s", frames[1], finalEvent)
	}
	if frames[2].event != "jack-end" {
		t.Fatalf("frame 2 = %+v, want jack-end", frames[2])
	}

	result := verifyStream(t, rec, clk, sig, h.server.Public().(ed25519.PublicKey), 0)
	if !result.Complete {
		t.Fatal("the end frame was not verified")
	}
	if len(result.Messages) != 2 || result.Messages[0] != progressEvent || result.Messages[1] != finalEvent {
		t.Fatalf("messages = %q, want [progress, final]", result.Messages)
	}
	// mcp_complete: the last verified message is the JSON-RPC response of the
	// opening request id 7.
	mcpComplete := false
	last := result.Messages[len(result.Messages)-1]
	var msg struct {
		JSONRPC string           `json:"jsonrpc"`
		ID      json.RawMessage  `json:"id"`
		Method  *json.RawMessage `json:"method"`
		Result  *json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal([]byte(last), &msg); err == nil && msg.JSONRPC == "2.0" &&
		msg.Method == nil && msg.Result != nil && string(msg.ID) == "7" {
		mcpComplete = true
	}
	if !mcpComplete {
		t.Fatalf("last message %q is not the final response of id 7", last)
	}
}

// TestStreamHandlerCanceledOnClientDisconnect covers spec 05 3.7: the handler
// context ends when the client disconnects.
func TestStreamHandlerCanceledOnClientDisconnect(t *testing.T) {
	handlerDone := make(chan struct{})
	h, clk := newHarness(t, modern.ProfileModern, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(progressFrame))
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		<-r.Context().Done()
		close(handlerDone)
	}))
	srv := httptest.NewServer(h.handler)

	// signedPost signs the origin-form target the server verifies; the client
	// request is a fresh one so its wire fields are a normal client request.
	signed, _ := signedPost(t, clk, testfixture.PrivateKey(t, "alice"), "/mcp", modernStreamBody(11), 40, "s1")
	modernMirrors(signed, "email.received")
	req, err := http.NewRequest("POST", srv.URL+"/mcp", bytes.NewReader(modernStreamBody(11)))
	if err != nil {
		srv.Close()
		t.Fatalf("build client request: %v", err)
	}
	req.Header = signed.Header.Clone()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		srv.Close()
		t.Fatalf("send signed POST: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		srv.Close()
		t.Fatalf("status = %d, want the open stream", resp.StatusCode)
	}
	one := make([]byte, 1)
	if _, err := io.ReadFull(resp.Body, one); err != nil {
		_ = resp.Body.Close()
		srv.Close()
		t.Fatalf("read stream bytes: %v", err)
	}
	_ = resp.Body.Close()

	select {
	case <-handlerDone:
	case <-time.After(10 * time.Second):
		srv.Close()
		<-handlerDone
		t.Fatal("the handler context did not end when the client disconnected")
	}
	srv.Close()
}

// responseKeysFunc adapts a function to the ResponseKeyProvider interface.
type responseKeysFunc func(transport.ResponseKeyRequest) (transport.ResponseKeyAuthorization, error)

func (f responseKeysFunc) AuthorizeResponse(req transport.ResponseKeyRequest) (transport.ResponseKeyAuthorization, error) {
	return f(req)
}

// fixedSigner is a ResponseSigner over one fixed private key.
type fixedSigner struct {
	key ed25519.PrivateKey
}

func (s fixedSigner) PublicKey() []byte {
	return append([]byte(nil), s.key.Public().(ed25519.PublicKey)...)
}

func (s fixedSigner) Sign(message []byte) ([]byte, error) {
	return ed25519.Sign(s.key, message), nil
}

// TestStreamRotationCutoffEndsBeforeActivation covers spec 05 5.1: once the
// clock reaches the guard before the successor activation no further frame is
// legal, so the stream closes strictly before the activation. Every frame ts
// is below the activation, the end frame is last and still legal, and the
// provider lease is released only after the end frame is already on the wire.
func TestStreamRotationCutoffEndsBeforeActivation(t *testing.T) {
	const activation = int64(2010)
	var released atomic.Bool
	var releasedAt int
	var rec *httptest.ResponseRecorder
	var secondErr error
	var secondTried bool
	var clk *clock
	provider := responseKeysFunc(func(transport.ResponseKeyRequest) (transport.ResponseKeyAuthorization, error) {
		return transport.ResponseKeyAuthorization{
			Signer:    fixedSigner{key: testfixture.PrivateKey(t, "svc")},
			Timestamp: 2000,
			Cutoff:    ptr(activation),
			Final:     func() error { return nil },
			Release: func() {
				// finish releases the lease only after the end frame; the body
				// length of that moment must be the final one.
				releasedAt = rec.Body.Len()
				released.Store(true)
			},
		}, nil
	})
	// The handler needs the harness clock, which newResponseKeysHarness
	// returns; the handler is only called after the pointer is assigned.
	h, clockRef := newResponseKeysHarness(t, modern.ProfileModern, provider, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		if _, err := w.Write([]byte(progressFrame)); err != nil {
			return
		}
		// One second before the successor activation: inside the guard, so no
		// further frame may be signed.
		clk.Set(activation - 1)
		secondTried = true
		_, secondErr = w.Write([]byte(progressFrame))
	}))
	clk = clockRef
	clk.Set(2000)
	req, _ := signedPost(t, clk, testfixture.PrivateKey(t, "alice"), "/mcp", modernStreamBody(13), 60, "s1")
	modernMirrors(req, "email.received")
	rec = httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	if !secondTried {
		t.Fatal("the handler did not attempt the second write inside the guard")
	}
	if secondErr == nil {
		t.Fatal("the second write inside the guard succeeded")
	}
	frames := parseFrames(t, rec.Body.Bytes())
	if len(frames) < 2 {
		t.Fatalf("frames = %+v, want at least the message and the end frame", frames)
	}
	end := frames[len(frames)-1]
	if end.event != "jack-end" {
		t.Fatalf("frames do not end with jack-end: %+v", frames)
	}
	for _, frame := range frames {
		if frame.ts >= activation {
			t.Fatalf("frame %+v carries ts %d at or past the successor activation %d", frame, frame.ts, activation)
		}
	}
	if end.ts < 2000 {
		t.Fatalf("end frame ts = %d, want at least the open ts 2000", end.ts)
	}
	if !released.Load() {
		t.Fatal("the provider lease was never released")
	}
	if releasedAt != len(rec.Body.Bytes()) {
		t.Fatalf("lease released after %d body bytes, want the final %d: the end frame was not yet on the wire", releasedAt, len(rec.Body.Bytes()))
	}
	if !bytes.Contains(rec.Body.Bytes()[:releasedAt], []byte("event: jack-end")) {
		t.Fatalf("body at release carried no end frame: %q", rec.Body.String())
	}
}

// ptr returns a pointer to v.
func ptr(v int64) *int64 { return &v }
