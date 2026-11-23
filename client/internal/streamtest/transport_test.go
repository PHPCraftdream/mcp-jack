// Transport-level tests of spec 05 sections 1.1 and 1.2: RoundTrip never
// opts into a stream and refuses one, OpenStream opts in exactly once.
package streamtest

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/PHPCraftdream/mcp-jack/client"
)

// headerRecorder is the bottom round tripper of the transports built in this
// file. It records the Jack-Accept values and the Jack-Auth values of every
// request exactly as net/http hands it to the server, because the handler of
// live_test.go records only Jack-Accept and may not be edited. It is safe for
// concurrent use.
type headerRecorder struct {
	next http.RoundTripper

	mu     sync.Mutex
	accept []string
	auth   []string
}

// RoundTrip records the unsigned opt-in and the signed auth header of req,
// then sends it.
func (r *headerRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.accept = append(r.accept, req.Header.Values("Jack-Accept")...)
	r.auth = append(r.auth, req.Header.Values("Jack-Auth")...)
	r.mu.Unlock()
	return r.next.RoundTrip(req)
}

// Values returns a copy of the recorded Jack-Accept values in arrival order;
// a request without the header contributes nothing.
func (r *headerRecorder) Values() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.accept...)
}

// AuthValues returns a copy of the recorded Jack-Auth values in arrival order.
func (r *headerRecorder) AuthValues() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.auth...)
}

// TestRoundTripSendsNoAcceptHeaderAndRefusesStreams verifies 1.1 and 1.2 at
// the transport level: a plain RoundTrip sends no Jack-Accept header, still
// signs the request, and refuses the text/event-stream answer rather than
// reading it.
func TestRoundTripSendsNoAcceptHeaderAndRefusesStreams(t *testing.T) {
	signer, priv := newTestSigner(t)
	served := &servedBody{}
	srv, _, _ := newStreamServer(t, served.get, false)
	defer srv.Close()
	recorder := &headerRecorder{next: http.DefaultTransport}

	req, err := http.NewRequest("POST", srv.URL+"/mcp", bytes.NewReader([]byte(testRequestBody)))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	requestSig := requestSignature(signer, priv, req)
	value, openSig := openHeader(priv, signer.KID(), requestSig)
	openAuth = value
	message, msgSig := messageFrame(priv, openSig, testMessage, testMessage)
	served.set([]byte(message + endFrame(priv, msgSig)))

	tr := newTestTransport(signer)
	tr.Base = recorder
	resp, err := tr.RoundTrip(req)
	if !errors.Is(err, client.ErrStreamingUnsupported) {
		t.Fatalf("RoundTrip on a stream answer = %v, want %v", err, client.ErrStreamingUnsupported)
	}
	if resp != nil {
		t.Fatalf("RoundTrip returned a non-nil response %v with the refusal", resp)
	}
	if got := recorder.Values(); len(got) != 0 {
		t.Fatalf("Jack-Accept values = %v, want none", got)
	}
	if got := recorder.AuthValues(); len(got) != 1 || got[0] == "" {
		t.Fatalf("Jack-Auth values = %v, want exactly one non-empty value", got)
	}
}

// TestOpenStreamSendsTheAcceptHeader verifies 1.1: OpenStream opts in with
// exactly one `Jack-Accept: s1` header, drains the verified stream to io.EOF
// and closes it.
func TestOpenStreamSendsTheAcceptHeader(t *testing.T) {
	signer, priv := newTestSigner(t)
	served := &servedBody{}
	srv, _, _ := newStreamServer(t, served.get, false)
	defer srv.Close()
	recorder := &headerRecorder{next: http.DefaultTransport}

	req, err := http.NewRequest("POST", srv.URL+"/mcp", bytes.NewReader([]byte(testRequestBody)))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	requestSig := requestSignature(signer, priv, req)
	value, openSig := openHeader(priv, signer.KID(), requestSig)
	openAuth = value
	message, msgSig := messageFrame(priv, openSig, testMessage, testMessage)
	served.set([]byte(message + endFrame(priv, msgSig)))

	tr := newTestTransport(signer)
	tr.Base = recorder
	s, verified, err := tr.OpenStream(req)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	if verified != nil {
		t.Fatalf("OpenStream verified response = %+v, want nil", verified)
	}
	drained := make(chan error, 1)
	go func() {
		for {
			if _, err := s.Next(); err != nil {
				drained <- err
				return
			}
		}
	}()
	var nextErr error
	select {
	case nextErr = <-drained:
	case <-time.After(guard):
		_ = s.Close()
		t.Fatalf("draining the stream did not finish within %s", guard)
	}
	if nextErr != io.EOF {
		t.Fatalf("draining Next ended with %v, want io.EOF", nextErr)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := recorder.Values(); len(got) != 1 || got[0] != "s1" {
		t.Fatalf("Jack-Accept values = %v, want [s1]", got)
	}
}
