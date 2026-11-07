package server

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/spec"
)

const overflowBody = `{"error":{"code":"response_too_large","message":"upstream response exceeds the configured limit"}}`

// newCapHarness is newHarness with a configurable response cap.
func newCapHarness(t *testing.T, maxBody, maxResp int64, wrap func(w http.ResponseWriter, r *http.Request)) *harness {
	t.Helper()
	registry, err := spec.LoadRegistry()
	if err != nil {
		t.Fatalf("LoadRegistry: %v", err)
	}
	h := &harness{next: new(atomic.Int32), seen: new([]byte), audit: NewMemoryAuditSink(), native: &fakeNative{}, server: testPrivateKey(t, "svc")}
	v, err := NewVerifier(Config{
		Aud: "https://svc.example.test", State: registryFromFixture(t, registry), Nonces: NewNonceStore(),
		Policy: loadTestPolicy(t, "policy.json"), Audit: h.audit, Native: h.native,
		Now: func() int64 { return testNow },
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.next.Add(1)
		body := new(bytes.Buffer)
		_, _ = body.ReadFrom(r.Body)
		*h.seen = body.Bytes()
		wrap(w, r)
	})
	h.handler, err = NewHandler(HandlerConfig{Verifier: v, ServerKey: h.server, MaxBodyBytes: maxBody, MaxResponseBytes: maxResp}, next)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	return h
}

// serveGet sends one signed GET through h and returns the recorder and the
// request signature.
func serveGet(t *testing.T, h *harness) (*httptest.ResponseRecorder, string) {
	t.Helper()
	req, sig := signedRequest(t, testPrivateKey(t, "alice"), "GET", "/mcp", nil)
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	return rec, sig
}

func signatureVerifies(t *testing.T, rec *httptest.ResponseRecorder, server ed25519.PrivateKey, requestSig string) bool {
	t.Helper()
	auth, err := jack.ParseResponseAuth(rec.Header().Values("Jack-Auth"))
	if err != nil {
		t.Fatalf("response Jack-Auth: %v", err)
	}
	sig, err := jack.DecodeBase64URLFixed(auth.Sig, 64)
	if err != nil {
		t.Fatalf("response sig: %v", err)
	}
	signing := jack.ResponseSigningString(rec.Code, requestSig, auth.Kid, auth.TS, rec.Body.Bytes())
	return jack.Verify(server.Public().(ed25519.PublicKey), []byte(signing), sig)
}

// chunked returns a handler that sets upstream headers and writes chunks of
// the given sizes, filled with 'a'.
func chunked(sizes ...int) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Upstream", "yes")
		w.Header().Add("Set-Cookie", "session=secret")
		w.WriteHeader(http.StatusCreated)
		for _, n := range sizes {
			if _, err := w.Write(bytes.Repeat([]byte("a"), n)); err != nil {
				return
			}
		}
	}
}

func assertPassed(t *testing.T, rec *httptest.ResponseRecorder, sig string, h *harness, size int) {
	t.Helper()
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", rec.Code)
	}
	if rec.Body.String() != strings.Repeat("a", size) {
		t.Fatalf("body length %d, want exactly %d bytes", rec.Body.Len(), size)
	}
	if rec.Header().Get("Content-Type") != "text/plain" || rec.Header().Get("X-Upstream") != "yes" || rec.Header().Get("Set-Cookie") != "session=secret" {
		t.Fatalf("upstream headers were not preserved: %v", rec.Header())
	}
	assertSigned(t, rec, h.server, sig)
}

func assertOverflow(t *testing.T, rec *httptest.ResponseRecorder, sig string, h *harness) {
	t.Helper()
	if rec.Code != http.StatusBadGateway || errorCode(t, rec) != "response_too_large" {
		t.Fatalf("got %d (%d body bytes), want 502 response_too_large", rec.Code, rec.Body.Len())
	}
	if rec.Body.String() != overflowBody {
		t.Fatalf("body = %s", rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q", got)
	}
	for _, name := range []string{"X-Upstream", "Set-Cookie"} {
		if rec.Header().Get(name) != "" {
			t.Fatalf("upstream header %s leaked", name)
		}
	}
	if strings.Contains(rec.Body.String(), "aaaa") {
		t.Fatal("partial upstream body leaked")
	}
	assertSigned(t, rec, h.server, sig)
}

func TestResponseCapSingleWriteBoundary(t *testing.T) {
	for _, tc := range []struct {
		name  string
		cfg   int64
		limit int
	}{
		{"configured 8", 8, 8},
		{"default 1 MiB", 0, 1 << 20},
	} {
		for _, d := range []struct {
			delta    int
			overflow bool
		}{{-1, false}, {0, false}, {1, true}} {
			size := tc.limit + d.delta
			t.Run(tc.name+"/"+"size="+strconv.Itoa(size), func(t *testing.T) {
				h := newCapHarness(t, 0, tc.cfg, chunked(size))
				rec, sig := serveGet(t, h)
				if d.overflow {
					assertOverflow(t, rec, sig, h)
				} else {
					assertPassed(t, rec, sig, h, size)
				}
			})
		}
	}
}

func TestResponseCapMultiWriteBoundary(t *testing.T) {
	cases := []struct {
		name     string
		sizes    []int
		total    int
		overflow bool
	}{
		{"two chunks to the cap", []int{4, 4}, 8, false},
		{"one below the cap", []int{4, 3}, 7, false},
		{"last chunk crosses", []int{3, 3, 3}, 0, true},
		{"one extra byte at the end", []int{4, 4, 1}, 0, true},
		{"first chunk fills, second crosses", []int{8, 1}, 0, true},
		{"single bytes", []int{1, 1, 1, 1, 1, 1, 1, 1, 1}, 0, true},
		{"empty writes between", []int{4, 0, 4, 0}, 8, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newCapHarness(t, 0, 8, chunked(c.sizes...))
			rec, sig := serveGet(t, h)
			if c.overflow {
				assertOverflow(t, rec, sig, h)
			} else {
				assertPassed(t, rec, sig, h, c.total)
			}
		})
	}
}

func TestResponseCapOverflowIsBoundToOriginalRequestSignature(t *testing.T) {
	h := newCapHarness(t, 0, 8, chunked(9))
	rec, sig := serveGet(t, h)
	assertOverflow(t, rec, sig, h)
	if signatureVerifies(t, rec, h.server, "A"+sig) {
		t.Fatal("the answer verifies against a different request signature")
	}
	if !signatureVerifies(t, rec, h.server, sig) {
		t.Fatal("the answer does not verify against the original request signature")
	}
}

func TestResponseCapCancelsContextAndFailsLaterWrites(t *testing.T) {
	var (
		firstN        int
		firstErr      error
		ctxDoneAfter  bool
		laterErrs     []error
		laterAccepted int
	)
	h := newCapHarness(t, 0, 8, func(w http.ResponseWriter, r *http.Request) {
		firstN, firstErr = w.Write(bytes.Repeat([]byte("a"), 9))
		select {
		case <-r.Context().Done():
			ctxDoneAfter = true
		default:
		}
		for i := 0; i < 3; i++ {
			n, err := w.Write([]byte("b"))
			laterAccepted += n
			laterErrs = append(laterErrs, err)
		}
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	})
	rec, sig := serveGet(t, h)
	assertOverflow(t, rec, sig, h)
	if firstN != 0 || !errors.Is(firstErr, errResponseTooLarge) {
		t.Fatalf("overflowing write = %d, %v; want 0, errResponseTooLarge", firstN, firstErr)
	}
	if !ctxDoneAfter {
		t.Fatal("the request context was not cancelled by the overflow")
	}
	if len(laterErrs) != 3 || laterAccepted != 0 {
		t.Fatalf("later writes accepted %d bytes over %d calls", laterAccepted, len(laterErrs))
	}
	for _, err := range laterErrs {
		if !errors.Is(err, errResponseTooLarge) {
			t.Fatalf("later write error = %v", err)
		}
	}
}

func TestBufferedWriterReleasesBufferOnOverflow(t *testing.T) {
	cancels := 0
	bw := &bufferedWriter{limit: 8, header: http.Header{}, cancel: func() { cancels++ }}
	if n, err := bw.Write([]byte("abcde")); n != 5 || err != nil {
		t.Fatalf("write within the limit = %d, %v", n, err)
	}
	n, err := bw.Write([]byte("fghi"))
	if n != 0 || !errors.Is(err, errResponseTooLarge) {
		t.Fatalf("overflowing write = %d, %v", n, err)
	}
	if bw.body.Len() != 0 || bw.body.Cap() != 0 {
		t.Fatalf("buffer retained: len %d cap %d", bw.body.Len(), bw.body.Cap())
	}
	if !bw.overflowed || cancels != 1 {
		t.Fatalf("overflowed = %v, cancels = %d", bw.overflowed, cancels)
	}
	for i := 0; i < 5; i++ {
		if n, err := bw.Write([]byte("x")); n != 0 || !errors.Is(err, errResponseTooLarge) {
			t.Fatalf("later write = %d, %v", n, err)
		}
		if bw.body.Len() != 0 {
			t.Fatal("a later write accumulated")
		}
	}
	bw.Flush()
	if cancels != 1 {
		t.Fatalf("cancels = %d, want the overflow cancel only", cancels)
	}
}

func TestBufferedWriterLimitArithmeticDoesNotOverflow(t *testing.T) {
	bw := &bufferedWriter{limit: 1<<63 - 1, header: http.Header{}}
	if n, err := bw.Write([]byte("abc")); n != 3 || err != nil {
		t.Fatalf("write = %d, %v", n, err)
	}
	if bw.overflowed {
		t.Fatal("a huge limit overflowed")
	}
}

func TestNewHandlerRejectsNegativeMaxResponseBytes(t *testing.T) {
	registry, err := spec.LoadRegistry()
	if err != nil {
		t.Fatalf("LoadRegistry: %v", err)
	}
	v, err := NewVerifier(Config{
		Aud: "https://svc.example.test", State: registryFromFixture(t, registry), Nonces: NewNonceStore(),
		Policy: loadTestPolicy(t, "policy.json"), Audit: NewMemoryAuditSink(), Native: &fakeNative{},
		Now: func() int64 { return testNow },
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	h, err := NewHandler(HandlerConfig{Verifier: v, ServerKey: testPrivateKey(t, "svc"), MaxResponseBytes: -1}, http.HandlerFunc(okHandler))
	if err == nil || h != nil {
		t.Fatalf("NewHandler = %v, %v; want an error", h, err)
	}
}

func TestResponseCapIsIndependentOfRequestCap(t *testing.T) {
	t.Run("small request cap does not limit the response", func(t *testing.T) {
		h := newCapHarness(t, 64, 0, chunked(100000))
		rec, sig := serveGet(t, h)
		assertPassed(t, rec, sig, h, 100000)
	})
	t.Run("small response cap does not limit the request", func(t *testing.T) {
		big := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping","params":{"pad":"` + strings.Repeat("x", 200) + `"}}`)
		h := newCapHarness(t, 4096, 8, chunked(8))
		req, sig := signedRequest(t, testPrivateKey(t, "alice"), "POST", "/mcp", big)
		rec := httptest.NewRecorder()
		h.handler.ServeHTTP(rec, req)
		if !bytes.Equal(*h.seen, big) {
			t.Fatalf("the wrapped handler saw %d request bytes, want %d", len(*h.seen), len(big))
		}
		assertPassed(t, rec, sig, h, 8)
	})
	t.Run("request cap still applies", func(t *testing.T) {
		big := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping","params":{"pad":"` + strings.Repeat("x", 200) + `"}}`)
		h := newCapHarness(t, 64, 1<<30, chunked(1))
		req, _ := signedRequest(t, testPrivateKey(t, "alice"), "POST", "/mcp", big)
		rec := httptest.NewRecorder()
		h.handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusRequestEntityTooLarge || h.next.Load() != 0 {
			t.Fatalf("status = %d, next calls %d", rec.Code, h.next.Load())
		}
	})
}

func assertStreamRefusal(t *testing.T, rec *httptest.ResponseRecorder, sig string, h *harness) {
	t.Helper()
	if rec.Code != http.StatusNotImplemented || errorCode(t, rec) != "streaming_unsupported" {
		t.Fatalf("got %d %s, want the signed 501", rec.Code, rec.Body.String())
	}
	assertSigned(t, rec, h.server, sig)
}

func TestResponseCapEventStreamRefusalWins(t *testing.T) {
	big := bytes.Repeat([]byte("d"), 100)
	cases := []struct {
		name string
		run  func(w http.ResponseWriter)
	}{
		{"header commit with oversized write", func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write(big)
		}},
		{"late final header after overflow", func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("abc"))
			_, _ = w.Write(big)
			w.Header().Set("Content-Type", "text/event-stream")
		}},
		{"late final header before overflow", func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("abc"))
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write(big)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newCapHarness(t, 0, 8, func(w http.ResponseWriter, r *http.Request) { c.run(w) })
			rec, sig := serveGet(t, h)
			assertStreamRefusal(t, rec, sig, h)
		})
	}
}

func TestResponseCapEventStreamRefusalStillCancelsContext(t *testing.T) {
	var ctxDone bool
	h := newCapHarness(t, 0, 8, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write(bytes.Repeat([]byte("d"), 100))
		select {
		case <-r.Context().Done():
			ctxDone = true
		default:
		}
	})
	rec, sig := serveGet(t, h)
	assertStreamRefusal(t, rec, sig, h)
	if !ctxDone {
		t.Fatal("the context was not cancelled on stream refusal")
	}
}

func TestResponseCapOrdinaryControls(t *testing.T) {
	t.Run("okHandler under a small cap on an exact fit", func(t *testing.T) {
		const want = `{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`
		h := newCapHarness(t, 0, int64(len(want)), okHandler)
		rec, sig := serveGet(t, h)
		if rec.Code != http.StatusOK || rec.Body.String() != want {
			t.Fatalf("got %d %s", rec.Code, rec.Body.String())
		}
		assertSigned(t, rec, h.server, sig)
	})
	t.Run("empty response", func(t *testing.T) {
		h := newCapHarness(t, 0, 8, func(w http.ResponseWriter, r *http.Request) {})
		rec, sig := serveGet(t, h)
		if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
			t.Fatalf("got %d %q", rec.Code, rec.Body.String())
		}
		assertSigned(t, rec, h.server, sig)
	})
}
