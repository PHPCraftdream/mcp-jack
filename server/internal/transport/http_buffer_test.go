package transport

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
	nonceimpl "github.com/PHPCraftdream/mcp-jack/server/internal/nonce"
	verify "github.com/PHPCraftdream/mcp-jack/server/internal/verify"
	"github.com/PHPCraftdream/mcp-jack/spec"
)

func TestMiddlewareRefusesStreams(t *testing.T) {
	h := newHarness(t, 0, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: x\n\n"))
	})
	req, sig := signedRequest(t, testPrivateKey(t, "alice"), "GET", "/mcp", nil)
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotImplemented || errorCode(t, rec) != "streaming_unsupported" {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
	assertSigned(t, rec, h.server, sig)
}

func TestMiddlewareRefusesLiveStream(t *testing.T) {
	p := newStreamProbe(t, "write", "text/event-stream")
	h := newHarness(t, 0, p.handle)
	req, sig := signedRequest(t, testPrivateKey(t, "alice"), "GET", "/mcp", nil)
	rec := serveBounded(t, h.handler, req, p)

	if rec.Code != http.StatusNotImplemented || errorCode(t, rec) != "streaming_unsupported" {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
	assertSigned(t, rec, h.server, sig)
	if strings.Contains(rec.Body.String(), "hello") {
		t.Fatalf("stream bytes leaked into the answer: %s", rec.Body.String())
	}
	if !errors.Is(p.writeErr, errStreamRefused) {
		t.Fatalf("write error = %v, want errStreamRefused", p.writeErr)
	}
	if p.firstWriteOK {
		t.Fatal("the first write succeeded on a refused stream")
	}
	if p.endedBy != "" {
		t.Fatalf("handler ended by %q, want a straight return from the write error", p.endedBy)
	}
	if p.ctxErrAtReturn == nil {
		t.Fatal("the request context of the wrapped handler was not cancelled")
	}
}

func TestMiddlewareCancelsStreamContextAfterHeaderCommit(t *testing.T) {
	p := newStreamProbe(t, "writeheader", "text/event-stream")
	h := newHarness(t, 0, p.handle)
	req, sig := signedRequest(t, testPrivateKey(t, "alice"), "GET", "/mcp", nil)
	rec := serveBounded(t, h.handler, req, p)

	if rec.Code != http.StatusNotImplemented || errorCode(t, rec) != "streaming_unsupported" {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
	assertSigned(t, rec, h.server, sig)
	if p.endedBy != "context" {
		t.Fatalf("handler ended by %q, want context cancellation", p.endedBy)
	}
	if p.ctxErrAtReturn == nil {
		t.Fatal("the request context of the wrapped handler was not cancelled")
	}
}

func TestMiddlewareRefusesLiveStreamWithFlusher(t *testing.T) {
	// On a writer without Flush this fails fast with flusherMissing.
	p := newStreamProbe(t, "flush", "text/event-stream")
	h := newHarness(t, 0, p.handle)
	req, sig := signedRequest(t, testPrivateKey(t, "alice"), "GET", "/mcp", nil)
	rec := serveBounded(t, h.handler, req, p)

	if p.flusherMissing.Load() {
		t.Fatal("the wrapped handler did not get an http.Flusher")
	}
	if rec.Code != http.StatusNotImplemented || errorCode(t, rec) != "streaming_unsupported" {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
	assertSigned(t, rec, h.server, sig)
	if strings.Contains(rec.Body.String(), "hello") {
		t.Fatalf("stream bytes leaked into the answer: %s", rec.Body.String())
	}
	// Write is the first commit, so it fails before the handler flushes.
	if !errors.Is(p.writeErr, errStreamRefused) {
		t.Fatalf("write error = %v, want errStreamRefused", p.writeErr)
	}
}

func TestMiddlewareCancelsStreamContextAfterFlushCommit(t *testing.T) {
	// On a writer without Flush this fails fast with flusherMissing.
	p := newStreamProbe(t, "flushonly", "text/event-stream")
	h := newHarness(t, 0, p.handle)
	req, sig := signedRequest(t, testPrivateKey(t, "alice"), "GET", "/mcp", nil)
	rec := serveBounded(t, h.handler, req, p)

	if p.flusherMissing.Load() {
		t.Fatal("the wrapped handler did not get an http.Flusher")
	}
	if rec.Code != http.StatusNotImplemented || errorCode(t, rec) != "streaming_unsupported" {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
	assertSigned(t, rec, h.server, sig)
	if p.endedBy != "context" {
		t.Fatalf("handler ended by %q, want context cancellation", p.endedBy)
	}
}

func TestMiddlewareRefusalIsBoundToOriginalRequestSignature(t *testing.T) {
	p := newStreamProbe(t, "write", "text/event-stream")
	h := newHarness(t, 0, p.handle)
	req, sig := signedRequest(t, testPrivateKey(t, "alice"), "GET", "/mcp", nil)
	rec := serveBounded(t, h.handler, req, p)

	foreign := "A" + sig
	auth, err := jack.ParseResponseAuth(rec.Header().Values("Jack-Auth"))
	if err != nil {
		t.Fatalf("response Jack-Auth: %v", err)
	}
	sigBytes, err := jack.DecodeBase64URLFixed(auth.Sig, 64)
	if err != nil {
		t.Fatalf("response sig: %v", err)
	}
	signing := jack.ResponseSigningString(rec.Code, foreign, auth.Kid, auth.TS, rec.Body.Bytes())
	if jack.Verify(h.server.Public().(ed25519.PublicKey), []byte(signing), sigBytes) {
		t.Fatal("the answer verifies against a foreign request signature")
	}
	assertSigned(t, rec, h.server, sig)
}

func TestMiddlewareRefusesLiveStreamContentTypeVariants(t *testing.T) {
	for _, ct := range []string{
		"Text/Event-Stream",
		"TEXT/EVENT-STREAM; charset=utf-8",
		"  text/event-stream  ;x",
		`text/event-stream; charset="`,
		"text/event-stream;;;=",
	} {
		t.Run(ct, func(t *testing.T) {
			p := newStreamProbe(t, "write", ct)
			h := newHarness(t, 0, p.handle)
			req, sig := signedRequest(t, testPrivateKey(t, "alice"), "GET", "/mcp", nil)
			rec := serveBounded(t, h.handler, req, p)
			if rec.Code != http.StatusNotImplemented || errorCode(t, rec) != "streaming_unsupported" {
				t.Fatalf("got %d %s", rec.Code, rec.Body.String())
			}
			assertSigned(t, rec, h.server, sig)
			if p.firstWriteOK {
				t.Fatal("a write succeeded on a refused stream")
			}
		})
	}
}

func TestMiddlewareRefusesLateEventStreamContentType(t *testing.T) {
	cases := []struct {
		name string
		run  func(w http.ResponseWriter)
	}{
		{"after write and flush", func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"a":1}`))
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			w.Header().Set("Content-Type", "text/event-stream")
		}},
		{"after WriteHeader, mixed case and malformed", func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Header().Set("Content-Type", `Text/Event-Stream; charset="`)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, 0, func(w http.ResponseWriter, r *http.Request) { c.run(w) })
			req, sig := signedRequest(t, testPrivateKey(t, "alice"), "GET", "/mcp", nil)
			rec := httptest.NewRecorder()
			h.handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusNotImplemented || errorCode(t, rec) != "streaming_unsupported" {
				t.Fatalf("got %d %s", rec.Code, rec.Body.String())
			}
			assertSigned(t, rec, h.server, sig)
			if strings.Contains(rec.Body.String(), `{"a":1}`) {
				t.Fatalf("handler bytes leaked into the answer: %s", rec.Body.String())
			}
		})
	}
}

func TestMiddlewareRefusesStreamWithoutWrite(t *testing.T) {
	h := newHarness(t, 0, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
	})
	req, sig := signedRequest(t, testPrivateKey(t, "alice"), "GET", "/mcp", nil)
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotImplemented || errorCode(t, rec) != "streaming_unsupported" {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
	assertSigned(t, rec, h.server, sig)
}

func TestMiddlewareKeepsOrdinaryResponseWithFlush(t *testing.T) {
	h := newHarness(t, 0, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Custom", "yes")
		w.Header().Set("Content-Length", "999")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"a":`))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		_, _ = w.Write([]byte(`1}`))
	})
	req, sig := signedRequest(t, testPrivateKey(t, "alice"), "POST", "/mcp", toolCallBody("svc.status"))
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated || rec.Body.String() != `{"a":1}` {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("X-Custom") != "yes" || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("headers = %v", rec.Header())
	}
	if rec.Header().Get("Content-Length") != strconv.Itoa(rec.Body.Len()) {
		t.Fatalf("Content-Length = %q for a %d byte body", rec.Header().Get("Content-Length"), rec.Body.Len())
	}
	assertSigned(t, rec, h.server, sig)
}

func TestMiddlewareSignsUpstreamFailure(t *testing.T) {
	h := newHarness(t, 0, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	})
	req, sig := signedRequest(t, testPrivateKey(t, "alice"), "POST", "/mcp", toolCallBody("svc.status"))
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError || rec.Body.String() != "boom" {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
	assertSigned(t, rec, h.server, sig)
}

func TestBufferedWriterRefusesEventStream(t *testing.T) {
	for _, ct := range []string{
		"text/event-stream", "Text/Event-Stream", "TEXT/EVENT-STREAM; charset=utf-8",
		"  text/event-stream  ;x", `text/event-stream; charset="`, "text/event-stream;;;=",
	} {
		for _, via := range []string{"write", "writeheader", "flush"} {
			t.Run(via+"/"+ct, func(t *testing.T) {
				var cancels int
				bw := &bufferedWriter{limit: defaultMaxResponseBytes, header: http.Header{}, cancel: func() { cancels++ }}
				bw.Header().Set("Content-Type", ct)
				switch via {
				case "write":
					n, err := bw.Write([]byte("data: x\n\n"))
					if n != 0 || !errors.Is(err, errStreamRefused) {
						t.Fatalf("Write = %d, %v", n, err)
					}
				case "writeheader":
					bw.WriteHeader(http.StatusOK)
				case "flush":
					bw.Flush()
				}
				if !bw.refused || cancels != 1 {
					t.Fatalf("refused = %v, cancels = %d", bw.refused, cancels)
				}
				for i := 0; i < 3; i++ {
					n, err := bw.Write([]byte("more"))
					if n != 0 || !errors.Is(err, errStreamRefused) {
						t.Fatalf("later Write = %d, %v", n, err)
					}
					bw.WriteHeader(http.StatusTeapot)
					bw.Flush()
				}
				if bw.body.Len() != 0 {
					t.Fatalf("%d stream bytes retained", bw.body.Len())
				}
				if cancels != 1 {
					t.Fatalf("cancel called %d times, want 1", cancels)
				}
			})
		}
	}
}

func TestBufferedWriterKeepsOrdinaryResponses(t *testing.T) {
	for _, ct := range []string{"text/event-streams", "application/json; x=text/event-stream", "", "application/json"} {
		t.Run(ct, func(t *testing.T) {
			var cancels int
			bw := &bufferedWriter{limit: defaultMaxResponseBytes, header: http.Header{}, cancel: func() { cancels++ }}
			if ct != "" {
				bw.Header().Set("Content-Type", ct)
			}
			bw.WriteHeader(http.StatusAccepted)
			bw.WriteHeader(http.StatusTeapot)
			if n, err := bw.Write([]byte("abc")); n != 3 || err != nil {
				t.Fatalf("Write = %d, %v", n, err)
			}
			bw.Flush()
			if bw.refused || cancels != 0 || bw.status != http.StatusAccepted || bw.body.String() != "abc" {
				t.Fatalf("refused=%v cancels=%d status=%d body=%q", bw.refused, cancels, bw.status, bw.body.String())
			}
		})
	}
}

func TestBufferedWriterImplicitStatusAndFlush(t *testing.T) {
	bw := &bufferedWriter{limit: defaultMaxResponseBytes, header: http.Header{}}
	_, _ = bw.Write([]byte("x"))
	bw.WriteHeader(http.StatusTeapot)
	if bw.status != http.StatusOK {
		t.Fatalf("status = %d, want implicit 200", bw.status)
	}
	fl := &bufferedWriter{limit: defaultMaxResponseBytes, header: http.Header{}}
	fl.Flush()
	if !fl.committed || fl.status != http.StatusOK {
		t.Fatalf("Flush: committed=%v status=%d", fl.committed, fl.status)
	}
	var _ http.Flusher = fl
	// The writer cannot observe a header change after the commit, so it does
	// not refuse here; forward checks the final header when the handler
	// returns (TestMiddlewareRefusesLateEventStreamContentType).
	fl.Header().Set("Content-Type", "text/event-stream")
	if _, err := fl.Write([]byte("x")); err != nil || fl.refused {
		t.Fatalf("the writer refused after a post-commit header change: %v", err)
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
	v, err := verify.NewVerifier(verify.Config{
		Aud: "https://svc.example.test", State: registryFromFixture(t, registry), Nonces: nonceimpl.NewNonceStore(),
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
