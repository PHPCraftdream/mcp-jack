package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/server"
)

type fixedClock struct{ path string }

func (c fixedClock) Now() int64 {
	b, err := os.ReadFile(c.path)
	if err != nil {
		return 0
	}
	n, _ := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	return n
}

type auditLog struct {
	mu   sync.Mutex
	file *os.File
}

func (l *auditLog) put(row map[string]any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, _ := json.Marshal(row)
	_, _ = l.file.Write(append(b, '\n'))
	_ = l.file.Sync()
}

type rpcRequest struct {
	JSONRPC string         `json:"jsonrpc"`
	ID      any            `json:"id"`
	Method  string         `json:"method"`
	Params  map[string]any `json:"params"`
}
type scenarioRow struct {
	ID       string `json:"id"`
	Producer string `json:"producer"`
}

func scenarioProducer(id string) string {
	b, err := os.ReadFile("interop/stream-scenarios.json")
	if err != nil {
		return ""
	}
	var doc struct {
		Matrices struct {
			Stream []scenarioRow `json:"stream"`
			Staged []scenarioRow `json:"staged"`
		} `json:"matrices"`
	}
	if json.Unmarshal(b, &doc) != nil {
		return ""
	}
	for _, pool := range [][]scenarioRow{doc.Matrices.Stream, doc.Matrices.Staged} {
		for _, row := range pool {
			if row.ID == id && row.Producer != "" {
				return row.Producer
			}
		}
	}
	return ""
}

type control struct {
	Action     string `json:"action"`
	Clock      int64  `json:"clock"`
	Start      int64  `json:"start"`
	DurationMS int64  `json:"duration_ms"`
}

type releaseState struct {
	mu      sync.Mutex
	sid     string
	release chan control
}
type releaseContextKey struct{}

type streamOpenWriter struct {
	http.ResponseWriter
	log       *auditLog
	request   *http.Request
	scenario  string
	serverKID string
	heartbeat int64
	committed bool
	status    int
	body      bytes.Buffer
	release   *releaseState
}

func (w *streamOpenWriter) WriteHeader(status int) {
	if !w.committed {
		w.committed = true
		w.status = status
		if status == http.StatusOK && strings.HasPrefix(strings.ToLower(w.Header().Get("Content-Type")), "text/event-stream") {
			requestAuth, _ := jack.ParseRequestAuth([]string{w.request.Header.Get("Jack-Auth")})
			openParts := strings.Split(w.Header().Get("Jack-Auth"), ",")
			var sid any
			serverKID := w.serverKID
			if len(openParts) == 4 && strings.HasPrefix(openParts[0], "s1 kid=") {
				serverKID = strings.TrimPrefix(openParts[0], "s1 kid=")
				sid = strings.TrimPrefix(openParts[2], "sid=")
				if w.release != nil {
					w.release.mu.Lock()
					w.release.sid = sid.(string)
					w.release.mu.Unlock()
				}
			}
			w.log.put(map[string]any{"event": "stream_open", "sid": sid, "request_sig": requestAuth.Sig, "identity": requestAuth.Kid, "server_kid": serverKID, "nonce_committed_before_first_byte": true})
			if w.scenario == "events-stream" {
				w.log.put(map[string]any{"event": "heartbeat_granted", "request_sig": requestAuth.Sig, "heartbeat_granted_ms": w.heartbeat})
			}
		}
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *streamOpenWriter) Write(p []byte) (int, error) {
	if !w.committed {
		w.WriteHeader(http.StatusOK)
	}
	if w.status == http.StatusUnauthorized {
		_, _ = w.body.Write(p)
	}
	return w.ResponseWriter.Write(p)
}

func (w *streamOpenWriter) Flush() {
	if !w.committed {
		w.WriteHeader(http.StatusOK)
	}
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *streamOpenWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func main() {
	profile := flag.String("profile", "modern", "")
	matrix := flag.String("matrix", "stream", "")
	scenario := flag.String("scenario", "", "")
	aud := flag.String("aud", "", "")
	statePath := flag.String("state", "", "")
	_ = flag.String("server-seed-hex", "", "")
	clockPath := flag.String("clock-file", "", "")
	logPath := flag.String("request-log", "", "")
	port := flag.Int("port", 0, "")
	frame := flag.Int64("frame-max-bytes", 0, "")
	concurrent := flag.Int("max-concurrent-streams", 0, "")
	duration := flag.Int64("max-stream-duration-ms", 0, "")
	heartbeat := flag.Int64("heartbeat-ms", 0, "")
	_ = flag.Int64("idle-timeout-ms", 0, "")
	_ = flag.String("ring-seed", "", "")
	_ = flag.String("successor-activation", "", "")
	_ = flag.String("rotation-store", "", "")
	_ = flag.String("durable-dir", "", "")
	seedHex := flag.Lookup("server-seed-hex")
	flag.Parse()
	producer := scenarioProducer(*scenario)
	if *scenario == "idle" || producer == "" {
		producer = *scenario
	}
	fail := func(err error) { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
	seed, err := hex.DecodeString(seedHex.Value.String())
	if err != nil || len(seed) != ed25519.SeedSize {
		fail(fmt.Errorf("invalid --server-seed-hex"))
	}
	clock := fixedClock{*clockPath}
	state, err := server.OpenFileState(*statePath)
	if err != nil {
		fail(err)
	}
	verifier, err := server.NewVerifier(server.Config{Aud: *aud, State: state, Nonces: server.NewNonceStore(), Now: clock.Now})
	if err != nil {
		fail(err)
	}
	lf, err := os.OpenFile(*logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		fail(err)
	}
	defer lf.Close()
	log := &auditLog{file: lf}
	opts := server.StreamOptions{}
	if *frame > 0 {
		opts.FrameMaxBytes = *frame
	}
	if *concurrent > 0 {
		opts.MaxConcurrentStreams = *concurrent
	}
	if *duration > 0 {
		opts.MaxStreamDuration = time.Duration(*duration) * time.Millisecond
	}
	if *heartbeat > 0 {
		opts.Heartbeat = time.Duration(*heartbeat) * time.Millisecond
	}
	opts = opts.Normalize(30 * time.Second)
	controls := make(chan control, 4)
	releaseControls := make(chan control, 1)
	scannerDone := make(chan struct{})
	go func() {
		defer close(scannerDone)
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			var c control
			if json.Unmarshal(sc.Bytes(), &c) == nil {
				if c.Action == "release" {
					select {
					case releaseControls <- c:
					default:
					}
				} else {
					select {
					case controls <- c:
					default:
					}
				}
			}
		}
		close(controls)
		close(releaseControls)
	}()
	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var in rpcRequest
		_ = json.Unmarshal(body, &in)
		authText := r.Header.Get("Jack-Auth")
		auth, _ := jack.ParseRequestAuth([]string{authText})
		sig := auth.Sig
		protocolVersion := ""
		if meta, ok := in.Params["_meta"].(map[string]any); ok {
			protocolVersion, _ = meta["io.modelcontextprotocol/protocolVersion"].(string)
		}
		row := map[string]any{"scenario": *scenario, "matrix": *matrix, "request_verified": true, "request_sig": sig, "nonce": auth.Nonce, "request_method": r.Method, "method": r.Method, "request_target": r.URL.RequestURI(), "target": r.URL.RequestURI(), "body": string(body), "request_body_b64u": jack.EncodeBase64URL(body), "request_headers": requestHeaderEvidence(r), "request_mcp_method": in.Method, "request_params": in.Params, "protocol_version": protocolVersion, "mirror_headers": mirrorHeaderEvidence(r), "mirror_protocol_version": r.Header.Get("Mcp-Protocol-Version"), "mirror_method": r.Header.Get("Mcp-Method"), "mirror_name": nullable(r.Header.Get("Mcp-Name")), "nonce_committed_before_first_byte": false}
		for name, value := range r.Header {
			if strings.HasPrefix(strings.ToLower(name), "mcp-param-") {
				key := strings.ToLower(strings.TrimPrefix(strings.ToLower(name), "mcp-param-"))
				row["mirror_param_"+key] = strings.Join(value, ",")
			}
		}
		log.put(row)
		log.put(map[string]any{"event": "nonce_committed", "request_sig": sig, "nonce": auth.Nonce, "nonce_committed_before_first_byte": true})
		if r.Header.Get("Jack-Accept") == "" {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "data: refusal\n\n")
			return
		}
		grant, ok := server.StreamFromContext(r.Context())
		if !ok {
			return
		}
		release, _ := r.Context().Value(releaseContextKey{}).(*releaseState)
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)
		emit := func(m any) bool {
			b, e := json.Marshal(m)
			if e != nil {
				return false
			}
			_, e = fmt.Fprintf(w, "data: %s\n\n", b)
			if flusher != nil {
				flusher.Flush()
			}
			if e == nil && producer == "events-stream" {
				if msg, ok := m.(map[string]any); ok && msg["method"] == "notifications/events/heartbeat" {
					log.put(map[string]any{"event": "heartbeat_frame", "request_sig": sig, "heartbeat_granted_ms": grant.Heartbeat.Milliseconds(), "ts": clock.Now()})
				}
			}
			return e == nil
		}
		progress := map[string]any{"jsonrpc": "2.0", "method": "notifications/progress", "params": map[string]any{"progress": 1}}
		final := map[string]any{"jsonrpc": "2.0", "id": in.ID, "result": map[string]any{}}
		switch producer {
		case "concurrency-limit", "durable-live-replay", "durable-restart-replay":
			emit(progress)
			if release != nil {
				select {
				case <-r.Context().Done():
					return
				case _, open := <-release.release:
					if !open {
						return
					}
					emit(final)
					release.mu.Lock()
					sid := release.sid
					release.mu.Unlock()
					fmt.Fprintln(os.Stdout, mustJSON(map[string]any{"control": "released", "sid": sid}))
				}
			}
		case "progress-final", "relay-drop", "relay-edit-data", "relay-truncate", "relay-reorder", "relay-splice", "relay-replay":
			emit(progress)
			emit(final)
		case "idle":
			if flusher != nil {
				flusher.Flush()
			}
			<-r.Context().Done()
			return
		case "oversize":
			oversized := map[string]any{"jsonrpc": "2.0", "method": "notifications/progress", "params": map[string]any{"payload": strings.Repeat("x", int(opts.FrameMaxBytes)+32)}}
			raw, _ := json.Marshal(oversized)
			log.put(map[string]any{"event": "frame_suppressed", "data_bytes": len(raw), "frame_max_bytes": opts.FrameMaxBytes})
			emit(oversized)
		case "cancel":
			emit(progress)
			<-r.Context().Done()
			log.put(map[string]any{"event": "handler_cancelled", "handler_cancelled": true, "request_sig": sig})
			return
		case "max-duration":
			emit(progress)
			ctxDone := r.Context().Done()
			clockObserved, contextCancelled := false, false
			var advanced control
			for !clockObserved || !contextCancelled {
				select {
				case <-ctxDone:
					contextCancelled = true
					ctxDone = nil
				case c, open := <-controls:
					if !open {
						return
					}
					if c.Action != "clock_advanced" || c.Clock != clock.Now() {
						continue
					}
					clockObserved = true
					advanced = c
					log.put(map[string]any{"event": "clock_changed", "clock": clock.Now(), "start": c.Start, "duration_ms": c.DurationMS, "request_sig": sig})
					fmt.Fprintln(os.Stdout, mustJSON(map[string]any{"control": "clock_advanced", "clock": c.Clock}))
				}
			}
			log.put(map[string]any{"event": "duration_elapsed", "start": advanced.Start, "duration_ms": advanced.DurationMS, "clock": clock.Now(), "request_sig": sig})
		case "list-changed", "subscriptions-listen":
			emit(map[string]any{"jsonrpc": "2.0", "method": "notifications/subscriptions/acknowledged", "params": map[string]any{"subscriptionId": 3}})
			if hasListChangedNotification(in.Params) {
				emit(map[string]any{"jsonrpc": "2.0", "method": "notifications/events/list_changed", "params": map[string]any{}})
			}
			emit(final)
		case "events-stream":
			emit(map[string]any{"jsonrpc": "2.0", "method": "notifications/events/active", "params": map[string]any{"state": "active"}})
			emit(map[string]any{"jsonrpc": "2.0", "method": "notifications/events/event", "params": map[string]any{"event": "event"}})
			emit(map[string]any{"jsonrpc": "2.0", "method": "notifications/events/heartbeat", "params": map[string]any{"event": "heartbeat", "heartbeatMs": grant.Heartbeat.Milliseconds()}})
			emit(map[string]any{"jsonrpc": "2.0", "method": "notifications/events/terminated", "params": map[string]any{"state": "terminated"}})
		}
	})
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	serverKID := jack.KeyID(pub)
	handler, err := server.NewHandler(server.HandlerConfig{Verifier: verifier, ServerKey: ed25519.NewKeyFromSeed(seed), Profile: server.Profile(*profile), Streams: &opts, TimerNow: func() time.Time { return time.Unix(clock.Now(), 0) }}, app)
	if err != nil {
		fail(err)
	}
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state := &releaseState{release: releaseControls}
		ctx := context.WithValue(r.Context(), releaseContextKey{}, state)
		outer := &streamOpenWriter{ResponseWriter: w, log: log, request: r, scenario: producer, serverKID: serverKID, heartbeat: opts.Heartbeat.Milliseconds(), release: state}
		handler.ServeHTTP(outer, r.WithContext(ctx))
		if outer.status == http.StatusUnauthorized {
			var refusal struct {
				Error struct {
					Code string `json:"code"`
				} `json:"error"`
			}
			if json.Unmarshal(outer.body.Bytes(), &refusal) == nil && refusal.Error.Code == "replayed_nonce" {
				auth, _ := jack.ParseRequestAuth(r.Header.Values("Jack-Auth"))
				log.put(map[string]any{"event": "replayed_nonce", "request_sig": auth.Sig, "nonce": auth.Nonce})
			}
		}
	})
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", *port))
	if err != nil {
		fail(err)
	}
	ready := map[string]any{"ready": true, "port": ln.Addr().(*net.TCPAddr).Port, "server_public_key": jack.EncodeBase64URL(pub), "server_kid": jack.KeyID(pub)}
	fmt.Println(mustJSON(ready))
	srv := &http.Server{Handler: wrapped, ReadHeaderTimeout: 10 * time.Second}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()
	select {
	case <-scannerDone:
	case e := <-serveErr:
		if e != nil && !errors.Is(e, http.ErrServerClosed) {
			fail(e)
		}
	}
	_ = srv.Close()
	<-scannerDone
}
func hasListChangedNotification(params map[string]any) bool {
	items, ok := params["notifications"].([]any)
	if !ok {
		return false
	}
	for _, item := range items {
		switch notification := item.(type) {
		case string:
			if notification == "notifications/events/list_changed" {
				return true
			}
		case map[string]any:
			if notification["method"] == "notifications/events/list_changed" {
				return true
			}
		}
	}
	return false
}

func requestHeaderEvidence(r *http.Request) [][2]string {
	out := [][2]string{{"content-type", r.Header.Get("Content-Type")}, {"content-length", strconv.FormatInt(r.ContentLength, 10)}, {"Jack-Auth", r.Header.Get("Jack-Auth")}}
	for _, n := range []string{"Mcp-Protocol-Version", "Mcp-Method", "Mcp-Name", "Jack-Accept"} {
		if v := r.Header.Get(n); v != "" {
			out = append(out, [2]string{n, v})
		}
	}
	return out
}
func mirrorHeaderEvidence(r *http.Request) [][2]string {
	out := [][2]string{}
	for name, values := range r.Header {
		lower := strings.ToLower(name)
		if lower == "mcp-protocol-version" || lower == "mcp-method" || lower == "mcp-name" || strings.HasPrefix(lower, "mcp-param-") {
			for _, value := range values {
				out = append(out, [2]string{lower, value})
			}
		}
	}
	return out
}
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}
func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
