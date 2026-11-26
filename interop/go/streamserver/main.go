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
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/durable"
	"github.com/PHPCraftdream/mcp-jack/rotation"
	"github.com/PHPCraftdream/mcp-jack/server"
	rotationserver "github.com/PHPCraftdream/mcp-jack/server/rotation"
)

type fixedClock struct{ path string }

type ringSigner struct {
	priv ed25519.PrivateKey
}

func (s ringSigner) PublicKey() []byte {
	return append([]byte(nil), s.priv.Public().(ed25519.PublicKey)...)
}

func (s ringSigner) Sign(message []byte) ([]byte, error) {
	return ed25519.Sign(s.priv, message), nil
}

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

func scenarioMeta(id string) (scenarioRow, bool) {
	b, err := os.ReadFile("interop/stream-scenarios.json")
	if err != nil {
		return scenarioRow{}, false
	}
	var doc struct {
		Matrices struct {
			Stream         []scenarioRow `json:"stream"`
			Staged         []scenarioRow `json:"staged"`
			RotationStream []scenarioRow `json:"rotation-stream"`
			DurableStream  []scenarioRow `json:"durable-stream"`
		} `json:"matrices"`
	}
	if json.Unmarshal(b, &doc) != nil {
		return scenarioRow{}, false
	}
	for _, pool := range [][]scenarioRow{doc.Matrices.Stream, doc.Matrices.Staged, doc.Matrices.RotationStream, doc.Matrices.DurableStream} {
		for _, row := range pool {
			if row.ID == id {
				return row, true
			}
		}
	}
	return scenarioRow{}, false
}

func scenarioProducer(id string) string {
	row, ok := scenarioMeta(id)
	if ok {
		return row.Producer
	}
	return ""
}

type control struct {
	Action     string `json:"action"`
	Op         string `json:"op"`
	Reference  string `json:"reference"`
	Kid        string `json:"kid"`
	Clock      int64  `json:"clock"`
	Start      int64  `json:"start"`
	DurationMS int64  `json:"duration_ms"`
}

type releaseState struct {
	mu      sync.Mutex
	sid     string
	ack     string
	release chan control
}
type releaseContextKey struct{}

type streamOpenWriter struct {
	http.ResponseWriter
	log          *auditLog
	request      *http.Request
	scenario     string
	serverKID    string
	heartbeat    int64
	commitLogged bool
	committed    bool
	nonce        string
	sig          string
	status       int
	body         bytes.Buffer
	release      *releaseState
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
			w.commitLogged = true
			w.log.put(map[string]any{"event": "nonce_committed", "nonce": w.nonce, "request_sig": w.sig, "nonce_committed_before_first_byte": true})
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
	ringSeed := flag.String("ring-seed", "", "")
	successorActivation := flag.Int64("successor-activation", 0, "")
	rotationStore := flag.String("rotation-store", "", "")
	durableDir := flag.String("durable-dir", "", "")
	durableInit := flag.Bool("durable-init", false, "")
	seedHex := flag.Lookup("server-seed-hex")
	flag.Parse()
	if *durableInit {
		if *durableDir == "" {
			fmt.Fprintln(os.Stderr, "--durable-init requires --durable-dir")
			os.Exit(1)
		}
		if err := durable.InitializeUnused(filepath.Join(*durableDir, "committed-nonces.db"), durable.Options{DeploymentID: "mcp-jack-stream-interop", Window: 30, Now: fixedClock{*clockPath}.Now}); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(`{"durable_initialized":true}`)
		os.Exit(0)
	}
	producer := scenarioProducer(*scenario)
	// Lifecycle rows declare producer progress-final; dispatch them by scenario id.
	switch *scenario {
	case "idle", "rotation-cutoff-reopen", "durable-live-replay", "durable-restart-replay":
		producer = *scenario
	}
	if producer == "" {
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
	var provider *rotationserver.Provider
	var rotStore *durable.ServerStore
	erinKid := ""
	if *ringSeed != "" && *rotationStore != "" {
		rest, ok := strings.CutPrefix(*ringSeed, "ring-1=")
		if !ok {
			fail(fmt.Errorf("invalid --ring-seed"))
		}
		erinSeed, err := hex.DecodeString(rest)
		if err != nil || len(erinSeed) != ed25519.SeedSize {
			fail(fmt.Errorf("invalid --ring-seed"))
		}
		svcPub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
		svcKid := jack.KeyID(svcPub)
		var anchorPub [32]byte
		copy(anchorPub[:], svcPub)
		rotationOpts := durable.TrustOptions{Binding: rotation.Binding{Endpoint: "http://127.0.0.1/mcp", Audience: *aud}, Window: 30, Checkpoint: rotation.Checkpoint{Ordinal: 0, Hash: "-", KID: svcKid, PublicKey: anchorPub, PublishedAt: 0}, Now: clock.Now}
		serverOpts := durable.ServerOptions{TrustOptions: rotationOpts, AnchorReference: "ring-0"}
		if _, err := os.Stat(*rotationStore); os.IsNotExist(err) {
			if err := durable.InitializeServerUnused(*rotationStore, serverOpts); err != nil {
				fail(err)
			}
		} else if err != nil {
			fail(err)
		}
		rotStore, err = durable.OpenServer(*rotationStore, serverOpts)
		if err != nil {
			fail(err)
		}
		erinKey := ed25519.NewKeyFromSeed(erinSeed)
		erinKid = jack.KeyID(erinKey.Public().(ed25519.PublicKey))
		provider, err = rotationserver.New(rotStore, []rotationserver.Key{{Reference: "ring-0", Signer: ringSigner{priv: ed25519.NewKeyFromSeed(seed)}}, {Reference: "ring-1", Signer: ringSigner{priv: erinKey}}})
		if err != nil {
			fail(err)
		}
	}
	var durableStore *durable.Store
	if *durableDir != "" {
		store, err := durable.Open(filepath.Join(*durableDir, "committed-nonces.db"), durable.Options{DeploymentID: "mcp-jack-stream-interop", Window: 30, Now: clock.Now})
		if err != nil {
			fail(err)
		}
		durableStore = store
	}
	verifierConfig := server.Config{Aud: *aud, State: state, Now: clock.Now}
	if provider != nil {
		verifierConfig.ServerKeys = provider
	}
	if durableStore != nil {
		verifierConfig.DurableNonces = durableStore
	} else {
		verifierConfig.Nonces = server.NewNonceStore()
	}
	verifier, err := server.NewVerifier(verifierConfig)
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
			if json.Unmarshal(sc.Bytes(), &c) != nil {
				continue
			}
			if c.Op == "announce" {
				if provider == nil || c.Reference != "ring-1" || c.Kid != erinKid {
					fmt.Fprintf(os.Stderr, "invalid rotation announce command\n")
					continue
				}
				publication, err := provider.Announce(c.Reference, c.Kid)
				if err != nil {
					fmt.Println(`{"announced":false,"reason":"rotation_state_unavailable"}`)
					continue
				}
				record := publication.Record
				log.put(map[string]any{"event": "rotation_announced", "reference": c.Reference, "kid": erinKid, "published_at": record.PublishedAt, "activates_at": record.ActivatesAt, "head_hash": record.Hash})
				fmt.Println(mustJSON(map[string]any{"announced": true, "ordinal": record.Ordinal, "head_ordinal": record.Ordinal, "published_at": record.PublishedAt, "activates_at": record.ActivatesAt, "head_hash": record.Hash}))
				continue
			}
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
		case "concurrency-limit":
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
					release.ack = release.sid
					release.mu.Unlock()
				}
			}
		case "durable-live-replay":
			emit(map[string]any{"jsonrpc": "2.0", "method": "notifications/progress", "params": map[string]any{"progress": 1, "message": "stream:first"}})
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
					release.ack = release.sid
					release.mu.Unlock()
				}
			}
		case "durable-restart-replay":
			emit(map[string]any{"jsonrpc": "2.0", "method": "notifications/progress", "params": map[string]any{"progress": 1, "message": "stream:first"}})
			emit(final)
		case "rotation-cutoff-reopen":
			hold := *successorActivation > 0 && clock.Now() < *successorActivation && release != nil
			emit(progress)
			emit(final)
			if hold {
				select {
				case <-r.Context().Done():
					return
				case _, open := <-release.release:
					if !open {
						return
					}
					release.mu.Lock()
					release.ack = release.sid
					release.mu.Unlock()
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
	var handlerConfig = server.HandlerConfig{Verifier: verifier, ServerKey: ed25519.NewKeyFromSeed(seed), Profile: server.Profile(*profile), Streams: &opts, TimerNow: func() time.Time { return time.Unix(clock.Now(), 0) }}
	if provider != nil {
		handlerConfig.ServerKey = nil
		handlerConfig.ResponseKeys = provider
	}
	handler, err := server.NewHandler(handlerConfig, app)
	if err != nil {
		fail(err)
	}
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		release := &releaseState{release: releaseControls}
		ctx := context.WithValue(r.Context(), releaseContextKey{}, release)
		auth, _ := jack.ParseRequestAuth(r.Header.Values("Jack-Auth"))
		outer := &streamOpenWriter{ResponseWriter: w, log: log, request: r, scenario: producer, serverKID: serverKID, heartbeat: opts.Heartbeat.Milliseconds(), release: release, nonce: auth.Nonce, sig: auth.Sig}
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
		if !outer.commitLogged && (outer.status == http.StatusOK || outer.status == http.StatusTooManyRequests || outer.status == http.StatusNotImplemented || outer.status == http.StatusBadGateway) && outer.nonce != "" {
			log.put(map[string]any{"event": "nonce_committed", "nonce": outer.nonce, "request_sig": outer.sig, "nonce_committed_before_first_byte": true})
		}
		// Printed after the handler returned; the SDK exposes no later completion hook.
		release.mu.Lock()
		ack := release.ack
		release.mu.Unlock()
		if ack != "" {
			fmt.Fprintln(os.Stdout, mustJSON(map[string]any{"control": "released", "sid": ack}))
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
	if rotStore != nil {
		_ = rotStore.Close()
	}
	if durableStore != nil {
		_ = durableStore.Close()
	}
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
