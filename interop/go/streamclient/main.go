package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/client"
	clientstream "github.com/PHPCraftdream/mcp-jack/client/stream"
)

type capture struct {
	mu             sync.Mutex
	method, target string
	body           []byte
	headers        [][2]string
	status         int
	responseHeader http.Header
	responseBody   bytes.Buffer
	mirrors        [][2]string
}
type recorder struct {
	base http.RoundTripper
	c    *capture
}
type teeBody struct {
	io.ReadCloser
	c *capture
}

func (b *teeBody) Read(p []byte) (int, error) {
	n, e := b.ReadCloser.Read(p)
	if n > 0 {
		b.c.mu.Lock()
		_, _ = b.c.responseBody.Write(p[:n])
		b.c.mu.Unlock()
	}
	return n, e
}
func (r recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	raw, _ := io.ReadAll(req.Body)
	_ = req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(raw))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(raw)), nil
	}
	r.c.mu.Lock()
	r.c.method = req.Method
	r.c.target = req.URL.RequestURI()
	r.c.body = append([]byte(nil), raw...)
	r.c.headers = requestHeaders(req, r.c.mirrors)
	r.c.mu.Unlock()
	resp, e := r.base.RoundTrip(req)
	if e == nil {
		r.c.mu.Lock()
		r.c.status = resp.StatusCode
		r.c.responseHeader = resp.Header.Clone()
		r.c.mu.Unlock()
		resp.Body = &teeBody{ReadCloser: resp.Body, c: r.c}
	}
	return resp, e
}
func requestHeaders(req *http.Request, mirrors [][2]string) [][2]string {
	out := [][2]string{}
	names := []string{"Content-Type", "Content-Length", "Jack-Auth"}
	for _, n := range names {
		v := req.Header.Get(n)
		if n == "Content-Length" {
			v = strconv.FormatInt(req.ContentLength, 10)
		}
		if v != "" {
			out = append(out, [2]string{n, v})
		}
	}
	for _, pair := range mirrors {
		out = append(out, pair)
	}
	if v := req.Header.Get("Jack-Accept"); v != "" {
		out = append(out, [2]string{"Jack-Accept", v})
	}
	return out
}

type frame struct {
	Kind string `json:"kind"`
	SID  string `json:"sid"`
	KID  string `json:"kid"`
	Seq  int64  `json:"seq"`
	TS   int64  `json:"ts"`
	Data string `json:"data"`
	Sig  string `json:"sig"`
}
type openEvidence struct {
	SID string `json:"sid"`
	KID string `json:"kid"`
	TS  int64  `json:"ts"`
	Sig string `json:"sig"`
}

func main() {
	profile := flag.String("profile", "modern", "")
	_ = flag.String("matrix", "stream", "")
	scenario := flag.String("scenario", "", "")
	endpoint := flag.String("url", "", "")
	aud := flag.String("aud", "", "")
	clockPath := flag.String("clock-file", "", "")
	pubText := flag.String("server-public-key", "", "")
	seedText := flag.String("seed-hex", "", "")
	requestLog := flag.String("request-log", "", "")
	nonceText := flag.String("nonce", "", "")
	_ = flag.String("sid", "", "")
	bodyText := flag.String("request-body-json", "", "")
	accept := flag.String("jack-accept", "s1", "")
	_ = flag.String("modern-version", "2026-07-28", "")
	mirrorsText := flag.String("mirror-headers-json", "[]", "")
	action := flag.String("action", "once", "")
	frameMax := flag.Int("frame-max-bytes", 0, "")
	idle := flag.Int("idle-timeout-ms", 0, "")
	_ = flag.Int("max-concurrent-streams", 0, "")
	_ = flag.Int64("max-stream-duration-ms", 0, "")
	_ = flag.Int64("heartbeat-ms", 0, "")
	_ = flag.String("successor-activation", "", "")
	_ = flag.String("rotation-store", "", "")
	_ = flag.String("durable-dir", "", "")
	flag.Parse()
	fail := func(err error) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	seed, err := base64.RawURLEncoding.DecodeString(*nonceText)
	if err != nil || len(seed) != 16 {
		fail(fmt.Errorf("invalid nonce"))
	}
	keySeed, err := hexDecode(*seedText)
	if err != nil {
		fail(err)
	}
	signer, err := client.NewInMemorySigner(keySeed)
	if err != nil {
		fail(err)
	}
	pub, err := base64.RawURLEncoding.DecodeString(*pubText)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		fail(fmt.Errorf("invalid server public key"))
	}
	var mirrors [][2]string
	if err = json.Unmarshal([]byte(*mirrorsText), &mirrors); err != nil {
		fail(err)
	}
	rawBody := []byte(*bodyText)
	var rpc map[string]any
	if err = json.Unmarshal(rawBody, &rpc); err != nil {
		fail(err)
	}
	parsedURL, err := url.Parse(*endpoint)
	if err != nil {
		fail(err)
	}
	parsedURL.Path = "/mcp"
	parsedURL.RawPath = ""
	now := func() time.Time {
		b, e := os.ReadFile(*clockPath)
		if e != nil {
			return time.Unix(0, 0)
		}
		n, _ := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
		return time.Unix(n, 0)
	}
	cap := &capture{mirrors: append([][2]string(nil), mirrors...)}
	base := recorder{base: http.DefaultTransport, c: cap}
	tr := client.NewTransport(base, *aud, signer, pub)
	tr.Now = now
	tr.Nonce = func() ([]byte, error) {
		return append([]byte(nil), seed...), nil
	}
	tr.Stream = &clientstream.ClientConfig{FrameMaxBytes: int64(*frameMax), Idle: time.Duration(*idle) * time.Millisecond}
	req, err := http.NewRequest("POST", parsedURL.String(), bytes.NewReader(rawBody))
	if err != nil {
		fail(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for _, pair := range mirrors {
		if len(pair) != 2 {
			fail(fmt.Errorf("invalid mirror header"))
		}
		req.Header.Add(pair[0], pair[1])
	}
	if *accept != "" {
		req.Header.Set("Jack-Accept", *accept)
	}
	if *profile != "modern" {
		fail(fmt.Errorf("stream client requires modern profile"))
	}
	sig := ""
	if *accept == "" {
		resp, e := tr.RoundTrip(req)
		sig = signatureFromCaptured(cap)
		terminalRefusal(*scenario, resp, e, sig, rpc, cap)
		return
	}
	stream, verified, e := tr.OpenStream(req)
	sig = signatureFromCaptured(cap)
	if e != nil {
		if verified != nil {
			code := responseErrorCode(verified.Body)
			if (verified.Status == http.StatusNotImplemented && code == "streaming_unsupported") || (verified.Status == http.StatusTooManyRequests && code == "stream_limit_exceeded") {
				emitRefusal(*scenario, verified.Status, verified.Header, verified.Body, sig, rpc["id"], cap)
			} else {
				emitTerminal(*scenario, "error", "stream_bad_frame", nil, nil, nil, 0, verified.Status, sig, rpc, nil)
			}
		} else {
			status := capturedStatus(cap)
			body := cap.responseBodySnapshot()
			if emitUnsignedReplayedNonce(*scenario, status, body, sig, rpc["id"]) {
				return
			}
			frames := parseFrames(body)
			open := parseOpen(capturedResponseHeader(cap).Get("Jack-Auth"))
			for i := range frames {
				frames[i].SID = openSID(open)
				frames[i].KID = openKID(open)
			}
			code := streamCode(e)
			emitTerminal(*scenario, "error", code, open, frames, failureFrame(frames, nil, code), 0, status, sig, rpc, nil)
		}
		return
	}
	if verified != nil {
		code := responseErrorCode(verified.Body)
		if verified.Status == http.StatusUnauthorized && code == "replayed_nonce" {
			emit(map[string]any{
				"type": "terminal", "scenario": *scenario, "outcome": "refused", "code": code,
				"http_status": verified.Status, "http_code": code, "frames_verified": 0,
				"request_id": rpc["id"], "mcp_complete": false, "terminal_frame": nil,
				"request_sig": sig, "v1_evidence": nil, "open": nil, "frames": []frame{},
				"failure_frame": nil, "successor_activation": nil,
				"http_body_b64u": base64.RawURLEncoding.EncodeToString(verified.Body),
			})
		} else if (verified.Status == http.StatusNotImplemented && code == "streaming_unsupported") || (verified.Status == http.StatusTooManyRequests && code == "stream_limit_exceeded") {
			emitRefusal(*scenario, verified.Status, verified.Header, verified.Body, sig, rpc["id"], cap)
		} else {
			emitTerminal(*scenario, "error", "stream_bad_frame", nil, nil, nil, 0, verified.Status, sig, rpc, nil)
		}
		return
	}
	if stream == nil {
		emitTerminal(*scenario, "error", "stream_bad_frame", nil, nil, nil, 0, capturedStatus(cap), sig, rpc, nil)
		return
	}
	defer stream.Close()
	open := parseOpen(cap.responseHeader.Get("Jack-Auth"))
	cancel := *action == "cancel"
	for {
		data, nextErr := stream.Next()
		if nextErr != nil {
			code := streamCode(nextErr)
			verifiedFrames := parseFrames(cap.responseBodySnapshot())
			for i := range verifiedFrames {
				verifiedFrames[i].SID = openSID(open)
				verifiedFrames[i].KID = openKID(open)
			}
			allFrames := append([]frame(nil), verifiedFrames...)
			verifiedFrames = verifiedFrames[:minInt(stream.FramesVerified(), len(verifiedFrames))]
			outcome := "error"
			if errors.Is(nextErr, io.EOF) {
				outcome = "complete"
				code = ""
			}
			failure := failureFrame(allFrames, verifiedFrames, code)
			emitTerminal(*scenario, outcome, code, open, verifiedFrames, failure, stream.FramesVerified(), capturedStatus(cap), sig, rpc, nil)
			return
		}
		frames := parseFrames(cap.responseBodySnapshot())
		for i := range frames {
			frames[i].SID = openSID(open)
			frames[i].KID = openKID(open)
		}
		frames = frames[:minInt(stream.FramesVerified(), len(frames))]
		msg := map[string]any{}
		_ = json.Unmarshal([]byte(data), &msg)
		evidence := requestEvidence(cap, sig, now(), *nonceText)
		record := map[string]any{"type": "message", "scenario": *scenario, "stream_index": 0, "request_method": evidence.Method, "request_target": evidence.Target, "request_body_b64u": evidence.Body, "request_headers": evidence.Headers, "request_sig": sig, "request_ts": requestTimestamp(cap), "nonce": *nonceText, "open": open, "frames": frames, "data": data, "message": msg}
		emit(record)
		if cancel {
			_ = stream.Close()
			waitForHandlerCancelled(*requestLog, sig)
			emitTerminal(*scenario, "cancelled", "", open, frames, nil, stream.FramesVerified(), capturedStatus(cap), sig, rpc, nil)
			return
		}

	}
}

type reqEvidence struct {
	Method, Target, Body string
	Headers              [][2]string
}

func (c *capture) responseBodySnapshot() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.responseBody.Bytes()...)
}
func requestEvidence(c *capture, sig string, now time.Time, nonce string) reqEvidence {
	c.mu.Lock()
	defer c.mu.Unlock()
	return reqEvidence{c.method, c.target, base64.RawURLEncoding.EncodeToString(c.body), c.headers}
}
func requestTimestamp(c *capture) int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, h := range c.headers {
		if strings.EqualFold(h[0], "Jack-Auth") {
			a, e := jack.ParseRequestAuth([]string{h[1]})
			if e == nil {
				return a.TS
			}
		}
	}
	return 0
}
func signatureFromCaptured(c *capture) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, h := range c.headers {
		if strings.EqualFold(h[0], "Jack-Auth") {
			a, e := jack.ParseRequestAuth([]string{h[1]})
			if e == nil {
				return a.Sig
			}
		}
	}
	return ""
}
func parseOpen(v string) *openEvidence {
	parts := strings.Split(v, ",")
	if len(parts) != 4 || !strings.HasPrefix(parts[0], "s1 kid=") {
		return nil
	}
	o := &openEvidence{KID: strings.TrimPrefix(parts[0], "s1 kid=")}
	o.TS, _ = strconv.ParseInt(strings.TrimPrefix(parts[1], "ts="), 10, 64)
	o.SID = strings.TrimPrefix(parts[2], "sid=")
	o.Sig = strings.TrimPrefix(parts[3], "sig=")
	return o
}
func parseFrames(raw []byte) []frame {
	out := []frame{}
	for _, block := range strings.Split(string(raw), "\n\n") {
		if !strings.Contains(block, "jack:") {
			continue
		}
		var f frame
		event := "message"
		auth := ""
		data := []string{}
		for _, line := range strings.Split(strings.TrimSuffix(block, "\r"), "\n") {
			switch {
			case strings.HasPrefix(line, "event:"):
				event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			case strings.HasPrefix(line, "data:"):
				data = append(data, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
			case strings.HasPrefix(line, "jack:"):
				auth = strings.TrimSpace(strings.TrimPrefix(line, "jack:"))
			}
		}
		f.Kind = "message"
		if event == "jack-end" {
			f.Kind = "end"
		}
		f.Data = strings.Join(data, "\n")
		var seq, ts int64
		var sig string
		for _, p := range strings.Split(auth, ",") {
			kv := strings.SplitN(p, "=", 2)
			if len(kv) != 2 {
				continue
			}
			switch kv[0] {
			case "seq":
				seq, _ = strconv.ParseInt(kv[1], 10, 64)
			case "ts":
				ts, _ = strconv.ParseInt(kv[1], 10, 64)
			case "sig":
				sig = kv[1]
			}
		}
		f.Seq = seq
		f.TS = ts
		f.Sig = sig
		if len(out) > 0 {
			f.SID = out[0].SID
			f.KID = out[0].KID
		}
		out = append(out, f)
	}
	return out
}
func streamCode(err error) string {
	var se *clientstream.Error
	if errors.As(err, &se) {
		return string(se.Code)
	}
	if errors.Is(err, clientstream.ErrClosed) {
		return "stream_cancelled"
	}
	return "stream_bad_frame"
}
func failureFrame(all, verified []frame, code string) any {
	if code != "stream_out_of_order" && code != "stream_bad_signature" {
		return nil
	}
	if len(all) > len(verified) {
		return all[len(verified)]
	}
	return nil
}
func emitTerminal(scenario, outcome, code string, open *openEvidence, frames []frame, failure any, count, responseStatus int, sig string, rpc map[string]any, evidence any) {
	var terminalFrame any
	if len(frames) > 0 && frames[len(frames)-1].Kind == "end" {
		terminalFrame = map[string]any{"kind": "end", "sig": frames[len(frames)-1].Sig}
	}
	complete := false
	if outcome == "complete" && terminalFrame != nil && len(frames) > 1 {
		var last map[string]any
		_ = json.Unmarshal([]byte(frames[len(frames)-2].Data), &last)
		complete = last["jsonrpc"] == "2.0" && last["id"] == rpc["id"] && (has(last, "result") != has(last, "error")) && !has(last, "method")
	}
	var c any
	if code != "" {
		c = code
	}
	var status any
	if responseStatus != 0 {
		status = responseStatus
	}
	emit(map[string]any{"type": "terminal", "scenario": scenario, "outcome": outcome, "code": c, "http_status": status, "http_code": nil, "frames_verified": count, "request_id": rpc["id"], "mcp_complete": complete, "terminal_frame": terminalFrame, "request_sig": sig, "v1_evidence": evidence, "open": open, "frames": frames, "failure_frame": failure, "successor_activation": nil})
}
func emitRefusal(scenario string, status int, h http.Header, body []byte, sig string, requestID any, c *capture) {
	ev := map[string]any{"status": status, "request_sig": sig, "body_b64u": base64.RawURLEncoding.EncodeToString(body)}
	auth := h.Get("Jack-Auth")
	p := strings.Split(auth, ",")
	if len(p) == 3 {
		ev["kid"] = strings.TrimPrefix(p[0], "v1 kid=")
		ev["ts"], _ = strconv.ParseInt(strings.TrimPrefix(p[1], "ts="), 10, 64)
		ev["sig"] = strings.TrimPrefix(p[2], "sig=")
	}
	code := ""
	var payload struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &payload) == nil {
		code = payload.Error.Code
	}
	emit(map[string]any{"type": "terminal", "scenario": scenario, "outcome": "refused", "code": code, "http_status": status, "http_code": code, "frames_verified": 0, "request_id": requestID, "mcp_complete": false, "terminal_frame": nil, "request_sig": sig, "v1_evidence": ev, "open": nil, "frames": []frame{}, "failure_frame": nil, "successor_activation": nil})
}
func emitUnsignedReplayedNonce(scenario string, status int, body []byte, sig string, requestID any) bool {
	if status != http.StatusUnauthorized || responseErrorCode(body) != "replayed_nonce" {
		return false
	}
	emit(map[string]any{"type": "terminal", "scenario": scenario, "outcome": "refused", "code": "replayed_nonce", "http_status": http.StatusUnauthorized, "http_code": "replayed_nonce", "frames_verified": 0, "request_id": requestID, "mcp_complete": false, "terminal_frame": nil, "request_sig": sig, "v1_evidence": nil, "open": nil, "frames": []frame{}, "failure_frame": nil, "successor_activation": nil, "http_body_b64u": base64.RawURLEncoding.EncodeToString(body)})
	return true
}
func terminalRefusal(s string, r *http.Response, e error, sig string, rpc map[string]any, c *capture) {
	if e != nil {
		status := capturedStatus(c)
		body := c.responseBodySnapshot()
		if emitUnsignedReplayedNonce(s, status, body, sig, rpc["id"]) {
			return
		}
		emitTerminal(s, "error", "stream_bad_frame", nil, nil, nil, 0, status, sig, rpc, nil)
		return
	}
	if r != nil && r.Body != nil {
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
	}
	body := c.responseBodySnapshot()
	c.mu.Lock()
	header := c.responseHeader.Clone()
	status := c.status
	c.mu.Unlock()
	if status == 0 && r != nil {
		status = r.StatusCode
	}
	emitRefusal(s, status, header, body, sig, rpc["id"], c)
}
func openSID(o *openEvidence) string {
	if o == nil {
		return ""
	}
	return o.SID
}
func openKID(o *openEvidence) string {
	if o == nil {
		return ""
	}
	return o.KID
}
func responseErrorCode(body []byte) string {
	var payload struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(body, &payload)
	return payload.Error.Code
}
func capturedResponseHeader(c *capture) http.Header {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.responseHeader.Clone()
}
func waitForHandlerCancelled(path, sig string) {
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		b, _ := os.ReadFile(path)
		for _, line := range bytes.Split(b, []byte{'\n'}) {
			var row map[string]any
			if json.Unmarshal(line, &row) == nil && row["event"] == "handler_cancelled" && row["request_sig"] == sig {
				return
			}
		}
		select {
		case <-deadline.C:
			return
		case <-ticker.C:
		}
	}
}
func capturedStatus(c *capture) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.status
}

func emit(v any) {
	b, _ := json.Marshal(v)
	fmt.Println(string(b))
}

func has(m map[string]any, k string) bool {
	_, ok := m[k]
	return ok
}
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func hexDecode(s string) ([]byte, error) {
	return hex.DecodeString(s)
}
