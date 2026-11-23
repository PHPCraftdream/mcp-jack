// The fixed wrapped handler of the modern matrix (interop/modern/contract.md
// 3.4 and 3.5) and its request log (3.3). The handler only ever sees
// authenticated requests the SDK forwarded; it never inspects the per-request
// era, and it never signs anything: the SDK signs every answer.
package main

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
)

// The --discover-version-mode values of contract 3.5 and the pinned answers of
// contract 3.4: the serverInfo identity, the only session id this server mints,
// the params._meta member carrying the requested version (spec 04 section 2)
// and the initialize fallback version.
const (
	discoverSupported        = "supported"
	discoverRefuseFirst      = "refuse-first"
	discoverRefuseAlways     = "refuse-always"
	serverImplementation     = "mcp-jack-interop-modern"
	serverVersion            = "1.0.0"
	sessionID                = "sess-1"
	metaProtocolVersion      = "io.modelcontextprotocol/protocolVersion"
	defaultNegotiatedVersion = "2025-11-25"
)

// serverInfo is the pinned serverInfo of contract 3.4: exactly two members.
var serverInfo = map[string]any{"name": serverImplementation, "version": serverVersion}

// toolsResult is the tools/list result of contract 3.4 (d): one tool whose
// region argument is projected onto the Region header.
var toolsResult = map[string]any{"tools": []map[string]any{{
	"name": "region.echo",
	"inputSchema": map[string]any{"type": "object", "required": []string{"region"},
		"properties": map[string]any{"region": map[string]any{"type": "string", "x-mcp-header": "Region"}}},
}}}

// wireRequest is the body the handler answers; an undecodable or empty body
// leaves Method empty and answers as an unknown method.
type wireRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

// handler is the fixed wrapped handler of contract 3.4.
type handler struct {
	profile   string
	versions  []string
	mode      string
	mu        sync.Mutex // guards discovers: refuse-first counts the process
	discovers int
	log       *requestLog
}

// newHandler returns the wrapped handler of contract 3.4 configured with the
// process profile, the configured versions and the discover version mode.
func newHandler(profile string, versions []string, mode string, log *requestLog) http.Handler {
	return &handler{profile: profile, versions: versions, mode: mode, log: log}
}

// answer is one handler answer: status, body, response headers beyond
// Content-Type, and the body method for the request log.
type answer struct {
	status int
	body   []byte
	extra  http.Header
	method string
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	var in wireRequest
	if err != nil || json.Unmarshal(body, &in) != nil {
		in = wireRequest{}
	}
	res := h.answer(in, r.Header)
	// Contract 3.3: the log line goes out before the response.
	h.log.write(res.method, res.status)
	for name, values := range res.extra {
		w.Header()[name] = values
	}
	// Contract 3.4: every JSON answer is application/json; the 202 of (g) has
	// no body and no response headers at all.
	if res.status != http.StatusAccepted {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(res.status)
	_, _ = w.Write(res.body)
}

// answer dispatches one request; received is the header set this handler got.
func (h *handler) answer(in wireRequest, received http.Header) answer {
	switch in.Method {
	case "server/discover":
		return h.discover(in)
	case "tools/list":
		return resultAnswer(in, toolsResult)
	case "tools/call":
		if name, _ := textMember(in.Params, "name"); name == "region.echo" {
			return resultAnswer(in, echoResult(received))
		}
	case "initialize":
		// (f): the requested version is echoed only when it is configured.
		negotiated := defaultNegotiatedVersion
		if requested, ok := textMember(in.Params, "protocolVersion"); ok && h.supports(requested) {
			negotiated = requested
		}
		extra := http.Header{}
		extra.Set("Mcp-Session-Id", sessionID)
		res := resultAnswer(in, map[string]any{
			"protocolVersion": negotiated,
			"capabilities":    map[string]any{},
			"serverInfo":      serverInfo,
		})
		res.extra = extra
		return res
	case "notifications/initialized":
		return answer{status: http.StatusAccepted, method: in.Method}
	}
	// (h): any other method, and tools/call of any other tool.
	return errorAnswer(in, http.StatusOK, -32601, "method not found", nil)
}

// discover answers server/discover per contract 3.4 (a) to (c) and 3.5.
func (h *handler) discover(in wireRequest) answer {
	if h.profile == profileLegacy {
		// (b): the spec 01 section 4 envelope has no jsonrpc and no id, so a C9
		// client reads it as a legacy signal and falls back to initialize.
		body, _ := json.Marshal(map[string]any{"error": map[string]any{
			"code":    "method_not_allowed",
			"message": "server/discover is not available in the legacy profile",
		}})
		return answer{status: http.StatusMethodNotAllowed, body: body, method: in.Method}
	}
	requested, hasRequested := textMember(in.Params, "_meta", metaProtocolVersion)
	// Every discover this handler answers is counted, whatever the decision.
	h.mu.Lock()
	first := h.discovers == 0
	h.discovers++
	h.mu.Unlock()

	refused := h.mode == discoverRefuseAlways || (h.mode == discoverRefuseFirst && first)
	if !refused {
		refused = !hasRequested || !h.supports(requested)
	}
	if refused {
		// (c): requested stays a Go nil unless the body carried a string, so a
		// missing or non-string request marshals as null.
		data := map[string]any{"supported": h.versions, "requested": any(nil)}
		if hasRequested {
			data["requested"] = requested
		}
		return errorAnswer(in, http.StatusBadRequest, -32022, "Unsupported protocol version", data)
	}
	return resultAnswer(in, map[string]any{
		"resultType":        "complete",
		"supportedVersions": h.versions,
		"capabilities":      map[string]any{},
		"serverInfo":        serverInfo,
	})
}

// supports reports whether version is one of the configured versions (exact
// byte equality of the trimmed flag entries).
func (h *handler) supports(version string) bool { return slices.Contains(h.versions, version) }

// echoResult is the region.echo result of contract 3.4 (e): one
// "<name>: <value>" line per header instance this handler received, LF-joined
// with no trailing LF. Go's http.Header is a map, so the wire order is already
// gone; the contract allows a framework-chosen deterministic order, hence the
// sorted names. Nothing is filtered: the SDK already removed the session
// headers in the modern era.
func echoResult(received http.Header) any {
	names := make([]string, 0, len(received))
	for name := range received {
		names = append(names, name)
	}
	sort.Strings(names)
	lines := []string{}
	for _, name := range names {
		for _, value := range received[name] {
			lines = append(lines, name+": "+value)
		}
	}
	return map[string]any{"content": []map[string]any{{"type": "text", "text": strings.Join(lines, "\n")}}}
}

// resultAnswer wraps a successful result in the JSON-RPC envelope of (a), (d),
// (e) and (f).
func resultAnswer(in wireRequest, result any) answer {
	return answer{status: http.StatusOK, body: envelope(in.ID, result, nil), method: in.Method}
}

// errorAnswer wraps a JSON-RPC error in the envelope of (c) and (h); the data
// member is omitted when nil.
func errorAnswer(in wireRequest, status, code int, message string, data any) answer {
	failure := map[string]any{"code": code, "message": message}
	if data != nil {
		failure["data"] = data
	}
	return answer{status: status, body: envelope(in.ID, nil, failure), method: in.Method}
}

// envelope renders {"jsonrpc":"2.0","id":...} with either the result or the
// error member; a body without an id echoes null (contract 3.4).
func envelope(id json.RawMessage, result, failure any) []byte {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	out := map[string]any{"jsonrpc": "2.0", "id": id}
	if failure != nil {
		out["error"] = failure
	} else {
		out["result"] = result
	}
	b, _ := json.Marshal(out)
	return b
}

// textMember returns the string found at path inside the raw JSON object; an
// absent step, null and every non-string value report false.
func textMember(raw json.RawMessage, path ...string) (string, bool) {
	for _, member := range path {
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil {
			return "", false
		}
		raw = fields[member]
	}
	var value *string
	if json.Unmarshal(raw, &value) != nil || value == nil {
		return "", false
	}
	return *value, true
}

// requestLog appends one {"method":...,"http_status":...} line per request
// this handler answers (contract 3.3). The mutex keeps concurrent handlers
// from interleaving lines, and a nil log disables logging entirely.
type requestLog struct {
	mu sync.Mutex
	f  *os.File
}

// openRequestLog opens the append-only request log; an empty path disables it.
func openRequestLog(path string) (*requestLog, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	return &requestLog{f: f}, nil
}

// write appends one line: only handler-dispatched requests reach it, and a
// body without a method logs null (contract 3.3).
func (l *requestLog) write(method string, status int) {
	if l == nil {
		return
	}
	entry := map[string]any{"method": any(nil), "http_status": status}
	if method != "" {
		entry["method"] = method
	}
	b, _ := json.Marshal(entry)
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.f.Write(append(b, '\n'))
}

// close releases the log file; a nil log is a no-op.
func (l *requestLog) close() {
	if l == nil {
		return
	}
	_ = l.f.Close()
}
