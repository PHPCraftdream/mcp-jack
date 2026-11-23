package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/client"
)

// errStopScenario says the scenario sent everything it will send: a client
// stop or an intermediate answer the sequence cannot continue from. The run
// loop then builds the result line from the steps already recorded.
var errStopScenario = errors.New("modern-client: scenario stopped")

// unsignedAllowedCodes is the spec 01 section 5 unsigned-allowed 401 family:
// the only response that may lack Jack-Auth (contract section 2). The client
// uses it only for the envelope check of an unsigned 401.
var unsignedAllowedCodes = map[string]bool{
	jack.CodeMissingAuth:          true,
	jack.CodeMalformedAuth:        true,
	jack.CodeUnsupportedVersion:   true,
	jack.CodeUnknownKey:           true,
	jack.CodeKeyInactive:          true,
	jack.CodeTimestampOutOfWindow: true,
	jack.CodeBadSignature:         true,
	jack.CodeReplayedNonce:        true,
}

// clientCodes is the closed client-code vocabulary of contract 4.2: the
// codes a client_error may report. It is the unsigned-allowed 401 family
// plus unknown_server_key, which the client raises itself when a response
// is not signed by the pinned key.
var clientCodes = map[string]bool{
	jack.CodeMissingAuth:          true,
	jack.CodeMalformedAuth:        true,
	jack.CodeUnsupportedVersion:   true,
	jack.CodeUnknownKey:           true,
	jack.CodeKeyInactive:          true,
	jack.CodeTimestampOutOfWindow: true,
	jack.CodeBadSignature:         true,
	jack.CodeUnknownServerKey:     true,
}

// recorder is the base RoundTripper of the SDK signing transport. It records
// the request the SDK signed and the exact response bytes the SDK read, so
// the executable can report them without signing or verifying anything
// itself (contract 4.2).
type recorder struct {
	base http.RoundTripper
	mu   sync.Mutex
	// pending holds the recorded exchanges whose response has not been
	// consumed yet, oldest first.
	pending []*exchange
}

// exchange is one recorded HTTP exchange.
type exchange struct {
	// requestAuth is the whole Jack-Auth value as the SDK put it on the wire;
	// the step reports this value rather than one recomputed from its parts.
	requestAuth string
	requestSig  string // sig parameter of the request Jack-Auth
	method      string // HTTP method the SDK signed
	url         string // exact URL the SDK signed
	// headerLines is the request's header set, deterministic order.
	headerLines [][2]string
	requestBody []byte // exact request body bytes
	status      int
	auth        *string
	contentType *string
	allow       *string
	sessionID   *string
	body        []byte // exact response body bytes the SDK read
}

// RoundTrip sends the SDK-signed request and records what came back. The
// response body is wrapped so the bytes the SDK reads are kept even when it
// stops early or reports an error after reading.
func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	// The SDK buffered and signed the body before this call; reading it here
	// and putting it back leaves the request bytes the base sends unchanged.
	var requestBody []byte
	if req.Body != nil {
		raw, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		requestBody = raw
		req.Body = io.NopCloser(bytes.NewReader(raw))
	}
	ex := &exchange{method: req.Method, url: req.URL.String(), requestBody: requestBody,
		requestAuth: req.Header.Get("Jack-Auth"), headerLines: headerLines(req.Header)}
	if auth, perr := jack.ParseRequestAuth([]string{ex.requestAuth}); perr == nil {
		ex.requestSig = auth.Sig
	}
	resp, err := r.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	recordResponse(ex, resp)
	resp.Body = &recordingBody{source: resp.Body, owner: r, ex: ex}
	r.mu.Lock()
	r.pending = append(r.pending, ex)
	r.mu.Unlock()
	return resp, nil
}

// take returns the oldest unconsumed exchange; requests are strictly
// sequential, so the caller sees them in send order.
func (r *recorder) take() *exchange {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.pending) == 0 {
		return nil
	}
	ex := r.pending[0]
	r.pending = r.pending[1:]
	return ex
}

// recordingBody copies every byte the SDK reads into the exchange, keeping
// ex.body up to date while the read is in progress.
type recordingBody struct {
	source io.ReadCloser
	owner  *recorder
	ex     *exchange
}

func (b *recordingBody) Read(p []byte) (int, error) {
	n, err := b.source.Read(p)
	if n > 0 {
		b.owner.mu.Lock()
		b.ex.body = append(b.ex.body, p[:n]...)
		b.owner.mu.Unlock()
	}
	return n, err
}

func (b *recordingBody) Close() error { return b.source.Close() }

// headerValue folds the field lines of one response header into the value the
// result line reports: nil when absent, the single value, or the instances
// joined with ", " (the combined form the fake client reports).
func headerValue(values []string) *string {
	switch len(values) {
	case 0:
		return nil
	case 1:
		value := values[0]
		return &value
	}
	joined := strings.Join(values, ", ")
	return &joined
}

// headerLines renders a request header set as name/value pairs. The HTTP
// library, not this executable, owns the wire order of differently named
// lines, so the names are sorted and the values of one name keep their
// order: this is the request's header set in a deterministic order.
func headerLines(header http.Header) [][2]string {
	names := make([]string, 0, len(header))
	for name := range header {
		names = append(names, name)
	}
	sort.Strings(names)
	lines := make([][2]string, 0, len(names))
	for _, name := range names {
		for _, value := range header[name] {
			lines = append(lines, [2]string{name, value})
		}
	}
	return lines
}

// recordResponse copies the status and the response headers the result line
// reports onto the exchange.
func recordResponse(ex *exchange, resp *http.Response) {
	ex.status = resp.StatusCode
	ex.auth = headerValue(resp.Header.Values("Jack-Auth"))
	ex.contentType = headerValue(resp.Header.Values("Content-Type"))
	ex.allow = headerValue(resp.Header.Values("Allow"))
	ex.sessionID = headerValue(resp.Header.Values("Mcp-Session-Id"))
}

// b64u is the unpadded base64url of the byte fields of a step (contract 4.2).
func b64u(data []byte) string { return base64.RawURLEncoding.EncodeToString(data) }

// request is one request a scenario sends.
type request struct {
	name        string      // step name (contract 4.4)
	method      string      // POST, GET or HEAD
	body        []byte      // exact bytes; nil for GET and HEAD
	contentType bool        // send Content-Type: application/json (POST only)
	mirrors     [][2]string // MCP-Protocol-Version, Mcp-Method, Mcp-Name, Mcp-Param-*, in that order
	era         string      // "modern" or "legacy": becomes data.era of the last request
}

// answer is what one exchange tells the scenario.
type answer struct {
	step   step
	status int
	body   []byte
	// sent is the recorded request, so a replay resends these bytes.
	sent *exchange
	// verified reports that the SDK verified the response; an unsigned-allowed
	// 401 is answered without verification, so it is not an era signal
	// (contract 4.3, unverified row).
	verified bool
}

// verdict is a pending client decision that decides the result line.
type verdict struct {
	code    string
	outcome string
}

// perform sends one request through the SDK client and records its step.
// A returned error is either errStopScenario (nothing more to send) or a
// fatal error (the scenario cannot be run at all, exit 1).
func (c *clientState) perform(w request) (*answer, error) {
	var body io.Reader
	if len(w.body) > 0 {
		// Contract 4.4: a GET or HEAD has no body at all, so no reader is set.
		body = bytes.NewReader(w.body)
	}
	req, err := http.NewRequest(w.method, c.endpoint, body)
	if err != nil {
		return nil, fmt.Errorf("request %s: %w", w.name, err)
	}
	if w.contentType {
		req.Header.Set("Content-Type", "application/json")
	}
	// Contract section 2: the mirrors go on as separate header lines in the
	// given order; nothing here sorts, renames or folds them.
	for _, mirror := range w.mirrors {
		req.Header.Set(mirror[0], mirror[1])
	}

	resp, doErr := c.hc.Do(req)
	ex := c.recorder.take()
	if resp != nil {
		_ = resp.Body.Close()
	}
	// Contract 4.2: a failure before the first answer means the scenario cannot
	// be run at all; after one answer the run reports a client error instead.
	transportFailure := func(cause error) error {
		if len(c.steps) == 0 {
			return fmt.Errorf("request %s: %w", w.name, cause)
		}
		return c.failTransport(requestStep(w.name, w))
	}
	if ex == nil {
		// The SDK refused the destination (client URL policy) or the connection
		// failed before anything came back, so no answer was recorded.
		cause := doErr
		if cause == nil {
			cause = errors.New("no exchange recorded")
		}
		return nil, transportFailure(cause)
	}
	code, verification := judgeResponse(doErr, ex.status, ex.body)
	if !verification {
		// A transport failure the recorder still saw (a truncated or unreadable
		// answer) is never a trusted answer: the step keeps the request and
		// reports no response members at all.
		return nil, transportFailure(doErr)
	}
	// Contract 4.2: a step exists for every request whose answer arrived, so it
	// is recorded before the answer is classified.
	recorded := c.stepFromExchange(w.name, ex)
	c.steps = append(c.steps, recorded)
	c.lastEra = w.era
	answer := &answer{
		step:     recorded,
		status:   ex.status,
		body:     ex.body,
		sent:     ex,
		verified: doErr == nil,
	}
	if code != "" {
		c.stop(code, "client_error")
		return nil, errStopScenario
	}
	return answer, nil
}

// exchangeTarget is the one target the contract defines (contract 4.1).
const exchangeTarget = "/mcp"

// stepFromExchange renders one reported step (contract 4.2) from a recorded
// exchange, so the report is what actually went on the wire and never a
// reconstruction from the scenario.
func (c *clientState) stepFromExchange(name string, ex *exchange) step {
	status := ex.status
	return step{
		Name:          name,
		HTTPMethod:    ex.method,
		HTTPTarget:    targetOf(ex.url),
		JSONRPCMethod: jsonrpcMethodOf(ex.requestBody),
		HTTPStatus:    &status,
		ID:            responseID(ex.body),
		// The honest header set handed to the HTTP library, deterministic
		// order (contract 4.2).
		RequestHeaders:      ex.headerLines,
		RequestBodyB64U:     b64u(ex.requestBody),
		RequestSig:          ex.requestSig,
		ResponseAuth:        ex.auth,
		ResponseContentType: ex.contentType,
		ResponseAllow:       ex.allow,
		ResponseSessionID:   ex.sessionID,
		ResponseBodyB64U:    b64u(ex.body),
	}
}

// requestStep renders the failing step of a request whose answer never
// arrived: the request members are the ones this executable handed to its
// HTTP library, and every response member stays null because nothing was
// verified (contract 4.2).
func requestStep(name string, w request) step {
	return step{
		Name:            name,
		HTTPMethod:      w.method,
		HTTPTarget:      exchangeTarget,
		JSONRPCMethod:   jsonrpcMethodOf(w.body),
		ID:              json.RawMessage("null"),
		RequestHeaders:  requestHeaderLines(w),
		RequestBodyB64U: b64u(w.body),
	}
}

// replayStep is requestStep for a replayed request: it was sent with the
// source request's own signature, so that signature is reported.
func replayStep(name string, sent *exchange) step {
	return step{
		Name:            name,
		HTTPMethod:      sent.method,
		HTTPTarget:      targetOf(sent.url),
		JSONRPCMethod:   jsonrpcMethodOf(sent.requestBody),
		ID:              json.RawMessage("null"),
		RequestHeaders:  sent.headerLines,
		RequestBodyB64U: b64u(sent.requestBody),
		RequestSig:      sent.requestSig,
	}
}

// requestHeaderLines renders the header set this executable hands its HTTP
// library for w, in the same deterministic order headerLines uses.
func requestHeaderLines(w request) [][2]string {
	header := http.Header{}
	if w.contentType {
		header.Set("Content-Type", "application/json")
	}
	for _, mirror := range w.mirrors {
		header.Set(mirror[0], mirror[1])
	}
	return headerLines(header)
}

// failTransport stops the run after a transport failure that followed at
// least one answer. Contract 4.2's closed client vocabulary has no code for
// a network failure, so the code stays null instead of inventing one, and
// the failing step carries the request with no response members.
func (c *clientState) failTransport(failed step) error {
	c.steps = append(c.steps, failed)
	c.pending = &verdict{code: "", outcome: "client_error"}
	return errStopScenario
}

// targetOf is the origin-form target of a recorded URL; the contract pins /mcp.
func targetOf(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.RequestURI() == "" {
		return exchangeTarget
	}
	return parsed.RequestURI()
}

// jsonrpcMethodOf is the body method of a recorded request body; nil when
// the body carries none (GET and HEAD send no body).
func jsonrpcMethodOf(body []byte) *string {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(body, &object); err != nil || object == nil {
		return nil
	}
	var method *string
	if err := json.Unmarshal(object["method"], &method); err != nil || method == nil {
		return nil
	}
	return method
}

// judgeResponse classifies one answer the SDK rejected. code is the client
// code to report and is empty for the spec 01 section 5 unsigned-allowed 401
// family (contract section 2: that family is the only answer that may lack
// Jack-Auth). verification is false when err is not a verification problem
// at all (a connection failure, a refused redirect, a decode error after a
// verified answer), so the caller keeps its own policy.
func judgeResponse(err error, status int, body []byte) (code string, verification bool) {
	if err == nil {
		return "", true
	}
	var unauthenticated *client.UnauthenticatedResponseError
	if errors.As(err, &unauthenticated) {
		// Contract section 2: Jack's own 401 envelope is the only response
		// that may lack Jack-Auth, and acting on it is not verification.
		if status == http.StatusUnauthorized {
			if envelope, ok := jackEnvelopeCode(body); ok && unsignedAllowedCodes[envelope] {
				return "", true
			}
		}
		return jack.CodeMissingAuth, true
	}
	var jackErr *jack.Error
	if errors.As(err, &jackErr) {
		// The same 401 envelope rule applies to a missing signature that
		// reaches the executable as a raw SDK error instead of an
		// *UnauthenticatedResponseError (the replay verifies directly). Only a
		// response that lacks Jack-Auth qualifies: a signed answer from an
		// unpinned key still reports its own code.
		if jackErr.Code == jack.CodeMissingAuth && status == http.StatusUnauthorized {
			if envelope, ok := jackEnvelopeCode(body); ok && unsignedAllowedCodes[envelope] {
				return "", true
			}
		}
		if !clientCodes[jackErr.Code] {
			// Contract 4.2 closes the client vocabulary, so an SDK code
			// outside it is reported as bad_signature.
			return jack.CodeBadSignature, true
		}
		return jackErr.Code, true
	}
	return "", false
}

// maxReplayBodyBytes is the SDK transport's own response cap.
const maxReplayBodyBytes = 1 << 20

// replay resends the recorded request unchanged - same bytes, same Jack-Auth
// signature, same nonce (contract section 2) - through the transport below
// the SDK, and verifies the answer with the SDK's own response verification
// (client.VerifyResponse, the call the SDK transport makes), so nothing is
// signed twice and nothing is re-implemented.
func (c *clientState) replay(stepName string, sent *exchange) (*answer, error) {
	req, err := http.NewRequest(sent.method, sent.url, bytes.NewReader(sent.requestBody))
	if err != nil {
		return nil, fmt.Errorf("replay %s: %w", stepName, err)
	}
	for _, header := range sent.headerLines {
		req.Header.Add(header[0], header[1])
	}
	// Contract 4.2: the same rule holds without the SDK, because a replayed
	// request is a request like any other.
	transportFailure := func(cause error) error {
		if len(c.steps) == 0 {
			return fmt.Errorf("replay %s: %w", stepName, cause)
		}
		return c.failTransport(replayStep(stepName, sent))
	}
	resp, err := c.base.RoundTrip(req)
	if err != nil {
		return nil, transportFailure(err)
	}
	responseBody, readErr := io.ReadAll(io.LimitReader(resp.Body, maxReplayBodyBytes+1))
	_ = resp.Body.Close()
	if readErr != nil {
		return nil, transportFailure(fmt.Errorf("reading response body: %w", readErr))
	}
	if len(responseBody) > maxReplayBodyBytes {
		return nil, transportFailure(fmt.Errorf("response body exceeds %d bytes", maxReplayBodyBytes))
	}
	ex := &exchange{
		method:      sent.method,
		url:         sent.url,
		requestBody: sent.requestBody,
		requestAuth: sent.requestAuth,
		requestSig:  sent.requestSig,
		headerLines: sent.headerLines,
		body:        responseBody,
	}
	recordResponse(ex, resp)
	verifyErr := client.VerifyResponse(c.anchor, ex.status, resp.Header.Values("Jack-Auth"),
		sent.requestSig, ex.body, time.Unix(c.clock.Now(), 0), client.DefaultWindow)

	recorded := c.stepFromExchange(stepName, ex)
	c.steps = append(c.steps, recorded)
	// The replay repeats the source request, so the era it proves is the one
	// already recorded; data.era does not change (contract 4.2).

	answer := &answer{
		step:     recorded,
		status:   ex.status,
		body:     ex.body,
		sent:     ex,
		verified: verifyErr == nil,
	}
	if verifyErr == nil {
		return answer, nil
	}
	code, verification := judgeResponse(verifyErr, ex.status, ex.body)
	if !verification {
		return nil, fmt.Errorf("replay %s: %w", stepName, verifyErr)
	}
	if code != "" {
		c.stop(code, "client_error")
		return nil, errStopScenario
	}
	return answer, nil
}

// stop records the client verdict that decides the result line (contract 4.2)
// and aborts the scenario: no further request is sent.
func (c *clientState) stop(code, outcome string) {
	c.pending = &verdict{code: code, outcome: outcome}
}

// stopSequence aborts the scenario without a client verdict, so the last
// recorded step decides the result line.
func (c *clientState) stopSequence() error { return errStopScenario }

// responseID is the raw JSON-RPC id member of a response body, or null when
// the body is not a JSON object or has no id member (contract 4.2).
func responseID(body []byte) json.RawMessage {
	null := json.RawMessage("null")
	var object map[string]json.RawMessage
	if err := json.Unmarshal(body, &object); err != nil || object == nil {
		return null
	}
	raw, ok := object["id"]
	if !ok {
		return null
	}
	return append(json.RawMessage(nil), raw...)
}

// listRegionEchoSchema extracts the served inputSchema of region.echo from a
// tools/list body; the fixed contract 3.4 (d) schema stands in when it cannot
// be extracted.
func listRegionEchoSchema(body []byte) []byte {
	var parsed struct {
		Result struct {
			Tools []struct {
				Name        string          `json:"name"`
				InputSchema json.RawMessage `json:"inputSchema"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return []byte(regionEchoSchema)
	}
	for _, tool := range parsed.Result.Tools {
		if tool.Name == regionEchoTool && len(tool.InputSchema) > 0 {
			return tool.InputSchema
		}
	}
	return []byte(regionEchoSchema)
}

// jackEnvelopeCode reports the string code of Jack's own {"error":{"code":...}}
// envelope: a JSON object with no jsonrpc member (spec 01 section 4). Any
// other shape, including a JSON-RPC error, is not that envelope.
func jackEnvelopeCode(body []byte) (string, bool) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(body, &object); err != nil || object == nil {
		return "", false
	}
	if _, ok := object["jsonrpc"]; ok {
		return "", false
	}
	var errorObject map[string]json.RawMessage
	if err := json.Unmarshal(object["error"], &errorObject); err != nil {
		return "", false
	}
	var code string
	if err := json.Unmarshal(errorObject["code"], &code); err != nil {
		return "", false
	}
	return code, true
}

// nextNonce is the deterministic nonce source of contract section 2: the
// first 16 bytes of sha256("mcp-jack-interop-modern/nonce/<scenario>/<i>"),
// as 16 raw bytes (the SDK encodes them as unpadded base64url).
func (c *clientState) nextNonce() ([]byte, error) {
	index := c.nonceIndex
	c.nonceIndex++
	sum := sha256.Sum256([]byte("mcp-jack-interop-modern/nonce/" + c.scenario + "/" + strconv.Itoa(index)))
	nonce := make([]byte, 16)
	copy(nonce, sum[:16])
	return nonce, nil
}
