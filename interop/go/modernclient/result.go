package main

import (
	"encoding/base64"
	"encoding/json"
	"math"
	"strconv"
	"strings"
)

// step is one request the executable actually sent, in the shape of contract
// 4.2. Every member is always present, null where not applicable.
type step struct {
	Name                string          `json:"name"`
	HTTPMethod          string          `json:"http_method"`
	HTTPTarget          string          `json:"http_target"`
	JSONRPCMethod       *string         `json:"jsonrpc_method"`
	HTTPStatus          *int            `json:"http_status"`
	ID                  json.RawMessage `json:"id"`
	RequestHeaders      [][2]string     `json:"request_headers"`
	RequestBodyB64U     string          `json:"request_body_b64u"`
	RequestSig          string          `json:"request_sig"`
	ResponseAuth        *string         `json:"response_auth"`
	ResponseContentType *string         `json:"response_content_type"`
	ResponseAllow       *string         `json:"response_allow"`
	ResponseSessionID   *string         `json:"response_session_id"`
	ResponseBodyB64U    string          `json:"response_body_b64u"`
}

// resultLine is the single stdout line of contract 4.2.
type resultLine struct {
	Scenario   string `json:"scenario"`
	Outcome    string `json:"outcome"`
	HTTPStatus *int   `json:"http_status"`
	Code       any    `json:"code"`
	Data       struct {
		Era   string `json:"era"`
		Steps []step `json:"steps"`
	} `json:"data"`
}

// resultLine classifies the run (contract 4.2): a pending client verdict wins,
// otherwise the last response decides outcome, status and code.
func (c *clientState) resultLine() resultLine {
	line := resultLine{Scenario: c.scenario}
	line.Data.Era = c.lastEra
	line.Data.Steps = c.steps

	var last *step
	if len(c.steps) > 0 {
		last = &c.steps[len(c.steps)-1]
	}
	if c.pending != nil {
		line.Outcome = c.pending.outcome
		// An empty code means the contract's closed client vocabulary has no
		// entry for the failure (a transport failure carries no wire code), so
		// the member stays null.
		if c.pending.code != "" {
			line.Code = c.pending.code
		}
		// client_error means no answer was trusted, so it carries no status;
		// a rejection after a verified answer reports that answer's status.
		if c.pending.outcome != "client_error" && last != nil {
			line.HTTPStatus = last.HTTPStatus
		}
		return line
	}
	if last == nil {
		line.Outcome = "client_error"
		return line
	}
	line.HTTPStatus = last.HTTPStatus
	if last.HTTPStatus != nil && *last.HTTPStatus >= 200 && *last.HTTPStatus <= 299 {
		line.Outcome = "ok"
	} else {
		line.Outcome = "rejected"
	}
	body, err := base64.RawURLEncoding.DecodeString(last.ResponseBodyB64U)
	if err != nil {
		body = nil
	}
	line.Code = wireCode(body)
	return line
}

// wireCode is the code of a response body (contract 4.2): an integer from a
// JSON-RPC 2.0 error object, else a string from Jack's own envelope, else null.
func wireCode(body []byte) any {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(body, &root); err != nil || root == nil {
		return nil
	}
	var errorObject map[string]json.RawMessage
	if err := json.Unmarshal(root["error"], &errorObject); err != nil || errorObject == nil {
		return nil
	}
	rawCode, ok := errorObject["code"]
	if !ok {
		return nil
	}
	var version string
	if json.Unmarshal(root["jsonrpc"], &version) == nil && version == "2.0" {
		if code, ok := integerCode(rawCode); ok {
			return code
		}
	}
	var text string
	if json.Unmarshal(rawCode, &text) == nil {
		return text
	}
	return nil
}

// twoTo63 is 2^63, the first float64 above the int64 range.
const twoTo63 = 1 << 63

// integerCode decides integrality the way the contract reads it: -32020 and
// -32020.0 are integers, 1.5, "7" and an out-of-range number are not.
func integerCode(raw json.RawMessage) (int, bool) {
	text := strings.TrimSpace(string(raw))
	if text == "" {
		return 0, false
	}
	if value, err := strconv.ParseInt(text, 10, 64); err == nil {
		return int(value), true
	}
	value, err := strconv.ParseFloat(text, 64)
	if err != nil || math.IsNaN(value) || math.IsInf(value, 0) || value != math.Trunc(value) {
		return 0, false
	}
	if value < -twoTo63 || value >= twoTo63 {
		return 0, false
	}
	return int(value), true
}
