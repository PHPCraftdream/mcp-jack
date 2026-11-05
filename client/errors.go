package client

import (
	"encoding/json"
	"fmt"
)

// HTTPError reports a non-2xx response whose verified body is
// {"error":{"code":...,"message":...}}.
type HTTPError struct {
	Status  int
	Code    string
	Message string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("jack client: http %d %s: %s", e.Status, e.Code, e.Message)
}

// RPCError reports the JSON-RPC error member of an otherwise successful call.
type RPCError struct {
	Code    int
	Message string
	Data    json.RawMessage
}

func (e *RPCError) Error() string {
	return fmt.Sprintf("jack client: rpc error %d: %s", e.Code, e.Message)
}

// ToolError reports an MCP result with isError true.
type ToolError struct {
	Message    string
	Structured json.RawMessage
}

func (e *ToolError) Error() string {
	return fmt.Sprintf("jack client: tool error: %s", e.Message)
}

// wireError mirrors the tolerant error envelope of spec 01 section 5
// (unsigned 401 bodies) and verified non-2xx bodies.
type wireError struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// parseErrorBody decodes {"error":{"code":string,"message":string}} tolerantly:
// any unknown shape yields empty strings.
func parseErrorBody(body []byte) (code, message string) {
	var w wireError
	if err := json.Unmarshal(body, &w); err != nil {
		return "", ""
	}
	return w.Error.Code, w.Error.Message
}
