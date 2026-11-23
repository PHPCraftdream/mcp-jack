package modern

// reason is one row of the reason table of spec 04 section 5.1.
type reason struct {
	status  int
	code    int
	message string
}

// reasons is the fixed reason table of spec 04 section 5.1, keyed by reason
// token. Messages are verbatim, carry no trailing period and never echo a
// received value.
var reasons = map[string]reason{
	"method_not_allowed":         {405, -32600, "HTTP method not allowed"},
	"header_value_invalid":       {400, -32020, "Header mismatch: a request metadata header value contains a character outside the HTTP field-value syntax"},
	"header_repeated":            {400, -32020, "Header mismatch: a request metadata header appears more than once"},
	"version_header_missing":     {400, -32020, "Header mismatch: MCP-Protocol-Version is missing"},
	"version_header_malformed":   {400, -32020, "Header mismatch: MCP-Protocol-Version is malformed"},
	"version_meta_missing":       {400, -32020, "Header mismatch: params._meta protocolVersion is missing"},
	"version_mismatch":           {400, -32020, "Header mismatch: MCP-Protocol-Version does not match params._meta protocolVersion"},
	"method_header_missing":      {400, -32020, "Header mismatch: Mcp-Method is missing"},
	"method_header_mismatch":     {400, -32020, "Header mismatch: Mcp-Method does not match the body method"},
	"name_header_not_applicable": {400, -32020, "Header mismatch: Mcp-Name is not defined for this method"},
	"name_source_missing":        {400, -32020, "Header mismatch: the body has no string value for the Mcp-Name source field"},
	"name_header_missing":        {400, -32020, "Header mismatch: Mcp-Name is missing"},
	"name_header_bad_encoding":   {400, -32020, "Header mismatch: Mcp-Name is not a valid base64 sentinel encoding"},
	"name_header_mismatch":       {400, -32020, "Header mismatch: Mcp-Name does not match the body value"},
}

// refuse renders a signed JSON-RPC refusal (S10) for a reason token.
func refuse(reasonToken, era string, id []byte) Outcome {
	r := reasons[reasonToken]
	return Outcome{
		Kind:          KindRefuse,
		Era:           era,
		Signed:        true,
		HTTPStatus:    r.status,
		ContentType:   "application/json",
		JSONRPC:       "2.0",
		ID:            id,
		Error:         RPCError{Code: r.code, Message: r.message},
		ConsumesNonce: true,
	}
}
