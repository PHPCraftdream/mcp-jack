package modern

import "fmt"

// RequestMirrors is the params._meta object and the mirror headers of one
// modern-era request (C1/C2).
type RequestMirrors struct {
	// Meta is the params._meta object of the request. It always carries the
	// protocol version and the client capabilities, and the client info when
	// the caller supplied it.
	Meta map[string]any
	// Headers are the exact C2 emit order: MCP-Protocol-Version,
	// Mcp-Method, Mcp-Name and then the Mcp-Param-* headers that the caller
	// appends after these. Go's net/http represents headers as a map, so the
	// HTTP stack cannot preserve this order or the canonical spelling on the
	// wire; this slice is the authoritative C2 order.
	Headers []Header
}

// BuildRequestMirrors builds the C1 _meta object and the C2 headers in the
// authoritative C2 emit order (MCP-Protocol-Version, Mcp-Method, Mcp-Name).
// Go's net/http represents headers as a map, so the HTTP stack cannot preserve
// that order or the canonical spelling on the wire; the returned slice is the
// authoritative C2 order. clientInfo is included only when non-nil. A method
// with an S6 name source needs a string params value; a missing or non-string
// value is an error.
func BuildRequestMirrors(version, method string, params map[string]any, clientInfo map[string]any) (RequestMirrors, error) {
	meta := map[string]any{
		MetaVersionKey:            version,
		MetaClientCapabilitiesKey: map[string]any{},
	}
	if clientInfo != nil {
		meta[MetaClientInfoKey] = clientInfo
	}

	// Preallocate the largest fixed prefix plus the optional Mcp-Name slot, so
	// the returned slice never aliases a larger array.
	headers := make([]Header, 0, 3)
	headers = append(headers,
		Header{Name: "MCP-Protocol-Version", Value: version},
		Header{Name: "Mcp-Method", Value: method},
	)
	if source, ok := NameSource(method); ok {
		value, ok := params[source].(string)
		if !ok {
			return RequestMirrors{}, fmt.Errorf("jack client: %s requires a string params.%s", method, source)
		}
		headers = append(headers, Header{Name: "Mcp-Name", Value: EncodeHeaderValue(value)})
	}
	return RequestMirrors{Meta: meta, Headers: headers}, nil
}
