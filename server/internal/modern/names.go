package modern

// nameSources maps an MCP method to the params member its Mcp-Name header
// mirrors (spec 04 S6). The table is closed: a method without a row has no
// source field and must not carry Mcp-Name.
var nameSources = map[string]string{
	"tools/call":         "name",
	"prompts/get":        "name",
	"events/poll":        "name",
	"events/stream":      "name",
	"events/subscribe":   "name",
	"events/unsubscribe": "name",
	"resources/read":     "uri",
}

// nameSource returns the params member that method mirrors, if the closed table
// has a row for it.
func nameSource(method string) (string, bool) {
	source, ok := nameSources[method]
	return source, ok
}
