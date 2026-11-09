// Package jack is the root of the mcp-jack Go SDK. mcp-jack is a secure
// transport protocol that wraps plain MCP (JSON-RPC over HTTP) with
// Ed25519-signed requests, an admin flag gating only the jack.admin.* tools,
// protocol-native user management, and a verified caller identity handed to
// the wrapped MCP handler.
//
// The SDK lives in subpackages (server, client, and the spec conformance
// fixtures); this package only holds the module documentation.
package jack
