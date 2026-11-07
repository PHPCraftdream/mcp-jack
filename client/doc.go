// Package client is the mcp-jack client SDK.
//
// Every outgoing request is signed with an Ed25519 signer (Signer) and every
// response is verified against the pinned server public key before its body is
// returned (spec 01 sections 4 and 5). The package speaks the protocol-native
// jack.* tools for user management, including enrollment and key rotation
// (spec 03 sections 3.1-3.3).
//
// # Generic tool calls
//
// Client.CallTool performs one signed, response-verified tools/call for any
// tool name and decodes the verified structuredContent into out (a pointer
// given to json.Unmarshal; nil discards the payload, but a result without
// structuredContent is still an error). It is a single-request signed tool
// caller, not a full MCP session client: there is no initialize, tools/list,
// notification or streaming support, and structuredContent is the only result
// model. The native helpers are unchanged.
//
//	var res struct {
//		OK bool `json:"ok"`
//	}
//	err := c.CallTool(ctx, "svc.restart", map[string]any{"name": "web"}, &res)
//	// errors: *client.HTTPError, *client.RPCError, *client.ToolError, ...
//
// # Destination policy
//
// Spec 01 section 1 requires HTTPS for non-loopback connections. The raw
// destination URL string is checked (docs/design/interop.md section 9) by
// NewClient, by profile loading and validation, and by every Transport
// request before signing: https is accepted for any host, http only for a
// literal canonical 127.x.y.z or [::1]; localhost aliases, userinfo and
// percent escapes in the authority (zone IDs included), and backslashes are
// refused; percent-encoded path/query is accepted and signed as given.
// Nothing is resolved. SDK-built HTTP clients never follow redirects and a
// 301, 302, 303, 307 or 308 answer to a signed request is refused before
// verification (ErrRedirectRefused); its Location is never surfaced. This is
// a no-follow/no-downgrade guard, not TLS enforcement. Other 3xx statuses
// (e.g. a signed 304) are verified normally.
//
// A caller-supplied http.Client or base http.RoundTripper (Config.HTTP,
// Transport.Base) is outside the SDK's control: it must use TLS for https
// URLs, connect to exactly the URL it is given and not follow redirects. The
// SDK cannot police it; the policy is applied before a request reaches it.
// Signing and response verification are mandatory regardless: NewClient always
// wraps Config.HTTP's base round tripper in its own signing/verifying
// Transport (a prewrapped *Transport is collapsed, never mutated).
package client
