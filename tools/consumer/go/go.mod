// Standalone Go consumer smoke module. It depends on the STAGED module
// snapshot only: the replace directive below is the documented resolution of
// the staged module artifact (stage/module produced by package-go.mjs),
// never the repo checkout.
// External dependencies of the staged module resolve through the public
// proxy and sumdb; the SDK's own go.mod and go.sum are kept byte for byte.

module mcp-jack-go-consumer-smoke

go 1.25.0

require github.com/PHPCraftdream/mcp-jack v0.0.0

replace github.com/PHPCraftdream/mcp-jack => ../module
