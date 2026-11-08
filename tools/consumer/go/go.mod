// Standalone Go consumer smoke module. It depends on the STAGED module
// snapshot only: the replace directive below is the documented resolution of
// the staged module artifact (stage/module produced by package-go.mjs),
// never the repo checkout. The replaced module is a filesystem path and the
// module has no external dependencies (stdlib only), so no go.sum is
// required: replaced modules bypass the proxy and checksum database entirely.

module mcp-jack-go-consumer-smoke

go 1.22

require github.com/PHPCraftdream/mcp-jack v0.0.0

replace github.com/PHPCraftdream/mcp-jack => ../module
