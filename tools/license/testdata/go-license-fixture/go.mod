// Licence-check rejection fixture: an Apache-2.0-only dependency that must
// fail an MIT-only allowlist and pass the real allowlist. Never built by the
// product jobs; only the license workflow uses it. See tools/license/README.md.
module mcp-jack.example/license-fixture

go 1.22

require github.com/google/go-cmp v0.6.0
