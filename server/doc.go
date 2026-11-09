// Package server provides the persistence-facing primitives of the mcp-jack
// server SDK: the replay-protection nonce store (01-authentication.md section 4),
// the registry and invite state store (02-authorization.md section 1,
// 03-user-management.md section 9) and the audit sink (03-user-management.md
// section 8). Verification, the verified-identity hand-off and the HTTP layers
// are built on top of it.
package server
