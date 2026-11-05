// Package client is the mcp-jack client SDK.
//
// Every outgoing request is signed with an Ed25519 signer (Signer) and every
// response is verified against the pinned server public key before its body is
// returned (spec 01 sections 4 and 5). The package speaks the protocol-native
// jack.* tools for user management, including enrollment and key rotation
// (spec 03 sections 3.1-3.3).
package client
