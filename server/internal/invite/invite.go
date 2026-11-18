// Package invite holds the invite-code identity helper shared by the
// verifier and the protocol-native tools. This is a file-layout move only;
// no behavior changed.
package invite

import (
	"crypto/sha256"

	jack "github.com/PHPCraftdream/mcp-jack"
)

// InviteIDOf derives the storage id of an invite from its raw code bytes.
// It was previously the unexported server.inviteIDOf; the body is unchanged.
func InviteIDOf(rawCode []byte) string {
	sum := sha256.Sum256(rawCode)
	return jack.EncodeBase64URL(sum[:])
}
