//go:build linux

package serverkey

import "crypto/ed25519"

// LocalServerKeySigner exposes the local signer type to external tests.
type LocalServerKeySigner = localServerKeySigner

// Private returns the raw private bytes for test-only custody assertions.
func (signer *localServerKeySigner) Private() ed25519.PrivateKey { return signer.private }
