package subscription

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/urlcheck"
)

// Domain separates subscription IDs from other hashes.
const Domain = "mcp-jack/webhook1/subscription"

// KeyError contains a rejection code and optional reason.
type KeyError struct {
	Code, Reason string
}

func (e *KeyError) Error() string {
	if e.Reason == "" {
		return e.Code
	}
	return e.Code + ": " + e.Reason
}

// Key contains the derived ID and its canonical inputs.
type Key struct {
	ID, CanonicalURL, CanonicalArguments, JCSInput string
}

// SubscriptionKey derives the R8.4 ID. arguments is the decoded arguments
// value, with nil representing both an absent member and JSON null.
func SubscriptionKey(principal, url, name string, arguments any) (Key, *KeyError) {
	target, err := urlcheck.Check(url)
	if err != nil {
		return Key{}, &KeyError{Code: err.Code, Reason: err.Reason}
	}
	canonicalArguments, jcsErr := JCS(arguments)
	if jcsErr != nil {
		return Key{}, invalidArguments("arguments")
	}
	input, jcsErr := JCS([]any{Domain, principal, target.Canonical, name, arguments})
	if jcsErr != nil {
		return Key{}, invalidArguments("arguments")
	}
	digest := sha256.Sum256([]byte(input))
	return Key{
		ID:                 "sub_" + hex.EncodeToString(digest[:8]),
		CanonicalURL:       target.Canonical,
		CanonicalArguments: canonicalArguments,
		JCSInput:           input,
	}, nil
}

func invalidArguments(reason string) *KeyError {
	return &KeyError{Code: "invalid_arguments", Reason: reason}
}
