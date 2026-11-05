package spec

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

// TestLoadersDecodeAllFixtures loads every fixture through its loader and
// fails on any decode error or empty result. Strict decoding turns a fixture
// field without a Go field into an error here.
func TestLoadersDecodeAllFixtures(t *testing.T) {
	keys, err := LoadKeys()
	if err != nil {
		t.Fatalf("LoadKeys: %v", err)
	}
	if len(keys.Keys) == 0 {
		t.Fatalf("LoadKeys: no keys")
	}

	registry, err := LoadRegistry()
	if err != nil {
		t.Fatalf("LoadRegistry: %v", err)
	}
	if len(registry.Keys) == 0 {
		t.Fatalf("LoadRegistry: no keys")
	}

	defaultPolicy, err := LoadDefaultPolicy()
	if err != nil {
		t.Fatalf("LoadDefaultPolicy: %v", err)
	}
	if len(defaultPolicy.Rules) == 0 {
		t.Fatalf("LoadDefaultPolicy: no rules")
	}

	wildcardPolicy, err := LoadWildcardPolicy()
	if err != nil {
		t.Fatalf("LoadWildcardPolicy: %v", err)
	}
	if len(wildcardPolicy.Rules) == 0 {
		t.Fatalf("LoadWildcardPolicy: no rules")
	}

	requests, err := LoadRequestVectors()
	if err != nil {
		t.Fatalf("LoadRequestVectors: %v", err)
	}
	if len(requests.Cases) == 0 {
		t.Fatalf("LoadRequestVectors: no cases")
	}
	if len(requests.Policies) == 0 {
		t.Fatalf("LoadRequestVectors: no policies")
	}

	admin, err := LoadAdminVectors()
	if err != nil {
		t.Fatalf("LoadAdminVectors: %v", err)
	}
	if len(admin.Cases) == 0 {
		t.Fatalf("LoadAdminVectors: no cases")
	}

	responses, err := LoadResponseVectors()
	if err != nil {
		t.Fatalf("LoadResponseVectors: %v", err)
	}
	if len(responses.Cases) == 0 {
		t.Fatalf("LoadResponseVectors: no cases")
	}

	keyVectors, err := LoadKeyVectors()
	if err != nil {
		t.Fatalf("LoadKeyVectors: %v", err)
	}
	if len(keyVectors.Cases) == 0 {
		t.Fatalf("LoadKeyVectors: no cases")
	}

	loadVectors, err := LoadLoadVectors()
	if err != nil {
		t.Fatalf("LoadLoadVectors: %v", err)
	}
	if len(loadVectors.Policies) == 0 || len(loadVectors.Registries) == 0 {
		t.Fatalf("LoadLoadVectors: empty policy or registry cases")
	}

	patterns, err := LoadPatternVectors()
	if err != nil {
		t.Fatalf("LoadPatternVectors: %v", err)
	}
	if len(patterns.Cases) == 0 {
		t.Fatalf("LoadPatternVectors: no cases")
	}
}

// TestRegistryKidMatchesPublicKey confirms the registry kid is
// base64url(SHA-256(public key bytes)) for every entry, as required by the
// spec's key checks.
func TestRegistryKidMatchesPublicKey(t *testing.T) {
	registry, err := LoadRegistry()
	if err != nil {
		t.Fatalf("LoadRegistry: %v", err)
	}
	for _, entry := range registry.Keys {
		publicKey, err := DecodeB64U(entry.PublicKey)
		if err != nil {
			t.Fatalf("key %s: public_key: %v", entry.Name, err)
		}
		if len(publicKey) != 32 {
			t.Fatalf("key %s: public key is %d bytes, want 32", entry.Name, len(publicKey))
		}
		sum := sha256.Sum256(publicKey)
		want := base64.RawURLEncoding.EncodeToString(sum[:])
		if entry.Kid != want {
			t.Errorf("key %s: kid %q, want %q", entry.Name, entry.Kid, want)
		}
	}
}
