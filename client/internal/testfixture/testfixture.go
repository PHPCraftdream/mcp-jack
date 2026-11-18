// Package testfixture shares the client URL-policy fixture loader
// (spec/fixtures/client-url-policy.json) between the root client tests and
// the client/internal/urlpolicy conformance test.
package testfixture

import (
	"encoding/json"
	"strings"
	"testing"

	spec "github.com/PHPCraftdream/mcp-jack/spec"
)

// URLPolicyCase is one row of spec/fixtures/client-url-policy.json.
type URLPolicyCase struct {
	Name        string   `json:"name"`
	URL         string   `json:"url"`
	Allow       bool     `json:"allow"`
	ParseReject []string `json:"parse_reject"`
}

// GoParseRejects reports whether the fixture row is flagged as rejected by
// Go's net/url parser although the policy accepts it.
func GoParseRejects(c URLPolicyCase) bool {
	for _, p := range c.ParseReject {
		if p == "go" {
			return true
		}
	}
	return false
}

// GenericParseMsg is the non-policy error text of the public constructors.
const GenericParseMsg = "must be an absolute http/https URL"

// LoadURLPolicyCases loads the client URL-policy fixture rows.
func LoadURLPolicyCases(t *testing.T) []URLPolicyCase {
	t.Helper()
	data, err := spec.Fixture("client-url-policy.json")
	if err != nil {
		t.Fatalf("spec.Fixture: %v", err)
	}
	var doc struct {
		Cases []URLPolicyCase `json:"cases"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("decode client-url-policy.json: %v", err)
	}
	if len(doc.Cases) == 0 {
		t.Fatal("client-url-policy.json has no cases")
	}
	seen := make(map[string]bool, len(doc.Cases))
	for _, c := range doc.Cases {
		if c.Name == "" || strings.ContainsAny(c.Name, " /\\") || seen[c.Name] {
			t.Fatalf("fixture case name %q is empty, unsanitised or duplicate", c.Name)
		}
		seen[c.Name] = true
		if len(c.ParseReject) > 0 && !c.Allow {
			t.Fatalf("fixture case %q: parse_reject only makes sense for allowed rows", c.Name)
		}
	}
	return doc.Cases
}
