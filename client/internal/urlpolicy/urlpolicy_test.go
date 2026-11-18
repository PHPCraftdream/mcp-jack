package urlpolicy

import (
	"testing"

	"github.com/PHPCraftdream/mcp-jack/client/internal/testfixture"
)

func TestCheckDestinationFixture(t *testing.T) {
	for _, c := range testfixture.LoadURLPolicyCases(t) {
		t.Run(c.Name, func(t *testing.T) {
			err := CheckDestination(c.URL)
			if c.Allow && err != nil {
				t.Fatalf("checkDestination(%q) = %v, want allow", c.URL, err)
			}
			if !c.Allow && err == nil {
				t.Fatalf("checkDestination(%q) = nil, want refusal", c.URL)
			}
		})
	}
}
