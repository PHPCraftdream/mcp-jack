package jack_test

import (
	"strings"
	"testing"

	"github.com/PHPCraftdream/mcp-jack"
)

func TestValidName(t *testing.T) {
	accept := []string{"a", "alice-laptop", "A_1.b-c", strings.Repeat("a", 64)}
	reject := []string{"", strings.Repeat("a", 65), "bad name", "bad:name", "bad/name"}

	for _, s := range accept {
		if !jack.ValidName(s) {
			t.Errorf("ValidName(%q) = false, want true", s)
		}
	}
	for _, s := range reject {
		if jack.ValidName(s) {
			t.Errorf("ValidName(%q) = true, want false", s)
		}
	}
}
