package jack_test

import (
	"strings"
	"testing"

	"github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/spec"
)

func TestMatchPatternVectors(t *testing.T) {
	vecs, err := spec.LoadPatternVectors()
	if err != nil {
		t.Fatalf("LoadPatternVectors: %v", err)
	}

	for _, c := range vecs.Cases {
		c := c
		t.Run(c.ID, func(t *testing.T) {
			got := jack.MatchPattern(c.Pattern, c.Input)
			if got != c.Match {
				t.Fatalf("MatchPattern(%q, %q) = %v, want %v", c.Pattern, c.Input, got, c.Match)
			}
		})
	}
}

func TestMatchPatternUnit(t *testing.T) {
	// Only '*' is a metacharacter; everything else is a literal, and '*'
	// matches across newlines too (spec 02 section 3).
	cases := []struct {
		pattern string
		input   string
		want    bool
	}{
		{"*", "", true},
		{"*", "anything\nat all", true},
		{"a*", "a\nb", true},
		{"*status", "svc.status.extra", false},
		{"a+b", "a+b", true},
		{"a+b", "aab", false},
		{"(x)", "(x)", true},
		{"?", "?", true},
		{"?", "a", false},
	}
	for _, c := range cases {
		c := c
		t.Run(c.pattern+"|"+c.input, func(t *testing.T) {
			got := jack.MatchPattern(c.pattern, c.input)
			if got != c.want {
				t.Fatalf("MatchPattern(%q, %q) = %v, want %v", c.pattern, c.input, got, c.want)
			}
		})
	}
}

func TestValidScope(t *testing.T) {
	accept := []string{"read", "config:write", "a:b:c", "lifecycle", "a1_b"}
	reject := []string{"", "Read", "1abc", "a::b", "a:b-", "read ", "a:b c"}

	for _, s := range accept {
		if !jack.ValidScope(s) {
			t.Errorf("ValidScope(%q) = false, want true", s)
		}
	}
	for _, s := range reject {
		if jack.ValidScope(s) {
			t.Errorf("ValidScope(%q) = true, want false", s)
		}
	}
}

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
