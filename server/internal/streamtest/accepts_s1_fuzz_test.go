package streamtest

import (
	"strings"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/server/internal/stream"
)

// acceptsS1Oracle models the documented Jack-Accept token grammar independently
// of the production parser: only ASCII space is trimmed, commas delimit tokens,
// and malformed lines contribute no tokens.
func acceptsS1Oracle(values ...string) bool {
	for _, line := range values {
		line = strings.Trim(line, " ")
		if line == "" {
			continue
		}
		parts := strings.Split(line, ",")
		valid := true
		for i := range parts {
			parts[i] = strings.Trim(parts[i], " ")
			if parts[i] == "" {
				valid = false
				break
			}
			for j := 0; j < len(parts[i]); j++ {
				c := parts[i][j]
				if !(c == '-' || c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z') {
					valid = false
					break
				}
			}
			if !valid {
				break
			}
		}
		if valid {
			for _, token := range parts {
				if token == "s1" {
					return true
				}
			}
		}
	}
	return false
}

// FuzzAcceptsS1 checks that only an exact s1 token opts into streaming.
func FuzzAcceptsS1(f *testing.F) {
	seeds := [][2][]byte{
		{[]byte(""), []byte("")},
		{[]byte("s1"), []byte("")},
		{[]byte(" s1 "), []byte("")},
		{[]byte("s2, s1"), []byte("")},
		{[]byte("S1"), []byte("")},
		{[]byte("s10"), []byte("")},
		{[]byte("s1x"), []byte("")},
		{[]byte("s1,,s2"), []byte("")},
		{[]byte(",s1"), []byte("")},
		{[]byte("s1,"), []byte("")},
		{[]byte("s1\ts2"), []byte("")},
		{[]byte("s1\r"), []byte("")},
		{[]byte("s1\n"), []byte("")},
		{[]byte("s1\x00"), []byte("")},
		{[]byte{0xff, 's', '1'}, []byte("")},
		{[]byte("s2"), []byte("s1")},
		{[]byte("s1,s1"), []byte("s2")},
		{[]byte(strings.Repeat("x", 4096)), []byte("s2")},
	}
	for _, seed := range seeds {
		f.Add(seed[0], seed[1])
	}

	f.Fuzz(func(t *testing.T, first, second []byte) {
		values := []string{string(first), string(second)}
		var got bool
		func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("AcceptsS1(%q) panicked: %v", values, recovered)
				}
			}()
			got = stream.AcceptsS1(values)
		}()
		want := acceptsS1Oracle(values...)
		if got != want {
			t.Fatalf("AcceptsS1(%q) = %v, want %v", values, got, want)
		}
	})
}
