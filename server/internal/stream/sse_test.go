package stream

import (
	"math/rand"
	"slices"
	"strings"
	"testing"
)

// splitterCases are handler bodies and the data values the splitter must emit
// for each: the behaviours of 2.10-2.14, one case per behaviour.
var splitterCases = []struct {
	name string
	body string
	want []string
}{
	{
		name: "plain message",
		body: "event: message\ndata: {\"a\":1}\n\n",
		want: []string{`{"a":1}`},
	},
	{
		name: "two events",
		body: "data: one\n\ndata: two\n\n",
		want: []string{"one", "two"},
	},
	{
		name: "multi-line data",
		body: "data: {\"a\":\ndata: 1}\n\n",
		want: []string{"{\"a\":\n1}"},
	},
	{
		name: "crlf terminators",
		body: "data: a\r\n\r\n",
		want: []string{"a"},
	},
	{
		name: "lone cr terminators",
		body: "data: a\r\r",
		want: []string{"a"},
	},
	{
		name: "bare cr inside the event normalises to lf",
		body: "data: a\rdata: b\n\n",
		want: []string{"a\nb"},
	},
	{
		name: "comments before between and inside",
		body: ": before\n\ndata: one\n\n: between\n\ndata: two\n: inside\n\n",
		want: []string{"one", "two"},
	},
	{
		name: "id retry event and unknown fields are dropped",
		body: "id: 7\nretry: 100\nevent: foo\nx-unknown: y\ndata: value\n\n",
		want: []string{"value"},
	},
	{
		name: "event without data produces nothing",
		body: "event: ping\n: comment\n\n",
		want: nil,
	},
	{
		name: "empty data line produces the empty value",
		body: "data:\n\n",
		want: []string{""},
	},
	{
		name: "unterminated trailing event produces nothing",
		body: "data: done\n\ndata: trailing",
		want: []string{"done"},
	},
	{
		name: "empty body produces nothing",
		body: "",
		want: nil,
	},
}

// collect feeds chunks through one splitter and returns the data values it
// emitted.
func collect(t *testing.T, limit int64, chunks ...[]byte) []string {
	t.Helper()
	var sp splitter
	var got []string
	for _, chunk := range chunks {
		if err := sp.feed(chunk, limit, func(data string) error {
			got = append(got, data)
			return nil
		}); err != nil {
			t.Fatalf("feed(%q): %v", chunk, err)
		}
	}
	return got
}

// record compares one feeding strategy against the expected data values.
func record(t *testing.T, c struct {
	name string
	body string
	want []string
}, strategy string, chunks ...[]byte) {
	t.Helper()
	if got := collect(t, 0, chunks...); !slices.Equal(got, c.want) {
		t.Fatalf("%s (%s): got %q, want %q", c.name, strategy, got, c.want)
	}
}

func TestSplitterFrameMaxCountsDataOnlyAndResets(t *testing.T) {
	const limit = int64(3)
	var sp splitter
	var got []string
	emit := func(data string) error { got = append(got, data); return nil }
	if err := sp.feed([]byte(": "+strings.Repeat("c", 20)+"\n"+"event: "+strings.Repeat("e", 20)+"\n"+"data: abc\n\n"), limit, emit); err != nil {
		t.Fatalf("exact cap and comment/field bytes rejected: %v", err)
	}
	if len(got) != 1 || got[0] != "abc" {
		t.Fatalf("events = %q, want [abc]", got)
	}
	if err := sp.feed([]byte("data: abcd\n\n"), limit, emit); err != errEventTooLarge {
		t.Fatalf("over-limit event = %v, want errEventTooLarge", err)
	}
}

func TestSplitterRejectsUnterminatedDataAsSoonAsOverCap(t *testing.T) {
	const limit = int64(3)
	for _, chunks := range [][]string{{"data: abcd"}, {"data: a", "bc", "d"}} {
		var sp splitter
		for i, chunk := range chunks {
			err := sp.feed([]byte(chunk), limit, func(string) error { return nil })
			if i == len(chunks)-1 && err != errEventTooLarge {
				t.Fatalf("chunks %q: final feed error = %v, want errEventTooLarge before newline", chunks, err)
			}
			if i < len(chunks)-1 && err != nil {
				t.Fatalf("chunks %q: feed %d error = %v", chunks, i, err)
			}
		}
	}
}

func TestSplitterCountsOnlyDataValuesIncrementally(t *testing.T) {
	const limit = int64(3)
	var sp splitter
	if err := sp.feed([]byte(":"+strings.Repeat("c", 100)+"\nevent: "+strings.Repeat("e", 100)+"\ndata:"), limit, func(string) error { return nil }); err != nil {
		t.Fatalf("comments and field bytes rejected: %v", err)
	}
	if err := sp.feed([]byte(" abc\n\n"), limit, func(value string) error {
		if value != "abc" {
			t.Fatalf("data = %q, want abc", value)
		}
		return nil
	}); err != nil {
		t.Fatalf("exact data cap rejected: %v", err)
	}
}

func TestSplitterCommentsDoNotAccumulateAcrossCompletions(t *testing.T) {
	var sp splitter
	for i := 0; i < 8; i++ {
		body := []byte(": " + strings.Repeat("x", 64) + "\n\ndata: a\n\n")
		if err := sp.feed(body, 1, func(string) error { return nil }); err != nil {
			t.Fatalf("comment-only completion %d: %v", i, err)
		}
		if sp.size != 0 {
			t.Fatalf("comment-only completion %d retained %d bytes", i, sp.size)
		}
	}
}

// TestSplitterExtractsDataValues covers 2.10-2.14: which bytes of a handler
// body become the data values of complete events.
func TestSplitterExtractsDataValues(t *testing.T) {
	for _, c := range splitterCases {
		record(t, c, "whole", []byte(c.body))
	}
}

// TestSplitterAnySplit requires the same data values however the body is cut
// into chunks: whole, one byte at a time, at every line boundary and at every
// possible two-part split.
func TestSplitterAnySplit(t *testing.T) {
	for _, c := range splitterCases {
		body := []byte(c.body)

		record(t, c, "whole", body)

		bytes := make([][]byte, 0, len(body))
		for i := range body {
			bytes = append(bytes, body[i:i+1])
		}
		record(t, c, "one byte at a time", bytes...)

		for i := 0; i <= len(body); i++ {
			if i != 0 && i != len(body) && body[i-1] != '\n' && body[i-1] != '\r' {
				continue
			}
			record(t, c, "line boundary", body[:i], body[i:])
		}

		for i := 0; i <= len(body); i++ {
			record(t, c, "two-part split", body[:i], body[i:])
		}
	}
}

// TestSplitterProperty feeds each body in deterministic random chunks of one
// to seven bytes and requires the same data values.
func TestSplitterProperty(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for _, c := range splitterCases {
		body := []byte(c.body)
		for iter := 0; iter < 200; iter++ {
			chunks := make([][]byte, 0, len(body))
			for i := 0; i < len(body); {
				n := rng.Intn(7) + 1
				if i+n > len(body) {
					n = len(body) - i
				}
				chunks = append(chunks, body[i:i+n])
				i += n
			}
			if got := collect(t, 0, chunks...); !slices.Equal(got, c.want) {
				t.Fatalf("%s (iteration %d, chunks %q): got %q, want %q", c.name, iter, chunks, got, c.want)
			}
		}
	}
}
