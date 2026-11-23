package stream

import (
	"math/rand"
	"slices"
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
