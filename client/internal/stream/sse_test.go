package stream

import (
	"bytes"
	"fmt"
	"testing"
	"time"
)

// collect feeds every chunk to p and returns the emitted events.
func collect(t *testing.T, p *sseParser, chunks [][]byte) []event {
	t.Helper()
	var events []event
	emit := func(ev event) error {
		events = append(events, ev)
		return nil
	}
	for i, chunk := range chunks {
		if err := p.feed(chunk, emit); err != nil {
			t.Fatalf("feed of chunk %d: %v", i, err)
		}
	}
	return events
}

// parseChunks feeds every chunk to a fresh parser without a budget and returns
// the emitted events.
func parseChunks(t *testing.T, chunks [][]byte) []event {
	t.Helper()
	return collect(t, newSSEParser(0), chunks)
}

// checkFields compares parsed field lines with the expected ones.
func checkFields(t *testing.T, got, want []field) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("field count = %d, want %d (%q)", len(got), len(want), got)
	}
	for i := range want {
		if got[i].name != want[i].name || !bytes.Equal(got[i].value, want[i].value) {
			t.Fatalf("field %d = {%q, %q}, want {%q, %q}",
				i, got[i].name, got[i].value, want[i].name, want[i].value)
		}
	}
}

// sameEvents compares the field lines of two parses: how a body was cut into
// feeds must not change them.
func sameEvents(t *testing.T, got, want []event) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("event count = %d, want %d", len(got), len(want))
	}
	for i := range want {
		checkFields(t, got[i].fields, want[i].fields)
	}
}

func TestSSEParserEventShapes(t *testing.T) {
	tests := []struct {
		name string
		body string
		want [][]field
	}{
		{
			name: "LF terminators",
			body: "data: one\ndata: two\n\n",
			want: [][]field{{
				{name: "data", value: []byte("one")},
				{name: "data", value: []byte("two")},
			}},
		},
		{
			name: "CRLF terminators",
			body: "data: one\r\ndata: two\r\n\r\n",
			want: [][]field{{
				{name: "data", value: []byte("one")},
				{name: "data", value: []byte("two")},
			}},
		},
		{
			name: "lone CR terminators",
			body: "data: one\rdata: two\r\r",
			want: [][]field{{
				{name: "data", value: []byte("one")},
				{name: "data", value: []byte("two")},
			}},
		},
		{
			name: "one leading BOM ignored",
			body: "\xef\xbb\xbfdata: one\n\n",
			want: [][]field{{
				{name: "data", value: []byte("one")},
			}},
		},
		{
			name: "BOM only at the very start",
			body: "data: one\n\ndata: \xef\xbb\xbftwo\n\n",
			want: [][]field{
				{{name: "data", value: []byte("one")}},
				{{name: "data", value: []byte("\xef\xbb\xbftwo")}},
			},
		},
		{
			name: "comments ignored outside and inside an event",
			body: ": keep-alive\ndata: one\n: mid\ndata: two\n: tail\n\n",
			want: [][]field{{
				{name: "data", value: []byte("one")},
				{name: "data", value: []byte("two")},
			}},
		},
		{
			name: "comment only emits no event",
			body: ": ping\n\n",
			want: nil,
		},
		{
			name: "bare field name is an empty value",
			body: "data\ndata: x\n\n",
			want: [][]field{{
				{name: "data", value: nil},
				{name: "data", value: []byte("x")},
			}},
		},
		{
			name: "one leading SP removed and a second kept",
			body: "data:  x\n\n",
			want: [][]field{{
				{name: "data", value: []byte(" x")},
			}},
		},
		{
			name: "blank line with no field lines emits nothing",
			body: "\n\n\n",
			want: nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			events := parseChunks(t, [][]byte{[]byte(tc.body)})
			if len(events) != len(tc.want) {
				t.Fatalf("event count = %d, want %d", len(events), len(tc.want))
			}
			for i := range tc.want {
				checkFields(t, events[i].fields, tc.want[i])
			}
		})
	}
}

func TestSSEParserAnySplit(t *testing.T) {
	bodies := []string{
		"data: one\ndata: two\n\n",
		"data: one\r\ndata: two\r\n\r\n",
		"data: one\rdata: two\r\r",
		"\xef\xbb\xbfevent: message\ndata: a\n\ndata: b\n\n",
		": a\ndata: one\n: b\ndata: two\n\n",
		"data\ndata:  x\n\n\n",
	}
	for i, body := range bodies {
		t.Run(fmt.Sprintf("body %d", i), func(t *testing.T) {
			raw := []byte(body)
			want := parseChunks(t, [][]byte{raw})

			sameEvents(t, parseChunks(t, [][]byte{raw}), want)

			oneByOne := make([][]byte, len(raw))
			for j := range raw {
				oneByOne[j] = raw[j : j+1]
			}
			sameEvents(t, parseChunks(t, oneByOne), want)

			for split := 1; split < len(raw); split++ {
				sameEvents(t, parseChunks(t, [][]byte{raw[:split], raw[split:]}), want)
			}
		})
	}
}

// TestSSEParserCompletionOffset pins the end offset of one event: the index of
// the byte that completed its terminating blank line, counted in body bytes
// after the BOM was stripped (2.6, 4.5). The LF that closes "data: a\n\n"
// sits at stripped index 8, and a leading BOM leaves that index unchanged.
func TestSSEParserCompletionOffset(t *testing.T) {
	t.Run("LF closes the event at the final LF", func(t *testing.T) {
		body := []byte("data: a\n\n")
		events := parseChunks(t, [][]byte{body})
		if len(events) != 1 {
			t.Fatalf("event count = %d, want 1", len(events))
		}
		if got := events[0].end; got != 8 {
			t.Fatalf("end = %d, want 8", got)
		}
	})

	t.Run("CRLF closes the event only at the final LF", func(t *testing.T) {
		body := []byte("data: a\r\n\r\n")
		p := newSSEParser(0)
		var events []event
		emit := func(ev event) error {
			events = append(events, ev)
			return nil
		}
		if err := p.feed(body[:len(body)-1], emit); err != nil {
			t.Fatalf("feed: %v", err)
		}
		if len(events) != 0 {
			t.Fatalf("emitted %d events before the final LF", len(events))
		}
		if err := p.feed(body[len(body)-1:], emit); err != nil {
			t.Fatalf("feed: %v", err)
		}
		if len(events) != 1 {
			t.Fatalf("event count = %d, want 1", len(events))
		}
		if got := events[0].end; got != 10 {
			t.Fatalf("end = %d, want 10", got)
		}
	})

	t.Run("lone CR closes the event at the second CR", func(t *testing.T) {
		body := []byte("data: a\r\r")
		p := newSSEParser(0)
		var events []event
		emit := func(ev event) error {
			events = append(events, ev)
			return nil
		}
		if err := p.feed(body, emit); err != nil {
			t.Fatalf("feed: %v", err)
		}
		if len(events) != 0 {
			t.Fatalf("emitted %d events before the pending CR was resolved", len(events))
		}
		// reset resolves the pending lone CR, which ended the blank line.
		p.reset()
		if len(events) != 1 {
			t.Fatalf("event count after reset = %d, want 1", len(events))
		}
		if got := events[0].end; got != 8 {
			t.Fatalf("end = %d, want 8", got)
		}
	})

	t.Run("a leading BOM is not counted", func(t *testing.T) {
		body := append([]byte("\xef\xbb\xbf"), []byte("data: a\n\n")...)
		events := parseChunks(t, [][]byte{body})
		if len(events) != 1 {
			t.Fatalf("event count = %d, want 1", len(events))
		}
		// The stripped BOM leaves the count untouched: the same event without
		// the BOM is also reported as 8 above.
		if got := events[0].end; got != 8 {
			t.Fatalf("end = %d, want 8", got)
		}
	})

	t.Run("a body without a BOM reports the same end", func(t *testing.T) {
		plain := []byte("data: a\n\n")
		withBOM := append([]byte("\xef\xbb\xbf"), plain...)
		plainEvents := parseChunks(t, [][]byte{plain})
		bomEvents := parseChunks(t, [][]byte{withBOM})
		if len(plainEvents) != 1 || len(bomEvents) != 1 {
			t.Fatalf("event counts = %d, %d, want 1, 1", len(plainEvents), len(bomEvents))
		}
		if plainEvents[0].end != 8 || bomEvents[0].end != 8 {
			t.Fatalf("end = %d, %d, want 8, 8", plainEvents[0].end, bomEvents[0].end)
		}
		if plainEvents[0].end != bomEvents[0].end {
			t.Fatalf("end = %d without a BOM, %d with one; want the same", plainEvents[0].end, bomEvents[0].end)
		}
	})
}

func TestSSEParserBudget(t *testing.T) {
	// over is 32 data bytes, twice the 16-byte budget of the parser below.
	over := append([]byte("data: "), bytes.Repeat([]byte("x"), 32)...)
	over = append(over, '\n', '\n')

	t.Run("event over the budget is dropped", func(t *testing.T) {
		p := newSSEParser(16)
		var events []event
		emit := func(ev event) error {
			events = append(events, ev)
			return nil
		}
		if err := p.feed(over, emit); err != nil {
			t.Fatalf("feed: %v", err)
		}
		if !p.exceeded {
			t.Fatal("exceeded = false, want true")
		}
		if len(events) != 0 {
			t.Fatalf("emitted %d events over the budget", len(events))
		}
	})

	t.Run("no budget emits the same event", func(t *testing.T) {
		events := parseChunks(t, [][]byte{over})
		if len(events) != 1 {
			t.Fatalf("event count = %d, want 1", len(events))
		}
		checkFields(t, events[0].fields, []field{{name: "data", value: bytes.Repeat([]byte("x"), 32)}})
	})

	t.Run("legal body stays under the frame budget", func(t *testing.T) {
		legal := append([]byte("data: "), bytes.Repeat([]byte("y"), 16)...)
		legal = append(legal, '\n', '\n')
		p := newSSEParser(16 + maxEventOverhead)
		var events []event
		emit := func(ev event) error {
			events = append(events, ev)
			return nil
		}
		if err := p.feed(legal, emit); err != nil {
			t.Fatalf("feed: %v", err)
		}
		if p.exceeded {
			t.Fatal("exceeded = true under the 16+1024 budget")
		}
		if len(events) != 1 {
			t.Fatalf("event count = %d, want 1", len(events))
		}
		checkFields(t, events[0].fields, []field{{name: "data", value: bytes.Repeat([]byte("y"), 16)}})
	})
}

func TestVerifierCommentTrickleIdle(t *testing.T) {
	const base = int64(1_700_000_000)
	b := newStream(t, base)
	value := b.open(base)
	b.frame(base, "hello")
	body := append([]byte(nil), b.bytes()...)
	arrival := make([]time.Time, len(body))
	for i := range arrival {
		arrival[i] = time.Unix(base, 0)
	}
	for second := 1; second <= 100; second++ {
		line := []byte(": ping\n")
		start := len(body)
		body = append(body, line...)
		at := time.Unix(base+int64(second), 0)
		for i := start; i < len(body); i++ {
			arrival = append(arrival, at)
		}
	}
	exp := b.expectation(t, base)
	exp.StreamIdle = 90 * time.Second
	exp.FrameNow = func(int) time.Time { return time.Unix(base, 0) }
	exp.Arrival = func(offset int) time.Time { return arrival[offset] }
	v := openVerifier(t, exp, openHeaders(value))
	if err := v.Feed(body); err != nil {
		t.Fatalf("Feed: %v", err)
	}
	err := v.Finish()
	wantCode(t, err, Idle, 1)
	res := v.Result()
	if res.FramesVerified != 1 || !equalStrings(res.Messages, []string{"hello"}) {
		t.Fatalf("result = %+v, want 1 frame and [hello]", res)
	}
}

func TestVerifierNextReleasesMessages(t *testing.T) {
	const base = int64(1_700_000_000)
	b := newStream(t, base)
	value := b.open(base)
	b.frame(base, "one")
	b.frame(base, "two")
	b.frame(base, "")
	v := openVerifier(t, b.expectation(t, base), openHeaders(value))
	if err := v.Feed(b.bytes()); err != nil {
		t.Fatalf("Feed: %v", err)
	}
	if err := v.Finish(); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	for i, want := range []string{"one", "two"} {
		got, ok := v.Next()
		if !ok || got != want {
			t.Fatalf("Next() = %q, %t; want %q, true", got, ok, want)
		}
		if got := v.Messages(); len(got) != 1-i {
			t.Fatalf("Messages() = %q, want %d remaining", got, 1-i)
		}
	}
	if got, ok := v.Next(); ok || got != "" {
		t.Fatalf("Next() = %q, %t; want empty, false", got, ok)
	}
	res := v.Result()
	if len(v.Messages()) != 0 || len(res.Messages) != 0 {
		t.Fatalf("messages after consumption = %q, result = %q; want empty", v.Messages(), res.Messages)
	}
	if !res.Complete || res.FramesVerified != 3 {
		t.Fatalf("result = %+v, want complete with 3 frames", res)
	}
}
