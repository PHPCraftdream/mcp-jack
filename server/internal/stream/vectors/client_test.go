package streamvectors

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"testing"
	"time"

	clientstream "github.com/PHPCraftdream/mcp-jack/client/stream"
)

// bodyBOM is the byte order mark 2.14 ignores once at the start of the body.
var bodyBOM = []byte{0xef, 0xbb, 0xbf}

// clientCorpus is spec/fixtures/modern/stream-vectors.json.
type clientCorpus struct {
	Note  string       `json:"note"`
	Cases []clientCase `json:"cases"`
}

// clientCase is one client verification vector.
type clientCase struct {
	ID            string         `json:"id"`
	Description   string         `json:"description"`
	State         clientState    `json:"state"`
	Response      clientResponse `json:"response"`
	SilentAfterMS *int64         `json:"silent_after_ms"`
	ArrivalMS     []int64        `json:"arrival_ms"`
	Consumer      string         `json:"consumer"`
	DataFill      *dataFill      `json:"data_fill"`
	Expect        clientExpect   `json:"expect"`
}

// clientState is the client state the vector verifies against.
type clientState struct {
	Now                   int64           `json:"now"`
	WindowSeconds         int64           `json:"window_seconds"`
	PinnedServerKid       string          `json:"pinned_server_kid"`
	PinnedServerPublicKey string          `json:"pinned_server_public_key"`
	RequestSig            string          `json:"request_sig"`
	RequestID             json.RawMessage `json:"request_id"`
	SuccessorActivation   *int64          `json:"successor_activation"`
	FrameMaxBytes         int64           `json:"frame_max_bytes"`
	FrameNows             []int64         `json:"frame_nows"`
	StreamIdleMS          int64           `json:"stream_idle_ms"`
}

// clientResponse is the answer the vector feeds, one base64url chunk at a time.
type clientResponse struct {
	Status     int        `json:"status"`
	Headers    [][]string `json:"headers"`
	StreamB64U []string   `json:"stream_b64u"`
}

// clientExpect is the outcome the vector demands.
type clientExpect struct {
	Messages []json.RawMessage `json:"messages"`
	Terminal struct {
		State          string `json:"state"`
		Code           string `json:"code"`
		FramesVerified int    `json:"frames_verified"`
	} `json:"terminal"`
	MCPComplete *bool `json:"mcp_complete"`
}

// feed is one Feed call: the body bytes body[start:end] arriving at once.
type feed struct {
	start int
	end   int
}

// strategy is one way of cutting the body into feeds.
type strategy struct {
	name  string
	feeds []feed
}

// TestStreamVectors runs every client verification vector of 4.2-4.5, 5.2 and
// 6.1-6.3 through the public verifier under every feed split.
func TestStreamVectors(t *testing.T) {
	var corpus clientCorpus
	if err := json.Unmarshal(fixtureFile(t, "stream-vectors.json"), &corpus); err != nil {
		t.Fatalf("decode stream-vectors.json: %v", err)
	}
	if len(corpus.Cases) != 80 {
		t.Fatalf("stream-vectors.json: want 80 cases, got %d", len(corpus.Cases))
	}
	pass := 0
	for _, c := range corpus.Cases {
		body, arrival := expandBody(t, c)
		want := make([]string, 0, len(c.Expect.Messages))
		for _, raw := range c.Expect.Messages {
			want = append(want, expandMessage(t, raw, c.DataFill))
		}
		type runResult struct {
			messages       []string
			frames         int
			complete       bool
			code           string
			terminalFrames int
		}
		var baseline *runResult
		for _, st := range clientStrategies(body, arrival) {
			messages, err, v := runClientCase(t, c, body, arrival, st)
			checkClientCase(t, c, st.name, messages, want, err, v)
			got := runResult{messages: messages, frames: v.FramesVerified(), complete: v.Complete()}
			var terminal *clientstream.Error
			if errors.As(err, &terminal) {
				got.code = string(terminal.Code)
				got.terminalFrames = terminal.FramesVerified
			}
			if baseline == nil {
				baseline = &got
			} else if !slices.Equal(baseline.messages, got.messages) || baseline.frames != got.frames ||
				baseline.complete != got.complete || baseline.code != got.code || baseline.terminalFrames != got.terminalFrames {
				t.Fatalf("case %s (%s): strategy result differs from whole-body result", c.ID, st.name)
			}
		}
		pass++
	}
	summary(t, "stream", pass)
}

// expandBody concatenates the expanded chunks and records, for every body
// byte, the arrival of the vector chunk that carried it: milliseconds after
// the open header was verified, 0 when the case gives no arrival_ms.
func expandBody(t *testing.T, c clientCase) (body []byte, arrival []int64) {
	t.Helper()
	chunks := expandChunks(t, c.Response.StreamB64U, c.DataFill)
	for i, chunk := range chunks {
		at := int64(0)
		if len(c.ArrivalMS) > 0 {
			at = c.ArrivalMS[min(i, len(c.ArrivalMS)-1)]
		}
		body = append(body, chunk...)
		for range chunk {
			arrival = append(arrival, at)
		}
	}
	return body, arrival
}

// clientStrategies returns the three feed splits of one body, for every case
// and independently of its arrival times: whole, one feed of the whole body;
// byte, one feed per body byte; and frame, feeds cut after every
// event-terminating blank line. A single feed can carry only one arrival time,
// so the frame split is cut at arrival boundaries as well: no feed ever mixes
// two of the vector's arrival times. Every verified time comes from
// Expectation.Arrival, so the split cannot change the result (4.5).
func clientStrategies(body []byte, arrival []int64) []strategy {
	return []strategy{
		{name: "whole", feeds: feedsFromCuts([]int{0, len(body)}, len(body))},
		{name: "byte", feeds: feedsFromCuts(everyCut(len(body)), len(body))},
		{name: "frame", feeds: feedsFromCuts(frameCuts(body, arrival), len(body))},
	}
}

// everyCut returns the cut after every body byte.
func everyCut(size int) []int {
	cuts := make([]int, 0, size+1)
	for i := 0; i <= size; i++ {
		cuts = append(cuts, i)
	}
	return cuts
}

// frameCuts returns the cut positions of the frame split: after every blank
// line that completes an event, and at every arrival-time change. A terminator
// is a lone LF, a CRLF pair or a lone CR (2.14), so the scanner tracks whether
// the last terminator already ended an empty line and cuts at the end of the
// second one.
func frameCuts(body []byte, arrival []int64) []int {
	cuts := []int{0, len(body)}
	empty := false // the last terminator already ended an empty line
	for i := 0; i < len(body); {
		if body[i] != '\n' && body[i] != '\r' {
			empty = false
			i++
			continue
		}
		end := i + 1 // a lone LF or a lone CR is one terminator
		if body[i] == '\r' && end < len(body) && body[end] == '\n' {
			end++ // a CRLF pair is one terminator
		}
		if empty {
			cuts = append(cuts, end) // the second terminator ends the event
		}
		empty = true
		i = end
	}
	for p := 1; p < len(body) && p < len(arrival); p++ {
		if arrival[p] != arrival[p-1] {
			cuts = append(cuts, p)
		}
	}
	return cuts
}

// feedsFromCuts returns the feeds between the ascending cut positions, the
// empty first feed and the duplicate cuts dropped.
func feedsFromCuts(cuts []int, size int) []feed {
	sort.Ints(cuts)
	feeds := make([]feed, 0, len(cuts))
	start := 0
	for _, cut := range cuts {
		if cut <= start || cut > size {
			continue
		}
		feeds = append(feeds, feed{start: start, end: cut})
		start = cut
	}
	if start < size {
		feeds = append(feeds, feed{start: start, end: size})
	}
	return feeds
}

// runClientCase verifies one case under one feed split: the open header at the
// case's now, then every feed, then Finish or ObserveLive. The clock stays
// pinned at the case's now; every arrival comes from Expectation.Arrival, so
// the feed split cannot move a clock sample.
func runClientCase(t *testing.T, c clientCase, body []byte, arrival []int64, st strategy) ([]string, error, *clientstream.Verifier) {
	t.Helper()
	base := time.Unix(c.State.Now, 0)
	clock := &scriptedClock{at: base}
	keys := map[string]clientstream.Key{
		c.State.PinnedServerKid: {
			PublicKey:           b64u(t, c.State.PinnedServerPublicKey),
			SuccessorActivation: c.State.SuccessorActivation,
		},
	}
	// Arrival is indexed in body bytes after the stripped BOM (4.5), while
	// arrival records every raw body byte: drop the BOM bytes so both sides
	// count from the same byte.
	if bytes.HasPrefix(body, bodyBOM) {
		arrival = arrival[len(bodyBOM):]
	}
	exp := clientstream.Expectation{
		Now:           clock.Now,
		Window:        time.Duration(c.State.WindowSeconds) * time.Second,
		Keys:          keys,
		RequestSig:    c.State.RequestSig,
		FrameMaxBytes: c.State.FrameMaxBytes,
		StreamIdle:    time.Duration(c.State.StreamIdleMS) * time.Millisecond,
		Consumer:      clientstream.Consumer(c.Consumer),
		Arrival: func(offset int) time.Time {
			if len(arrival) == 0 {
				return base
			}
			if offset >= len(arrival) {
				offset = len(arrival) - 1
			}
			return base.Add(time.Duration(arrival[offset]) * time.Millisecond)
		},
	}
	if len(c.State.FrameNows) > 0 {
		frameNows := c.State.FrameNows
		exp.FrameNow = func(index int) time.Time {
			return time.Unix(frameNows[min(index, len(frameNows)-1)], 0)
		}
	}
	v, err := clientstream.NewVerifier(exp)
	if err != nil {
		t.Fatalf("case %s (%s): new verifier: %v", c.ID, st.name, err)
	}
	headers := make([]clientstream.Header, 0, len(c.Response.Headers))
	for _, h := range c.Response.Headers {
		headers = append(headers, clientstream.Header{Name: h[0], Value: h[1]})
	}
	err = v.Open(c.Response.Status, headers)
	if err == nil {
		for _, f := range st.feeds {
			if err = v.Feed(body[f.start:f.end]); err != nil {
				break
			}
		}
	}
	if err == nil {
		if c.SilentAfterMS != nil {
			err = v.ObserveLive(time.Duration(*c.SilentAfterMS) * time.Millisecond)
		} else {
			err = v.Finish()
		}
	}
	return v.Messages(), err, v
}

// checkClientCase compares one run of one strategy with the vector.
func checkClientCase(t *testing.T, c clientCase, strategyName string, messages, want []string, err error, v *clientstream.Verifier) {
	t.Helper()
	if !slices.Equal(messages, want) {
		t.Fatalf("case %s (%s): messages differ\ngot:  %q\nwant: %q", c.ID, strategyName, messages, want)
	}
	if c.Expect.Terminal.State == "ok" {
		if err != nil {
			t.Fatalf("case %s (%s): want ok terminal, got %v", c.ID, strategyName, err)
		}
		if c.SilentAfterMS == nil && !v.Complete() {
			t.Fatalf("case %s (%s): ok terminal without a verified end frame", c.ID, strategyName)
		}
	} else {
		var terminal *clientstream.Error
		if !errors.As(err, &terminal) {
			t.Fatalf("case %s (%s): want terminal %s after %d frames, got %v",
				c.ID, strategyName, c.Expect.Terminal.Code, c.Expect.Terminal.FramesVerified, err)
		}
		if string(terminal.Code) != c.Expect.Terminal.Code {
			t.Fatalf("case %s (%s): terminal code %s, want %s", c.ID, strategyName, terminal.Code, c.Expect.Terminal.Code)
		}
		if terminal.FramesVerified != c.Expect.Terminal.FramesVerified {
			t.Fatalf("case %s (%s): terminal frames_verified %d, want %d",
				c.ID, strategyName, terminal.FramesVerified, c.Expect.Terminal.FramesVerified)
		}
		if got := v.FramesVerified(); got != c.Expect.Terminal.FramesVerified {
			t.Fatalf("case %s (%s): verifier frames_verified %d, want %d",
				c.ID, strategyName, got, c.Expect.Terminal.FramesVerified)
		}
	}
	if c.Expect.MCPComplete != nil {
		complete := err == nil && c.SilentAfterMS == nil && len(messages) > 0 &&
			isRPCResponse(t, messages[len(messages)-1], c.State.RequestID)
		if complete != *c.Expect.MCPComplete {
			t.Fatalf("case %s (%s): mcp_complete %t, want %t", c.ID, strategyName, complete, *c.Expect.MCPComplete)
		}
	}
}
