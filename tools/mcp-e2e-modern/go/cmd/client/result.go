package main

// Result schema, progress recorder, and stdout emission (CONTRACT.md client
// result record).

import (
	"encoding/json"
	"sync"
	"time"
)

func after(ms int64) <-chan time.Time { return time.After(time.Duration(ms) * time.Millisecond) }

type sdkID struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type bridgeInfo struct {
	Spawned       bool   `json:"spawned"`
	ExitCode      *int   `json:"exit_code"`
	CloseObserved bool   `json:"close_observed"`
	StdoutBytes   int64  `json:"stdout_bytes"`
	StderrTail    string `json:"stderr_tail"`
}

type progressObs struct {
	Progress float64  `json:"progress"`
	Total    *float64 `json:"total,omitempty"`
}

type releaseEvidence struct {
	Observed bool            `json:"observed"`
	Status   int             `json:"status"`
	Body     json.RawMessage `json:"body"`
}

type timings struct {
	StartedMs    int64  `json:"started_ms"`
	FirstEventMs *int64 `json:"first_event_ms"`
	CompletedMs  *int64 `json:"completed_ms"`
	CancelledMs  *int64 `json:"cancelled_ms"`
}

type result struct {
	Scenario           int              `json:"scenario"`
	SDK                sdkID            `json:"sdk"`
	Outcome            string           `json:"outcome"`
	ToolResult         json.RawMessage  `json:"tool_result"`
	SDKError           *string          `json:"sdk_error"`
	RequestMeta        any              `json:"request_meta"`
	Bridge             bridgeInfo       `json:"bridge"`
	Progress           []progressObs    `json:"progress"`
	Release            *releaseEvidence `json:"release,omitempty"`
	CapabilityEvidence *string          `json:"capability_evidence"`
	Timings            timings          `json:"timings"`
}

func marshalResult(r result) ([]byte, error) { return json.Marshal(r) }

// recorder collects progress notifications in delivery order and the elapsed
// time of the first one.
type recorder struct {
	mu            sync.Mutex
	order         []progressObs
	firstMs       *int64
	now           func() int64
	observed      chan struct{}
	observedOnce  sync.Once
	releaseSignal chan struct{}
}

func newRecorder(now func() int64) *recorder {
	return &recorder{observed: make(chan struct{}), now: now}
}

func (r *recorder) add(p progressObs) {
	ms := r.now()
	r.mu.Lock()
	if r.firstMs == nil {
		first := ms
		r.firstMs = &first
	}
	r.order = append(r.order, p)
	r.mu.Unlock()
	r.observedOnce.Do(func() { close(r.observed) })
}

func (r *recorder) snapshot() ([]progressObs, *int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]progressObs, len(r.order))
	copy(out, r.order)
	return out, r.firstMs
}

// waitObserved blocks until the first progress notification or the timeout.
func (r *recorder) waitObserved(timeoutMs int64) bool {
	select {
	case <-r.observed:
		return true
	case <-after(timeoutMs):
		return false
	}
}
