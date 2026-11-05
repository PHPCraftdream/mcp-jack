package server

import (
	"encoding/json"
	"io"
	"sync"
)

// Audit outcome values.
const (
	AuditSuccess = "success"
	AuditFailure = "failure"
)

// AuditEvent is one audit record. It deliberately carries nothing that could
// hold an invite code or a private key: 03-user-management.md section 8
// requires time, caller kid and name, tool, target, outcome and failure code.
type AuditEvent struct {
	Time      int64  `json:"time"`
	Tool      string `json:"tool"`
	Outcome   string `json:"outcome"`
	Code      string `json:"code,omitempty"`
	ActorKid  string `json:"actor_kid"`
	ActorName string `json:"actor_name,omitempty"`
	Target    string `json:"target,omitempty"`
}

// AuditSink receives audit events.
type AuditSink interface {
	Record(event AuditEvent) error
}

// MemoryAuditSink keeps audit events in memory. Record always succeeds.
type MemoryAuditSink struct {
	mu     sync.Mutex
	events []AuditEvent
}

// Compile-time check that MemoryAuditSink satisfies AuditSink.
var _ AuditSink = (*MemoryAuditSink)(nil)

// NewMemoryAuditSink returns an empty in-memory audit sink.
func NewMemoryAuditSink() *MemoryAuditSink {
	return &MemoryAuditSink{}
}

// Record appends the event under a mutex and always succeeds.
func (s *MemoryAuditSink) Record(event AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
	return nil
}

// Events returns a copy of the recorded events.
func (s *MemoryAuditSink) Events() []AuditEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]AuditEvent, len(s.events))
	copy(out, s.events)
	return out
}

// JSONLAuditSink writes one compact JSON object per line to an io.Writer,
// guarded by a mutex so concurrent records never interleave.
type JSONLAuditSink struct {
	mu  sync.Mutex
	enc *json.Encoder
}

// Compile-time check that JSONLAuditSink satisfies AuditSink.
var _ AuditSink = (*JSONLAuditSink)(nil)

// NewJSONLAuditSink returns a sink writing JSON lines to w.
func NewJSONLAuditSink(w io.Writer) *JSONLAuditSink {
	enc := json.NewEncoder(w)
	return &JSONLAuditSink{enc: enc}
}

// Record encodes one event as a JSON object followed by a newline and returns
// the encoder error, if any.
func (s *JSONLAuditSink) Record(event AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enc.Encode(event)
}
