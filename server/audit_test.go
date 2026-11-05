package server

import (
	"bytes"
	"encoding/json"
	"sync"
	"testing"
)

func auditTestEvent(outcome, code string) AuditEvent {
	return AuditEvent{
		Time:     1767225500,
		Tool:     "tools/call",
		Outcome:  outcome,
		Code:     code,
		ActorKid: "k1",
	}
}

// TestMemoryAuditSinkOrderAndCopy checks ordering and that Events returns a copy.
func TestMemoryAuditSinkOrderAndCopy(t *testing.T) {
	sink := NewMemoryAuditSink()
	success := auditTestEvent(AuditSuccess, "")
	failure := auditTestEvent(AuditFailure, "E_INVITE_EXPIRED")
	if err := sink.Record(success); err != nil {
		t.Fatalf("record success: %v", err)
	}
	if err := sink.Record(failure); err != nil {
		t.Fatalf("record failure: %v", err)
	}
	events := sink.Events()
	if len(events) != 2 {
		t.Fatalf("len(events) = %d, want 2", len(events))
	}
	if events[0].Outcome != AuditSuccess || events[1].Outcome != AuditFailure {
		t.Fatalf("events out of order: %+v", events)
	}

	// Mutating the returned slice must not affect the sink.
	events[0].Tool = "MUTATED"
	events[0].ActorKid = "MUTATED"
	again := sink.Events()
	if again[0].Tool != "tools/call" || again[0].ActorKid != "k1" {
		t.Fatalf("sink affected by caller mutation: %+v", again[0])
	}
}

// TestJSONLSinkFieldSets checks which keys appear per event and the one-line
// format.
func TestJSONLSinkFieldSets(t *testing.T) {
	var buf bytes.Buffer
	sink := NewJSONLAuditSink(&buf)

	if err := sink.Record(auditTestEvent(AuditSuccess, "")); err != nil {
		t.Fatalf("record success: %v", err)
	}
	if err := sink.Record(func() AuditEvent {
		ev := auditTestEvent(AuditFailure, "E_POLICY")
		ev.Target = "file:/tmp/x"
		return ev
	}()); err != nil {
		t.Fatalf("record failure: %v", err)
	}

	out := buf.String()
	if got := bytes.Count(buf.Bytes(), []byte{'\n'}); got != 2 {
		t.Fatalf("newline count = %d, want 2; output: %q", got, out)
	}

	lines := bytes.Split(bytes.TrimSuffix(buf.Bytes(), []byte{'\n'}), []byte{'\n'})
	if len(lines) != 2 {
		t.Fatalf("line count = %d, want 2", len(lines))
	}

	var success map[string]any
	if err := json.Unmarshal(lines[0], &success); err != nil {
		t.Fatalf("unmarshal success line: %v", err)
	}
	wantKeys := map[string]bool{"time": true, "tool": true, "outcome": true, "actor_kid": true}
	if len(success) != len(wantKeys) {
		t.Fatalf("success keys = %v, want exactly %v", success, wantKeys)
	}
	for k := range wantKeys {
		if _, ok := success[k]; !ok {
			t.Errorf("success line missing key %s: %v", k, success)
		}
	}
	if success["outcome"] != AuditSuccess || success["actor_kid"] != "k1" {
		t.Errorf("success values wrong: %v", success)
	}

	var failure map[string]any
	if err := json.Unmarshal(lines[1], &failure); err != nil {
		t.Fatalf("unmarshal failure line: %v", err)
	}
	wantKeysFail := map[string]bool{"time": true, "tool": true, "outcome": true, "code": true, "actor_kid": true, "target": true}
	if len(failure) != len(wantKeysFail) {
		t.Fatalf("failure keys = %v, want exactly %v", failure, wantKeysFail)
	}
	for k := range wantKeysFail {
		if _, ok := failure[k]; !ok {
			t.Errorf("failure line missing key %s: %v", k, failure)
		}
	}
	if failure["code"] != "E_POLICY" || failure["target"] != "file:/tmp/x" {
		t.Errorf("failure values wrong: %v", failure)
	}
}

// TestAuditEventNoSecretKeys pins that an AuditEvent can only serialize the
// seven audited fields — nothing that could carry an invite code or a private
// key.
func TestAuditEventNoSecretKeys(t *testing.T) {
	event := AuditEvent{
		Time:      1767225500,
		Tool:      "tools/call",
		Outcome:   AuditFailure,
		Code:      "E_POLICY",
		ActorKid:  "k1",
		ActorName: "alice",
		Target:    "file:/tmp/x",
	}
	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var keys map[string]any
	if err := json.Unmarshal(data, &keys); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	allowed := map[string]bool{
		"time": true, "tool": true, "outcome": true, "code": true,
		"actor_kid": true, "actor_name": true, "target": true,
	}
	for k := range keys {
		if !allowed[k] {
			t.Errorf("unexpected key %q in marshaled audit event", k)
		}
	}
}

// TestJSONLSinkConcurrent checks concurrent records never interleave.
func TestJSONLSinkConcurrent(t *testing.T) {
	var buf bytes.Buffer
	sink := NewJSONLAuditSink(&buf)
	const writers = 50
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sink.Record(auditTestEvent(AuditSuccess, ""))
		}()
	}
	wg.Wait()

	data := bytes.TrimSuffix(buf.Bytes(), []byte{'\n'})
	lines := bytes.Split(data, []byte{'\n'})
	if len(lines) != writers {
		t.Fatalf("line count = %d, want %d", len(lines), writers)
	}
	for i, line := range lines {
		var ev AuditEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			t.Fatalf("line %d is not valid JSON (%v): %q", i, err, line)
		}
		if ev.Outcome != AuditSuccess || ev.ActorKid != "k1" {
			t.Fatalf("line %d corrupt: %q", i, line)
		}
	}
}
