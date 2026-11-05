//! Audit records and the AuditSink trait (Go: server/audit.go).

use crate::error::JackError;
use std::io::Write;
use std::sync::{Mutex, MutexGuard};

/// Successful operation (audit `outcome` value).
pub const AUDIT_SUCCESS: &str = "success";
/// Failed operation (audit `outcome` value).
pub const AUDIT_FAILURE: &str = "failure";

/// One audit record. It deliberately carries nothing that could hold an
/// invite code or a private key: spec 03 section 8 requires only time,
/// caller kid and name, tool, target, outcome and failure code. Field order
/// is the Go struct order, hence serde's JSON emission order; empty optional
/// fields are omitted (Go `omitempty`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct AuditEvent {
    /// Unix seconds of the event.
    pub time: i64,
    /// Protocol tool name invoked.
    pub tool: String,
    /// `success` or `failure`.
    pub outcome: String,
    /// Spec failure code; omitted when empty.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub code: String,
    /// Key id of the caller.
    pub actor_kid: String,
    /// Registry name of the caller; omitted when empty.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub actor_name: String,
    /// Addressed object; omitted when empty.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub target: String,
}

/// Receives audit events (Go: AuditSink). Object-safe so `Arc<dyn AuditSink>`
/// works; `JsonlAuditSink<W>` is Sync via `Mutex<W>` iff `W: Send`, hence the
/// `W: Write + Send` bound below.
pub trait AuditSink: Send + Sync {
    fn record(&self, event: AuditEvent) -> Result<(), JackError>;
}

/// In-memory audit sink; `record` always succeeds.
pub struct MemoryAuditSink {
    events: Mutex<Vec<AuditEvent>>,
}

impl MemoryAuditSink {
    /// Returns an empty in-memory audit sink.
    pub fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
        }
    }

    /// A copy of the recorded events in record order.
    pub fn events(&self) -> Vec<AuditEvent> {
        Self::lock(&self.events).clone()
    }

    /// A panic here can only come from a Vec append (allocation failure);
    /// the buffer is an append-only list of plain values with no cross-
    /// invariant, so recovering cannot expose broken state.
    fn lock(events: &Mutex<Vec<AuditEvent>>) -> MutexGuard<'_, Vec<AuditEvent>> {
        events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl Default for MemoryAuditSink {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditSink for MemoryAuditSink {
    fn record(&self, event: AuditEvent) -> Result<(), JackError> {
        Self::lock(&self.events).push(event);
        Ok(())
    }
}

/// Writes one compact JSON object per line to a `Write`, guarded by a mutex
/// so concurrent records never interleave.
pub struct JsonlAuditSink<W: Write + Send> {
    writer: Mutex<W>,
}

impl<W: Write + Send> JsonlAuditSink<W> {
    /// Returns a sink writing JSON lines to `w`.
    pub fn new(w: W) -> Self {
        Self {
            writer: Mutex::new(w),
        }
    }

    /// Same poison rationale as `MemoryAuditSink::lock`: a panic can only
    /// come from allocation inside `write_all`, and a byte stream has no
    /// cross-invariant to break.
    fn lock(writer: &Mutex<W>) -> MutexGuard<'_, W> {
        writer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl<W: Write + Send> AuditSink for JsonlAuditSink<W> {
    fn record(&self, event: AuditEvent) -> Result<(), JackError> {
        // to_string cannot fail for this field set (strings + i64, no maps),
        // but errors are mapped rather than unwrapped.
        let line = serde_json::to_string(&event)
            .map_err(|e| JackError::new(500, "internal", format!("audit encode failed: {e}")))?;
        let mut w = Self::lock(&self.writer);
        w.write_all(line.as_bytes())
            .map_err(|e| JackError::new(500, "internal", format!("audit write failed: {e}")))?;
        w.write_all(b"\n")
            .map_err(|e| JackError::new(500, "internal", format!("audit write failed: {e}")))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn test_event(outcome: &str, code: &str) -> AuditEvent {
        AuditEvent {
            time: 1767225500,
            tool: "tools/call".to_owned(),
            outcome: outcome.to_owned(),
            code: code.to_owned(),
            actor_kid: "k1".to_owned(),
            actor_name: String::new(),
            target: String::new(),
        }
    }

    #[test]
    fn memory_sink_order_and_copy() {
        let sink = MemoryAuditSink::new();
        sink.record(test_event(AUDIT_SUCCESS, "")).unwrap();
        sink.record(test_event(AUDIT_FAILURE, "E_INVITE_EXPIRED"))
            .unwrap();

        let events = sink.events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].outcome, AUDIT_SUCCESS);
        assert_eq!(events[1].outcome, AUDIT_FAILURE);

        // Mutating the returned vec must not affect the sink.
        let mut events = events;
        events[0].tool = "MUTATED".to_owned();
        events[0].actor_kid = "MUTATED".to_owned();
        let again = sink.events();
        assert_eq!(again[0].tool, "tools/call");
        assert_eq!(again[0].actor_kid, "k1");
    }

    #[test]
    fn jsonl_sink_field_sets() {
        let mut buf = Vec::new();
        let sink = JsonlAuditSink::new(&mut buf);

        let mut failure = test_event(AUDIT_FAILURE, "E_POLICY");
        failure.target = "file:/tmp/x".to_owned();
        sink.record(test_event(AUDIT_SUCCESS, "")).unwrap();
        sink.record(failure).unwrap();

        let out = String::from_utf8(buf).unwrap();
        assert_eq!(out.matches('\n').count(), 2);
        let lines: Vec<&str> = out.trim_end_matches('\n').split('\n').collect();
        assert_eq!(lines.len(), 2);

        let success: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        let success_keys: BTreeSet<&str> = success
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        let want_success: BTreeSet<&str> = ["time", "tool", "outcome", "actor_kid"]
            .into_iter()
            .collect();
        assert_eq!(success_keys, want_success);
        assert_eq!(success["outcome"], AUDIT_SUCCESS);
        assert_eq!(success["actor_kid"], "k1");

        let failure: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        let failure_keys: BTreeSet<&str> = failure
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        let want_failure: BTreeSet<&str> =
            ["time", "tool", "outcome", "code", "actor_kid", "target"]
                .into_iter()
                .collect();
        assert_eq!(failure_keys, want_failure);
        assert_eq!(failure["code"], "E_POLICY");
        assert_eq!(failure["target"], "file:/tmp/x");
    }

    #[test]
    fn audit_event_json_pins() {
        let minimal = test_event(AUDIT_SUCCESS, "");
        assert_eq!(
            serde_json::to_string(&minimal).unwrap(),
            r#"{"time":1767225500,"tool":"tools/call","outcome":"success","actor_kid":"k1"}"#
        );

        let mut full = test_event(AUDIT_FAILURE, "E_POLICY");
        full.actor_name = "alice".to_owned();
        full.target = "file:/tmp/x".to_owned();
        assert_eq!(
            serde_json::to_string(&full).unwrap(),
            r#"{"time":1767225500,"tool":"tools/call","outcome":"failure","code":"E_POLICY","actor_kid":"k1","actor_name":"alice","target":"file:/tmp/x"}"#
        );
    }

    #[test]
    fn jsonl_sink_concurrent() {
        let mut buf = Vec::new();
        let sink = JsonlAuditSink::new(&mut buf);
        let lines = AtomicUsize::new(0);
        std::thread::scope(|s| {
            for _ in 0..50 {
                s.spawn(|| {
                    sink.record(test_event(AUDIT_SUCCESS, "")).unwrap();
                    lines.fetch_add(1, Ordering::SeqCst);
                });
            }
        });
        assert_eq!(lines.load(Ordering::SeqCst), 50);

        let out = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = out.trim_end_matches('\n').split('\n').collect();
        assert_eq!(lines.len(), 50, "every record must land as its own line");
        for line in lines {
            let ev: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(ev["outcome"], AUDIT_SUCCESS);
            assert_eq!(ev["actor_kid"], "k1");
        }
    }

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("nope"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn record_reports_io_errors() {
        let sink = JsonlAuditSink::new(FailingWriter);
        let err = sink.record(test_event(AUDIT_SUCCESS, "")).unwrap_err();
        assert_eq!(err.code, "internal");
        assert_eq!(err.http_status, 500);
    }
}
