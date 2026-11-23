//! Incremental WHATWG server-sent events reader (spec 05 sections 2.6, 2.10,
//! 2.12-2.14). Used by both the client verifier and the server signer: it
//! turns a body arriving in chunks into complete events and remembers where
//! in the original body each byte arrived, which is what the idle rule of 4.5
//! measures.
//!
//! The reader is deliberately grammar-agnostic: UTF-8 validity, field names
//! and the Jack fields are frame rules of 2.7-2.13, applied later by
//! [`super::grammar::parse_frame`]. What it owns is the SSE framing: `\r\n`,
//! `\n` and a lone `\r` are one terminator, one leading U+FEFF is ignored, a
//! comment belongs to no event, and an event is emitted only at a blank line
//! that follows at least one field line.

/// One `name: value` field line; bytes as received (UTF-8 validity is a frame
/// rule of 2.10, not a reader rule). A line with no `:` is a field with an
/// empty value (2.13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseField {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}

/// One complete event: its field lines and `end`, the offset just past the
/// terminating blank line in the ORIGINAL (unstripped) body coordinates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseEvent {
    pub lines: Vec<SseField>,
    pub end: usize,
}

const BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];
const CR: u8 = 0x0D;
const LF: u8 = 0x0A;
const SP: u8 = 0x20;
const COLON: u8 = 0x3A;

/// Incremental reader. Accepts `\r\n`, `\n` and a lone `\r` as one terminator;
/// ignores at most one leading U+FEFF BOM; a comment line belongs to no event
/// and does not clear the fields of the event it appears in; an event is
/// emitted only at a blank line that follows at least one field line; trailing
/// bytes without a terminator are discarded at [`SseReader::finish`].
#[derive(Debug, Default)]
pub struct SseReader {
    /// Unparsed bytes from the start of the current incomplete line onward.
    tail: Vec<u8>,
    /// Original body offset of `tail[0]`.
    tail_start: usize,
    /// Index into `tail` of the next byte to scan for a terminator.
    scanned: usize,
    /// Field lines of the event being assembled.
    fields: Vec<SseField>,
    /// Total bytes pushed, BOM included.
    total: usize,
    /// Whether the leading BOM probe has been decided.
    bom_decided: bool,
    /// Number of ignored leading BOM bytes (0 or 3).
    bom_len: usize,
    /// `(exclusive end offset, arrival time)` per non-empty push, ascending.
    chunks: Vec<(usize, i64)>,
}

impl SseReader {
    pub fn new() -> Self {
        SseReader::default()
    }

    /// Appends one body chunk that arrived at `arrived_at_ms` milliseconds
    /// after the open header was verified, and returns every event completed
    /// by it, in order.
    pub fn push(&mut self, chunk: &[u8], arrived_at_ms: i64) -> Vec<SseEvent> {
        self.total += chunk.len();
        if !chunk.is_empty() {
            self.chunks.push((self.total, arrived_at_ms));
        }
        self.tail.extend_from_slice(chunk);
        self.drain(false)
    }

    /// Makes pending bytes parseable at end of body (a lone trailing CR counts
    /// as a terminator; an unterminated trailing line is discarded). Returns
    /// the events completed by that flush.
    pub fn finish(&mut self) -> Vec<SseEvent> {
        let events = self.drain(true);
        // 2.14: an unterminated trailing line is discarded.
        self.tail.clear();
        self.tail_start = self.total;
        self.scanned = 0;
        events
    }

    /// Arrival time of the byte at `offset` (original body coordinates): the
    /// `arrived_at_ms` of the chunk that contained it; 0 when no chunk
    /// contains it.
    pub fn arrival_at(&self, offset: usize) -> i64 {
        // `timeAt` of the reference: the first chunk whose end offset is
        // greater than `offset`.
        let index = self.chunks.partition_point(|&(end, _)| end <= offset);
        match self.chunks.get(index) {
            Some(&(_, arrived_at)) => arrived_at,
            None => 0,
        }
    }

    /// Total bytes pushed (original coordinates, BOM included).
    pub fn total_bytes(&self) -> usize {
        self.total
    }

    /// Number of leading BOM bytes that were ignored (0 or 3).
    pub fn bom_len(&self) -> usize {
        self.bom_len
    }

    /// Scans the buffered tail for complete lines. `at_eof` commits a trailing
    /// CR as a lone terminator instead of waiting for the byte that decides
    /// between CRLF and CR.
    fn drain(&mut self, at_eof: bool) -> Vec<SseEvent> {
        let mut events = Vec::new();
        if !self.bom_decided {
            // 2.14: at most one leading U+FEFF. Hold up to three bytes so the
            // probe also works when the BOM is split across chunks.
            if self.tail.len() < BOM.len() && !at_eof {
                return events;
            }
            if self.tail.len() >= BOM.len() && self.tail[..BOM.len()] == BOM {
                self.bom_len = BOM.len();
                self.tail.drain(..BOM.len());
                self.tail_start += BOM.len();
            }
            self.bom_decided = true;
            self.scanned = 0;
        }
        while let Some(local) = self.next_terminator(at_eof) {
            let byte = self.tail[local];
            let next = self.tail.get(local + 1).copied();
            let term_len = if byte == CR && next == Some(LF) { 2 } else { 1 };
            let term_end = self.tail_start + local + term_len;
            if local == 0 {
                // A blank line: it emits only when at least one field line
                // preceded it (2.6).
                if !self.fields.is_empty() {
                    events.push(SseEvent {
                        lines: std::mem::take(&mut self.fields),
                        end: term_end,
                    });
                }
            } else if self.tail[0] != COLON {
                // 2.12: a comment belongs to no event and clears nothing.
                self.fields.push(parse_field(&self.tail[..local]));
            }
            self.tail.drain(..local + term_len);
            self.tail_start = term_end;
            self.scanned = 0;
        }
        events
    }

    /// The index of the next committed terminator in `tail`, or `None` when
    /// more bytes are needed or the tail holds no terminator. A trailing CR is
    /// never committed before the next byte arrives, because a split between
    /// CR and LF would otherwise look like a blank line.
    fn next_terminator(&mut self, at_eof: bool) -> Option<usize> {
        let mut index = self.scanned;
        while index < self.tail.len() {
            let byte = self.tail[index];
            if byte == CR || byte == LF {
                let decided = byte == LF || index + 1 < self.tail.len() || at_eof;
                if decided {
                    return Some(index);
                }
                // Hold the trailing CR until the next byte decides CRLF vs CR.
                self.scanned = index;
                return None;
            }
            index += 1;
        }
        self.scanned = index;
        None
    }
}

/// 2.13: `name: value`, with exactly one SP stripped after the colon. A line
/// with no `:` is a field whose name is the whole line and whose value is
/// empty.
fn parse_field(line: &[u8]) -> SseField {
    match line.iter().position(|&byte| byte == COLON) {
        Some(colon) => {
            let value = &line[colon + 1..];
            let value = if value.first() == Some(&SP) {
                &value[1..]
            } else {
                value
            };
            SseField {
                name: line[..colon].to_vec(),
                value: value.to_vec(),
            }
        }
        None => SseField {
            name: line.to_vec(),
            value: Vec::new(),
        },
    }
}
