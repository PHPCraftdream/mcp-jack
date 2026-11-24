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
    /// Arrival time of the byte completing the terminating blank line.
    pub arrived_at_ms: i64,
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
    /// Maximum pending SSE framing bytes. `None` keeps the grammar-only reader unbounded.
    max_pending_bytes: Option<usize>,
    too_large: bool,
    current_arrival_ms: i64,
    /// Arrival of the final body byte, retained without per-chunk history in bounded mode.
    last_byte_arrival_ms: i64,
    /// Arrival sample for a CR held across a push boundary.
    pending_cr: Option<(usize, i64)>,
    pending_data_bytes: usize,
}

impl SseReader {
    pub fn new() -> Self {
        SseReader::default()
    }

    /// Creates a reader that aborts as soon as its incomplete event exceeds `max_pending_bytes`.
    pub fn with_max_pending_bytes(max_pending_bytes: usize) -> Self {
        SseReader {
            max_pending_bytes: Some(max_pending_bytes),
            ..SseReader::default()
        }
    }

    /// Whether an incomplete line/event crossed the configured framing bound.
    pub fn too_large(&self) -> bool {
        self.too_large
    }

    /// Bytes retained for arrival-time lookup; included in the bounded-reader memory budget.
    pub fn arrival_metadata_bytes(&self) -> usize {
        0
    }

    /// Bytes retained for the current partial event, including Vec capacities.
    pub fn buffered_bytes(&self) -> usize {
        self.tail.capacity()
            + self.fields.capacity() * std::mem::size_of::<SseField>()
            + self
                .fields
                .iter()
                .map(|field| field.name.capacity() + field.value.capacity())
                .sum::<usize>()
    }

    /// Appends one body chunk that arrived at `arrived_at_ms` milliseconds
    /// after the open header was verified, and returns every event completed
    /// by it, in order.
    pub fn push(&mut self, chunk: &[u8], arrived_at_ms: i64) -> Vec<SseEvent> {
        let start = self.total;
        self.total = self.total.saturating_add(chunk.len());
        if self.max_pending_bytes.is_some() {
            // Bounded consumers need only the arrival of the byte completing each event.
            self.chunks.clear();
        }
        let mut events = Vec::new();
        if !chunk.is_empty() {
            self.current_arrival_ms = arrived_at_ms;
            self.last_byte_arrival_ms = arrived_at_ms;
        }
        for (index, &byte) in chunk.iter().enumerate() {
            if self.too_large {
                break;
            }
            let offset_end = start + index + 1;
            self.tail.reserve_exact(1);
            self.tail.push(byte);
            if byte == CR && self.pending_cr.is_none() {
                self.pending_cr = Some((start + index, arrived_at_ms));
            }
            events.extend(self.drain(false));
            if let Some(max) = self.max_pending_bytes {
                let in_progress_data = current_data_value_len(&self.tail)
                    .map(|len| {
                        len.saturating_add(usize::from(
                            self.fields.iter().any(|field| field.name == b"data"),
                        ))
                    })
                    .unwrap_or(0);
                let retained = self.buffered_bytes();
                if self.pending_data_bytes.saturating_add(in_progress_data) > max
                    || retained > max.saturating_add(4096)
                {
                    self.too_large = true;
                    self.tail.clear();
                    self.tail.shrink_to_fit();
                    self.fields.clear();
                    self.fields.shrink_to_fit();
                    self.chunks.clear();
                    break;
                }
            }
            if self.max_pending_bytes.is_none() {
                if let Some((end, time)) = self.chunks.last_mut() {
                    if *time == arrived_at_ms {
                        *end = offset_end;
                    } else {
                        self.chunks.push((offset_end, arrived_at_ms));
                    }
                } else {
                    self.chunks.push((offset_end, arrived_at_ms));
                }
            }
        }
        events
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
        if self.max_pending_bytes.is_some() {
            // The bounded reader retains only the final byte's timestamp, needed by finish()
            // for the trailing-silence rule. Completed events carry their own terminator time.
            return if offset.checked_add(1) == Some(self.total) {
                self.last_byte_arrival_ms
            } else {
                0
            };
        }
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
            let terminator_arrival = if byte == CR && next != Some(LF) {
                let arrival = self
                    .pending_cr
                    .filter(|(offset, _)| *offset == self.tail_start + local)
                    .map(|(_, time)| time)
                    .unwrap_or(self.current_arrival_ms);
                if self
                    .pending_cr
                    .is_some_and(|(offset, _)| offset == self.tail_start + local)
                {
                    self.pending_cr = None;
                }
                arrival
            } else {
                if byte == CR {
                    self.pending_cr = None;
                }
                self.current_arrival_ms
            };
            let term_len = if byte == CR && next == Some(LF) { 2 } else { 1 };
            let term_end = self.tail_start + local + term_len;
            if local == 0 {
                // A blank line: it emits only when at least one field line
                // preceded it (2.6).
                if !self.fields.is_empty() {
                    events.push(SseEvent {
                        lines: std::mem::take(&mut self.fields),
                        end: term_end,
                        arrived_at_ms: terminator_arrival,
                    });
                    self.pending_data_bytes = 0;
                }
            } else if self.tail[0] != COLON {
                // 2.12: comments are not fields. The byte cap tracks only data values.
                let has_data = self.fields.iter().any(|field| field.name == b"data");
                self.fields.push(parse_field(&self.tail[..local]));
                if self.max_pending_bytes.is_some() {
                    let field = self.fields.last().expect("just pushed");
                    if field.name == b"data" {
                        self.pending_data_bytes = self
                            .pending_data_bytes
                            .saturating_add(field.value.len())
                            .saturating_add(usize::from(has_data));
                    }
                }
            }
            self.tail.drain(..local + term_len);
            self.tail_start = term_end;
            self.scanned = 0;
            if self.max_pending_bytes.is_some() {
                // Parsing a data line copies its value into `fields`; release the framing
                // allocation now so retained memory is not counted twice or left at peak size.
                self.tail.shrink_to_fit();
            }
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

fn current_data_value_len(tail: &[u8]) -> Option<usize> {
    // No bytes contribute to the data value until the exact field name and
    // colon are known. In particular, `data` without a colon is an empty-valued
    // field, and prefixes such as `dat` are ordinary field-name framing.
    let rest = tail.strip_prefix(b"data:")?;
    let value_len = rest
        .len()
        .saturating_sub(usize::from(rest.first() == Some(&SP)));
    // A trailing CR is still a pending terminator, not part of the value.
    Some(value_len.saturating_sub(usize::from(rest.last() == Some(&CR))))
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
