//! Incremental SSE reader tests: split-invariance (whole body, one byte at a
//! time, between CR and LF, across a BOM), comments, line endings, `finish`
//! and the arrival-time mapping of spec 05 section 4.5.

use crate::stream::{SseEvent, SseField, SseReader};

const BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];

/// `data: a` CRLF CRLF, a comment, then `data: b` LF LF.
const BODY: &[u8] = b"data: a\r\n\r\n: ping\ndata: b\n\n";

fn field(name: &[u8], value: &[u8]) -> SseField {
    SseField {
        name: name.to_vec(),
        value: value.to_vec(),
    }
}

fn whole(body: &[u8]) -> Vec<SseEvent> {
    let mut reader = SseReader::new();
    let mut events = reader.push(body, 0);
    events.extend(reader.finish());
    events
}

fn one_byte_at_a_time(body: &[u8]) -> Vec<SseEvent> {
    let mut reader = SseReader::new();
    let mut events = Vec::new();
    for (offset, byte) in body.iter().enumerate() {
        events.extend(reader.push(std::slice::from_ref(byte), offset as i64));
    }
    events.extend(reader.finish());
    events
}

fn from_chunks(chunks: &[(&[u8], i64)]) -> Vec<SseEvent> {
    let mut reader = SseReader::new();
    let mut events = Vec::new();
    for (chunk, arrived_at) in chunks {
        events.extend(reader.push(chunk, *arrived_at));
    }
    events.extend(reader.finish());
    events
}

fn expected_body_events() -> Vec<SseEvent> {
    vec![
        SseEvent {
            lines: vec![field(b"data", b"a")],
            end: 11,
        },
        SseEvent {
            lines: vec![field(b"data", b"b")],
            end: 27,
        },
    ]
}

#[test]
fn whole_body() {
    assert_eq!(whole(BODY), expected_body_events());
}

#[test]
fn byte_at_a_time_matches_whole() {
    assert_eq!(one_byte_at_a_time(BODY), whole(BODY));
}

#[test]
fn split_between_cr_and_lf_matches_whole() {
    // The CR of every terminator lands in a different chunk from its LF (or
    // the following byte), so a naive reader would see a spurious blank line
    // after `data: a`.
    let chunks: Vec<(&[u8], i64)> = vec![
        (&b"data: a\r"[..], 0),
        (&b"\n"[..], 1),
        (&b"\r"[..], 2),
        (&b"\n: ping\ndata: b\n"[..], 3),
        (&b"\n"[..], 4),
    ];
    assert_eq!(from_chunks(&chunks), whole(BODY));
}

#[test]
fn trailing_cr_is_not_committed_early() {
    let mut reader = SseReader::new();
    assert!(reader.push(b"data: x\r", 0).is_empty());
    assert!(reader.push(b"\n", 1).is_empty());
    let events = reader.push(b"\n", 2);
    assert_eq!(
        events,
        vec![SseEvent {
            lines: vec![field(b"data", b"x")],
            end: 10,
        }]
    );
}

#[test]
fn bom_is_ignored_across_chunks() {
    let mut bodied = BOM.to_vec();
    bodied.extend_from_slice(BODY);

    let bom_whole = whole(&bodied);
    assert_eq!(bom_whole.len(), 2);
    // `end` stays in original coordinates: shifted by the three BOM bytes.
    assert_eq!(bom_whole[0].end, 14);
    assert_eq!(bom_whole[1].end, 30);
    // The field values are the same as without a BOM.
    let plain: Vec<Vec<SseField>> = expected_body_events()
        .into_iter()
        .map(|event| event.lines)
        .collect();
    let stripped: Vec<Vec<SseField>> = bom_whole.iter().map(|event| event.lines.clone()).collect();
    assert_eq!(stripped, plain);

    // Every split of the BOM prefix yields the same events.
    let mut bom_whole_reader = SseReader::new();
    let mut from_whole = bom_whole_reader.push(&bodied, 0);
    from_whole.extend(bom_whole_reader.finish());
    assert_eq!(bom_whole_reader.bom_len(), 3);

    let chunks: Vec<(&[u8], i64)> = vec![
        (&bodied[..1], 0),
        (&bodied[1..2], 1),
        (&bodied[2..3], 2),
        (&bodied[3..], 3),
    ];
    assert_eq!(from_chunks(&chunks), from_whole);

    let chunks: Vec<(&[u8], i64)> = vec![(&bodied[..3], 0), (&bodied[3..], 1)];
    assert_eq!(from_chunks(&chunks), from_whole);
}

#[test]
fn bom_offset_of_first_event() {
    let mut reader = SseReader::new();
    let mut body = BOM.to_vec();
    body.extend_from_slice(b"data: x\n\n");
    let events = reader.push(&body, 0);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].end, 12);
    assert_eq!(reader.bom_len(), 3);
    assert_eq!(reader.total_bytes(), 12);
    assert_eq!(reader.arrival_at(0), 0);
}

#[test]
fn comments_inside_an_event() {
    let events = whole(b"data: a\n: note\ndata: b\n\n");
    assert_eq!(
        events,
        vec![SseEvent {
            lines: vec![field(b"data", b"a"), field(b"data", b"b")],
            end: 24,
        }]
    );
}

#[test]
fn comment_only_events_are_not_emitted() {
    // ": ping" then a blank line has no field line, so it emits nothing.
    assert!(whole(b": ping\n\n").is_empty());
    assert!(whole(b":\n\n").is_empty());
    assert!(whole(b": only a comment").is_empty());
}

#[test]
fn unknown_fields_and_bare_names() {
    let events = whole(b"x-unknown: v\nbare\n\n");
    assert_eq!(
        events,
        vec![SseEvent {
            lines: vec![field(b"x-unknown", b"v"), field(b"bare", b"")],
            end: 19,
        }]
    );
    // Exactly one SP after the colon is stripped.
    assert_eq!(whole(b"data:  x\n\n")[0].lines, vec![field(b"data", b" x")]);
    // No SP: the value starts right after the colon.
    assert_eq!(whole(b"data:x\n\n")[0].lines, vec![field(b"data", b"x")]);
    // A colon inside the value is ordinary content.
    assert_eq!(
        whole(b"data: a:b\n\n")[0].lines,
        vec![field(b"data", b"a:b")]
    );
}

#[test]
fn line_endings_are_equivalent() {
    let crlf = whole(b"data: x\r\ndata: y\r\n\r\n");
    let cr = whole(b"data: x\rdata: y\r\r");
    let lf = whole(b"data: x\ndata: y\n\n");
    assert_eq!(crlf[0].lines, lf[0].lines);
    assert_eq!(cr[0].lines, lf[0].lines);
    // A CRLF and a lone CR are each one terminator, so the `end` offsets
    // differ with the byte width.
    assert_eq!(crlf[0].end, 20);
    assert_eq!(cr[0].end, 17);
    assert_eq!(lf[0].end, 17);
}

#[test]
fn finish_discards_unterminated_tail() {
    let mut reader = SseReader::new();
    let events = reader.push(b"data: x\n\ndata: y", 0);
    assert_eq!(events.len(), 1);
    assert!(reader.finish().is_empty());
    assert_eq!(reader.total_bytes(), 16);

    let mut reader = SseReader::new();
    assert!(reader.push(b"data: y", 0).is_empty());
    assert!(reader.finish().is_empty());
}

#[test]
fn finish_commits_a_trailing_cr() {
    let mut reader = SseReader::new();
    // The second CR would be a blank line only once it is committed, and the
    // reader holds a trailing CR until the next byte or `finish`.
    assert!(reader.push(b"data: x\r\r", 0).is_empty());
    let events = reader.finish();
    assert_eq!(
        events,
        vec![SseEvent {
            lines: vec![field(b"data", b"x")],
            end: 9,
        }]
    );
}

#[test]
fn arrival_at_maps_offsets_to_chunks() {
    let mut reader = SseReader::new();
    assert!(reader.push(b"data: a\n", 100).is_empty());
    let events = reader.push(b"\n", 250);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].end, 9);
    assert_eq!(reader.total_bytes(), 9);
    assert_eq!(reader.bom_len(), 0);
    // Offsets 0..=7 belong to the first chunk, offset 8 to the second, and
    // anything past the pushed bytes maps to 0 (reference `timeAt`).
    assert_eq!(reader.arrival_at(0), 100);
    assert_eq!(reader.arrival_at(7), 100);
    assert_eq!(reader.arrival_at(8), 250);
    assert_eq!(reader.arrival_at(9), 0);
    assert_eq!(reader.arrival_at(usize::MAX), 0);
}

#[test]
fn arrival_at_includes_the_bom() {
    let mut reader = SseReader::new();
    assert!(reader.push(&BOM[..1], 10).is_empty());
    assert!(reader.push(&BOM[1..2], 20).is_empty());
    assert!(reader.push(&BOM[2..3], 30).is_empty());
    let events = reader.push(b"data: x\n\n", 40);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].end, 12);
    assert_eq!(reader.bom_len(), 3);
    assert_eq!(reader.arrival_at(0), 10);
    assert_eq!(reader.arrival_at(2), 30);
    assert_eq!(reader.arrival_at(3), 40);
    assert_eq!(reader.arrival_at(11), 40);
    assert_eq!(reader.arrival_at(12), 0);
}

#[test]
fn empty_pushes_do_not_create_chunks() {
    let mut reader = SseReader::new();
    assert!(reader.push(b"", 5).is_empty());
    assert_eq!(reader.total_bytes(), 0);
    assert_eq!(reader.arrival_at(0), 0);
    let events = reader.push(b"data: x\n\n", 7);
    assert_eq!(events.len(), 1);
    assert_eq!(reader.arrival_at(0), 7);
    assert_eq!(reader.total_bytes(), 9);
}
