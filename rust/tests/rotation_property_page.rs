// Детерминированные property-тесты фрейминга страницы (validate_page_framing)
// и лимитов тела результата: фиксированный seed воспроизводит каждый refusal.
mod common;

use mcp_jack::client::{InMemorySigner, Signer};
use mcp_jack::encoding::{decode_b64url_fixed, key_id};
use mcp_jack::rotation::{
    self, Binding, Checkpoint, DecodedResult, PageFraming, Record, ResultCursor, RotationError,
};
use serde::Deserialize;
use std::collections::BTreeMap;

const SEED: u64 = 0x5eed_00b2;

#[derive(Deserialize)]
struct FixtureBinding {
    endpoint: String,
    aud: String,
}

#[derive(Deserialize)]
struct FixtureKey {
    kid: String,
    public_key: String,
}

#[derive(Deserialize)]
struct Corpus {
    binding: FixtureBinding,
    keys: BTreeMap<String, FixtureKey>,
}

fn corpus() -> Corpus {
    let bytes = std::fs::read(common::fixtures::fixture_path(
        "candidate/rotation-vectors.json",
    ))
    .expect("committed independent candidate fixture");
    serde_json::from_slice(&bytes).expect("typed corpus")
}

fn binding(corpus: &Corpus) -> Binding<'_> {
    Binding {
        endpoint: &corpus.binding.endpoint,
        aud: &corpus.binding.aud,
    }
}

fn assert_code(result: Result<impl std::fmt::Debug, RotationError>, code: &str, label: &str) {
    let error = result.expect_err(label);
    assert_eq!(error.code, code, "{label}");
}

// Детерминированный PRNG: фиксированный seed воспроизводит каждый refusal.
struct SplitMix64(u64);

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut value = self.0;
        value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        value ^ (value >> 31)
    }

    fn below(&mut self, limit: u64) -> u64 {
        self.next() % limit
    }
}

fn splitmix64_value(input: u64) -> u64 {
    let mut value = input.wrapping_add(0x9E37_79B9_7F4A_7C15);
    value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    value ^ (value >> 31)
}

// Больше 255 различных индексов: seed выводится из PRNG, а не из одного байта.
fn signer_seed(index: u64) -> [u8; 32] {
    let mut seed = [0_u8; 32];
    for lane in 0..4_u64 {
        let mixed = splitmix64_value(index * 4 + lane);
        let start = usize::try_from(lane * 8).expect("small offset");
        seed[start..start + 8].copy_from_slice(&mixed.to_be_bytes());
    }
    seed
}

fn signer(index: u64) -> InMemorySigner {
    InMemorySigner::from_seed(&signer_seed(index)).expect("test signer")
}

fn generated_chain(
    corpus: &Corpus,
    count: u64,
    mut published_at: impl FnMut(u64) -> u64,
) -> (Checkpoint, Vec<Record>) {
    let mut old = signer(0);
    let root = Checkpoint {
        ordinal: 0,
        hash: "-".to_owned(),
        kid: key_id(&old.public_key()),
        public_key: old.public_key(),
        published_at: 0,
    };
    let mut previous = root.clone();
    let mut records = Vec::new();
    for index in 1..=count {
        let next = signer(index);
        let record = rotation::create_record(
            binding(corpus),
            &previous,
            &old,
            &next,
            published_at(index),
        )
        .expect("generated rotation record");
        previous = Checkpoint {
            ordinal: record.ordinal,
            hash: record.hash.clone(),
            kid: record.new_kid.clone(),
            public_key: record.public_key,
            published_at: record.published_at,
        };
        records.push(record);
        old = next;
    }
    (root, records)
}

fn result_literal(
    root: &Checkpoint,
    wires: &[String],
    head_ordinal: u64,
    head_hash: &str,
    complete: bool,
) -> DecodedResult {
    DecodedResult {
        current_kid: root.kid.clone(),
        current_public_key: root.public_key,
        records: wires.to_vec(),
        head_ordinal,
        head_hash: head_hash.to_owned(),
        complete,
    }
}

fn flip_first_char(text: &str) -> String {
    let first = text.chars().next().expect("non-empty string");
    let replacement = if first == 'A' { 'B' } else { 'A' };
    let flipped = format!("{replacement}{}", text.get(first.len_utf8()..).expect("tail"));
    assert_ne!(flipped, text, "flip must change the string");
    flipped
}

// Канонический тело-шаблон ответа jack.server.key; text и structuredContent
// несут один и тот же payload, как требует зеркальная проверка decode_result.
fn result_body(kid: &str, public_key: &str, filler: &str) -> String {
    let payload = format!(
        r#"{{"current":{{"kid":"{kid}","public_key":"{public_key}"}},"records":["{filler}"],"head":{{"ordinal":0,"hash":"-"}},"complete":true}}"#
    );
    let text = serde_json::to_string(&payload).expect("payload encodes as a JSON string");
    format!(
        r#"{{"jsonrpc":"2.0", "id":7,"result":{{"content":[{{"type":"text","text":{text}}}],"structuredContent":{payload},"isError":false}}}}"#
    )
}

fn filler_text(prng: &mut SplitMix64, length: usize) -> String {
    let mut text = String::new();
    while text.len() < length {
        let offset = u8::try_from(prng.below(26)).expect("letter offset");
        text.push(char::from(b'a' + offset));
    }
    text
}

#[test]
fn generated_pages_frame_one_contiguous_extension_from_the_exact_cursor() {
    let corpus = corpus();
    let (root, records) = generated_chain(&corpus, 6, |index| 1000 + index * 10);
    assert_eq!(records.len(), 6, "seed {SEED:#x} chain length");
    let tail = ResultCursor {
        ordinal: 6,
        hash: records.get(5).expect("tail record").hash.clone(),
    };
    let wires: Vec<String> = records.iter().map(|record| record.wire.clone()).collect();
    for k in 0..=6_u64 {
        let index = usize::try_from(k).expect("cursor index");
        let cursor = ResultCursor {
            ordinal: k,
            hash: if k == 0 {
                "-".to_owned()
            } else {
                records.get(index - 1).expect("cursor record").hash.clone()
            },
        };
        // Полная страница принимается для каждого k, включая пустую при k = 6
        // (terminal == cursor == tail).
        let label = format!("seed {SEED:#x} cursor {k} full page");
        let page_wires = wires.get(index..).expect("full page wires");
        let result = result_literal(&root, page_wires, 6, &tail.hash, true);
        let framing = rotation::validate_page_framing(
            &result,
            &cursor,
            records.get(index..).expect("full page records"),
            &BTreeMap::new(),
        )
        .expect(&label);
        assert_eq!(
            framing,
            PageFraming {
                extension_start: 0,
                terminal: tail.clone(),
                head: tail.clone(),
                complete: true,
            },
            "{label} framing"
        );
        // Частичная страница из двух записей принимается, пока её terminal
        // строго меньше head; страницы, дошедшие до head без complete (k = 4, 5)
        // или пустые (k = 6), отказывают с rotation_gap.
        if k <= 3 {
            let label = format!("seed {SEED:#x} cursor {k} partial page");
            let partial = records.get(index..index + 2).expect("partial records");
            let partial_wires = wires.get(index..index + 2).expect("partial wires");
            let result = result_literal(&root, partial_wires, 6, &tail.hash, false);
            let framing = rotation::validate_page_framing(
                &result,
                &cursor,
                partial,
                &BTreeMap::new(),
            )
            .expect(&label);
            let terminal = ResultCursor {
                ordinal: k + 2,
                hash: records.get(index + 1).expect("terminal record").hash.clone(),
            };
            assert_eq!(
                framing,
                PageFraming {
                    extension_start: 0,
                    terminal,
                    head: tail.clone(),
                    complete: false,
                },
                "{label} framing"
            );
        } else {
            let label = format!("seed {SEED:#x} cursor {k} tail incomplete page");
            let partial = records.get(index..).expect("tail records");
            let partial_wires = wires.get(index..).expect("tail wires");
            let result = result_literal(&root, partial_wires, 6, &tail.hash, false);
            assert_code(
                rotation::validate_page_framing(&result, &cursor, partial, &BTreeMap::new()),
                "rotation_gap",
                &label,
            );
        }
    }

    // Acknowledged-префикс: записи 1 и 2 уже известны, расширение с индекса 2.
    let cursor = ResultCursor {
        ordinal: 2,
        hash: records.get(1).expect("second record").hash.clone(),
    };
    let acknowledged = BTreeMap::from([(1, records.first().expect("first record").hash.clone())]);
    let label = format!("seed {SEED:#x} acknowledged prefix page");
    let result = result_literal(&root, &wires, 6, &tail.hash, true);
    let framing = rotation::validate_page_framing(&result, &cursor, &records, &acknowledged)
        .expect(&label);
    assert_eq!(
        framing,
        PageFraming {
            extension_start: 2,
            terminal: tail.clone(),
            head: tail.clone(),
            complete: true,
        },
        "{label} framing"
    );
}

struct FramingCase {
    result: DecodedResult,
    records: Vec<Record>,
    cursor: ResultCursor,
    acknowledged: BTreeMap<u64, String>,
}

fn base_case(root: &Checkpoint, records: &[Record]) -> FramingCase {
    assert_eq!(records.len(), 4, "seed {SEED:#x} base page chain length");
    let wires: Vec<String> = records.iter().map(|record| record.wire.clone()).collect();
    let tail_hash = records.get(3).expect("tail record").hash.clone();
    FramingCase {
        result: result_literal(root, &wires, 4, &tail_hash, true),
        records: records.to_vec(),
        cursor: ResultCursor {
            ordinal: 2,
            hash: records.get(1).expect("second record").hash.clone(),
        },
        acknowledged: BTreeMap::from([(1, records.first().expect("first record").hash.clone())]),
    }
}

fn assert_refused(case: &FramingCase, code: &str, label: &str) {
    let framing = rotation::validate_page_framing(
        &case.result,
        &case.cursor,
        &case.records,
        &case.acknowledged,
    );
    assert_code(framing, code, label);
}

#[test]
fn every_framing_mutation_is_rejected_with_its_exact_code() {
    let corpus = corpus();
    let (root, records) = generated_chain(&corpus, 4, |index| 1000 + index);
    let label = format!("seed {SEED:#x} base page accepted");
    let base = base_case(&root, &records);
    let framing = rotation::validate_page_framing(
        &base.result,
        &base.cursor,
        &base.records,
        &base.acknowledged,
    )
    .expect(&label);
    let expected_tail = records.get(3).expect("tail record").hash.clone();
    assert_eq!(
        framing,
        PageFraming {
            extension_start: 2,
            terminal: ResultCursor {
                ordinal: 4,
                hash: expected_tail.clone(),
            },
            head: ResultCursor {
                ordinal: 4,
                hash: expected_tail,
            },
            complete: true,
        },
        "{label} framing"
    );

    let mut case = base_case(&root, &records);
    case.result.records.swap(0, 1);
    assert_refused(&case, "rotation_record_invalid", "seed 0x5eed00b2 case 1 swap result wires");

    let mut case = base_case(&root, &records);
    case.records.swap(0, 1);
    case.result.records.swap(0, 1);
    assert_refused(&case, "rotation_gap", "seed 0x5eed00b2 case 2 swap page records");

    let mut case = base_case(&root, &records);
    let first_record = case.records.first().expect("first record").clone();
    let first_wire = case.result.records.first().expect("first wire").clone();
    case.records.insert(1, first_record);
    case.result.records.insert(1, first_wire);
    assert_refused(&case, "rotation_gap", "seed 0x5eed00b2 case 3 duplicate record");

    let mut case = base_case(&root, &records);
    case.records.remove(1);
    case.result.records.remove(1);
    assert_refused(&case, "rotation_gap", "seed 0x5eed00b2 case 4 remove record");

    let mut case = base_case(&root, &records);
    *case.result.records.get_mut(2).expect("third wire") = "x".to_owned();
    assert_refused(&case, "rotation_record_invalid", "seed 0x5eed00b2 case 5 replace wire");

    let mut case = base_case(&root, &records);
    let mutated = case.records.get_mut(2).expect("third record");
    mutated.hash = flip_first_char(&mutated.hash);
    assert_refused(&case, "rotation_record_invalid", "seed 0x5eed00b2 case 6 flip record hash");

    let mut case = base_case(&root, &records);
    case.cursor.hash = case.records.first().expect("first record").hash.clone();
    assert_refused(&case, "rotation_conflict", "seed 0x5eed00b2 case 7 cursor hash stale");

    let mut case = base_case(&root, &records);
    let saved = case.acknowledged.get_mut(&1).expect("acknowledged entry");
    *saved = flip_first_char(saved);
    assert_refused(&case, "rotation_conflict", "seed 0x5eed00b2 case 8 flip acked hash");

    let mut case = base_case(&root, &records);
    case.acknowledged.clear();
    assert_refused(&case, "rotation_gap", "seed 0x5eed00b2 case 9 drop acked map");

    let mut case = base_case(&root, &records);
    case.records.truncate(1);
    case.result.records.truncate(1);
    assert_refused(&case, "rotation_gap", "seed 0x5eed00b2 case 10 cursor-only page");

    // Отклонение от literal-спецификации: cursor 2 со страницей [r3, r4] —
    // каноническое продолжение, оно ПРИНИМАЕТСЯ; настоящий gap — старт записи
    // за cursor + 1, поэтому cursor = 1 и страница начинается с r3.
    let mut case = base_case(&root, &records);
    case.cursor.ordinal = 1;
    case.cursor.hash = case.records.first().expect("first record").hash.clone();
    let third = case.records.get(2).expect("third record").clone();
    let fourth = case.records.get(3).expect("fourth record").clone();
    let third_wire = case.result.records.get(2).expect("third wire").clone();
    let fourth_wire = case.result.records.get(3).expect("fourth wire").clone();
    case.records = vec![third, fourth];
    case.result.records = vec![third_wire, fourth_wire];
    assert_refused(&case, "rotation_gap", "seed 0x5eed00b2 case 11 skip past cursor");

    let mut case = base_case(&root, &records);
    case.result.head_ordinal = 3;
    assert_refused(&case, "rotation_gap", "seed 0x5eed00b2 case 12 head ordinal low");

    let mut case = base_case(&root, &records);
    case.result.head_hash = flip_first_char(&case.result.head_hash);
    assert_refused(&case, "rotation_gap", "seed 0x5eed00b2 case 13 flip head hash");

    let mut case = base_case(&root, &records);
    case.result.complete = false;
    assert_refused(&case, "rotation_gap", "seed 0x5eed00b2 case 14 complete at head");

    let mut case = base_case(&root, &records);
    case.records.clear();
    case.result.records.clear();
    case.result.complete = false;
    assert_refused(&case, "rotation_gap", "seed 0x5eed00b2 case 15 empty incomplete");

    let mut case = base_case(&root, &records);
    case.records.truncate(2);
    case.result.records.truncate(2);
    assert_refused(&case, "rotation_gap", "seed 0x5eed00b2 case 16 complete partial");

    let mut case = base_case(&root, &records);
    case.cursor.ordinal = 0;
    case.cursor.hash = "x".to_owned();
    assert_refused(&case, "rotation_gap", "seed 0x5eed00b2 case 17 zero cursor hash");

    let mut case = base_case(&root, &records);
    case.cursor.ordinal = 1;
    case.cursor.hash = "-".to_owned();
    assert_refused(&case, "rotation_gap", "seed 0x5eed00b2 case 18 ordinal one dash");

    let mut case = base_case(&root, &records);
    case.result.head_ordinal = rotation::MAX_ORDINAL + 1;
    assert_refused(&case, "rotation_gap", "seed 0x5eed00b2 case 19 head ordinal max");

    let mut case = base_case(&root, &records);
    case.cursor.ordinal = rotation::MAX_ORDINAL + 1;
    assert_refused(&case, "rotation_gap", "seed 0x5eed00b2 case 20 cursor ordinal max");
}

#[test]
fn page_and_body_limits_hold_exactly() {
    let corpus = corpus();
    let mut prng = SplitMix64::new(SEED);
    assert_eq!(rotation::MAX_PAGE_RECORDS, 16, "seed {SEED:#x} page limit");
    let (root16, records16) = generated_chain(&corpus, 16, |index| 1000 + index);
    assert_eq!(records16.len(), 16, "seed {SEED:#x} 16-record chain");
    let wires16: Vec<String> = records16.iter().map(|record| record.wire.clone()).collect();
    let tail16 = records16.get(15).expect("tail record").hash.clone();
    let cursor0 = ResultCursor {
        ordinal: 0,
        hash: "-".to_owned(),
    };
    let label = format!("seed {SEED:#x} full 16-record page");
    let full = result_literal(&root16, &wires16, 16, &tail16, true);
    rotation::validate_page_framing(&full, &cursor0, &records16, &BTreeMap::new()).expect(&label);

    let (root17, records17) = generated_chain(&corpus, 17, |index| 1000 + index);
    assert_eq!(records17.len(), 17, "seed {SEED:#x} 17-record chain");
    let wires17: Vec<String> = records17.iter().map(|record| record.wire.clone()).collect();
    let tail17 = records17.get(16).expect("tail record").hash.clone();
    let label = format!("seed {SEED:#x} 17-record page");
    let oversized = result_literal(&root17, &wires17, 17, &tail17, true);
    assert_code(
        rotation::validate_page_framing(&oversized, &cursor0, &records17, &BTreeMap::new()),
        "rotation_result_invalid",
        &label,
    );
    let label = format!("seed {SEED:#x} 15-record partial page");
    let partial = records17.get(..15).expect("15-record prefix");
    let partial_wires = wires17.get(..15).expect("15-record prefix wires");
    let incomplete = result_literal(&root17, partial_wires, 17, &tail17, false);
    rotation::validate_page_framing(&incomplete, &cursor0, partial, &BTreeMap::new())
        .expect(&label);

    // Тело ровно MAX_RESULT_BODY_BYTES: текущий ключ — реальный fixture anchor.
    // Payload входит в тело ДВАЖДЫ (text и structuredContent), поэтому filler
    // получает половину разницы, а нечётный остаток добирается пробелом вне payload.
    let anchor = &corpus.keys["anchor"];
    let anchor_public = decode_b64url_fixed(&anchor.public_key, 32).expect("fixture anchor key");
    let empty = result_body(&anchor.kid, &anchor.public_key, "");
    let deficit = rotation::MAX_RESULT_BODY_BYTES - empty.len();
    let filler = filler_text(&mut prng, deficit / 2);
    let mut exact = result_body(&anchor.kid, &anchor.public_key, &filler);
    if deficit % 2 == 1 {
        // Нечётная разница: один пробел вне payload добирает ровно до лимита.
        exact = exact.replacen(r#""2.0", "id""#, r#""2.0",  "id""#, 1);
    }
    assert_eq!(
        exact.len(),
        rotation::MAX_RESULT_BODY_BYTES,
        "seed {SEED:#x} exact body limit"
    );
    let label = format!("seed {SEED:#x} exact body decodes");
    let decoded = rotation::decode_result(exact.as_bytes(), b"7").expect(&label);
    assert_eq!(decoded.current_kid, anchor.kid, "seed {SEED:#x} current kid");
    assert_eq!(
        decoded.current_public_key,
        anchor_public.as_slice(),
        "seed {SEED:#x} current public key"
    );
    assert_eq!(
        decoded.records,
        vec![filler.clone()],
        "seed {SEED:#x} exact body records"
    );
    let label = format!("seed {SEED:#x} body one past the limit");
    let oversize = format!("{exact}a");
    assert_code(
        rotation::decode_result(oversize.as_bytes(), b"7"),
        "rotation_result_invalid",
        &label,
    );
}

#[test]
fn canonical_result_bodies_reject_every_single_byte_mutation() {
    let corpus = corpus();
    let anchor = &corpus.keys["anchor"];
    let exact = result_body(&anchor.kid, &anchor.public_key, "rotation-property");
    let label = format!("seed {SEED:#x} canonical baseline");
    let baseline = rotation::decode_result(exact.as_bytes(), b"7").expect(&label);
    for (byte_index, byte) in exact.as_bytes().iter().enumerate() {
        let mut mutated = exact.as_bytes().to_vec();
        mutated[byte_index] = *byte ^ 1;
        let label = format!("seed {SEED:#x} byte {byte_index} xor 1");
        assert!(rotation::decode_result(&mutated, b"7").is_err(), "{label}");
    }
    let label = format!("seed {SEED:#x} positive control");
    let decoded = rotation::decode_result(exact.as_bytes(), b"7").expect(&label);
    assert_eq!(decoded, baseline, "{label} unchanged");
}
