// Детерминированные property-тесты слоя record (parse_record/create_record):
// фиксированный seed воспроизводит каждый refusal, а сообщения об ошибках
// печатают seed, индекс записи и мутированное поле.
mod common;

use mcp_jack::client::{InMemorySigner, Signer};
use mcp_jack::encoding::{body_hash, encode_b64url, key_id};
use mcp_jack::rotation::{self, Binding, Checkpoint, Record, RotationError};
use serde::Deserialize;
use std::collections::BTreeMap;

const SEED: u64 = 0x5eed_00b1;

#[derive(Deserialize)]
struct FixtureBinding {
    endpoint: String,
    aud: String,
}

#[derive(Deserialize)]
struct FixtureKey {
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
    for (lane, value) in seed.chunks_exact_mut(8).enumerate() {
        let mixed = splitmix64_value(index * 4 + u64::try_from(lane).expect("small lane"));
        value.copy_from_slice(&mixed.to_be_bytes());
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

// Каждый old_kid принадлежит signer(index - 1) этой же цепочки.
fn chain_authorizers(records: &[Record]) -> BTreeMap<String, [u8; 32]> {
    let mut authorizers = BTreeMap::new();
    for (offset, record) in records.iter().enumerate() {
        let old_index = u64::try_from(offset).expect("small chain");
        authorizers.insert(record.old_kid.clone(), signer(old_index).public_key());
    }
    authorizers
}

fn prng_bytes(prng: &mut SplitMix64) -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    for value in &mut bytes {
        *value = u8::try_from(prng.below(256)).expect("byte");
    }
    bytes
}

// Случайные байты почти всегда декодируются в валидную точку, поэтому выбор
// детерминирован между двумя заведомо невалидными encodings: неканоничный
// y >= p и точка-тождество. Оба гарантированно отклоняются validate_public_key
// (см. rust/src/ed25519.rs) и дают "new_key".
fn forced_invalid_key(prng: &mut SplitMix64) -> [u8; 32] {
    let mut bytes = [0xff_u8; 32];
    if prng.below(2) == 0 {
        bytes = [0_u8; 32];
        bytes[0] = 1;
    }
    bytes
}

#[test]
fn generated_records_round_trip_with_exact_fields() {
    let corpus = corpus();
    let mut prng = SplitMix64::new(SEED);
    for length in [1_u64, 2, 4] {
        let (root, records) = generated_chain(&corpus, length, |index| {
            1000 + prng.below(50) + index
        });
        let authorizers = chain_authorizers(&records);
        assert_eq!(root.ordinal, 0, "seed {SEED:#x} root ordinal");
        for (index, record) in records.iter().enumerate() {
            let base = format!("seed {SEED:#x} chain {length} record {index}");
            let parsed = rotation::parse_record(
                record.wire.as_bytes(),
                binding(&corpus),
                &authorizers,
            )
            .expect(&base);
            assert_eq!(parsed.ordinal, record.ordinal, "{base} field ordinal");
            assert_eq!(parsed.previous_hash, record.previous_hash, "{base} field previous_hash");
            assert_eq!(parsed.old_kid, record.old_kid, "{base} field old_kid");
            assert_eq!(parsed.new_kid, record.new_kid, "{base} field new_kid");
            assert_eq!(parsed.public_key, record.public_key, "{base} field public_key");
            assert_eq!(parsed.published_at, record.published_at, "{base} field published_at");
            assert_eq!(
                parsed.activates_at,
                record.published_at + rotation::GRACE_SECONDS,
                "{base} field activates_at"
            );
            assert_eq!(parsed.wire, record.wire, "{base} field wire");
            assert_eq!(
                parsed.hash,
                body_hash(record.wire.as_bytes()),
                "{base} field hash"
            );
            let second = rotation::parse_record(
                record.wire.as_bytes(),
                binding(&corpus),
                &authorizers,
            )
            .expect(&base);
            assert_eq!(second, parsed, "{base} second parse is equal");
        }
    }
}

#[test]
fn every_single_byte_mutation_of_a_generated_record_is_rejected() {
    let corpus = corpus();
    let mut prng = SplitMix64::new(SEED);
    let (_, records4) = generated_chain(&corpus, 4, |index| 1000 + index);
    let (_, records2) = generated_chain(&corpus, 2, |index| 1000 + index);
    let authorizers4 = chain_authorizers(&records4);
    let authorizers2 = chain_authorizers(&records2);
    let full_index = prng.below(4);
    let other_index = prng.below(2);
    let full_position = usize::try_from(full_index).expect("chain index");
    let other_position = usize::try_from(other_index).expect("chain index");
    let full = records4.get(full_position).expect("swept record");
    let other = records2.get(other_position).expect("sampled record");
    let baseline_label = format!("seed {SEED:#x} baseline parses");
    let baseline_full = rotation::parse_record(
        full.wire.as_bytes(),
        binding(&corpus),
        &authorizers4,
    )
    .expect(&baseline_label);
    let baseline_other = rotation::parse_record(
        other.wire.as_bytes(),
        binding(&corpus),
        &authorizers2,
    )
    .expect(&baseline_label);

    // Полный sweep по одной записи: каждый одиночный байт-переворот отклонён.
    let mut exercised = 0_usize;
    for (byte_index, byte) in full.wire.as_bytes().iter().enumerate() {
        let mut mutated = full.wire.as_bytes().to_vec();
        mutated[byte_index] = *byte ^ 1;
        let label = format!("seed {SEED:#x} record {full_index} byte {byte_index} xor 1");
        assert!(
            rotation::parse_record(&mutated, binding(&corpus), &authorizers4).is_err(),
            "{label}"
        );
        let reparsed = rotation::parse_record(
            full.wire.as_bytes(),
            binding(&corpus),
            &authorizers4,
        )
        .expect(&label);
        assert_eq!(reparsed, baseline_full, "{label} original unchanged");
        exercised += 1;
    }
    assert_eq!(
        exercised,
        full.wire.len(),
        "seed {SEED:#x} full sweep byte coverage"
    );

    // Плюс 16 PRNG-индексов с ^= 0x80 на обеих записях.
    for sample in 0..16_u64 {
        let byte_index = prng.below(u64::try_from(full.wire.len()).expect("wire length"));
        let index = usize::try_from(byte_index).expect("byte index");
        let mut mutated = full.wire.as_bytes().to_vec();
        mutated[index] ^= 0x80;
        let label = format!("seed {SEED:#x} record {full_index} sample {sample} byte {index}");
        assert!(
            rotation::parse_record(&mutated, binding(&corpus), &authorizers4).is_err(),
            "{label} xor 128"
        );
    }
    for sample in 0..16_u64 {
        let byte_index = prng.below(u64::try_from(other.wire.len()).expect("wire length"));
        let index = usize::try_from(byte_index).expect("byte index");
        let mut mutated = other.wire.as_bytes().to_vec();
        mutated[index] ^= 0x80;
        let label = format!("seed {SEED:#x} record {other_index} sample {sample} byte {index}");
        assert!(
            rotation::parse_record(&mutated, binding(&corpus), &authorizers2).is_err(),
            "{label} xor 128"
        );
    }
    assert_eq!(baseline_other.ordinal, other_index + 1, "seed {SEED:#x} other ordinal");
}

#[test]
fn line_targeted_mutations_fail_with_exact_codes() {
    let corpus = corpus();
    let mut prng = SplitMix64::new(SEED);
    let (_, records) = generated_chain(&corpus, 1, |index| 1000 + index);
    let record = records.first().expect("generated record");
    let authorizers = chain_authorizers(&records);
    let lines: Vec<String> = record.wire.split('\n').map(str::to_owned).collect();
    assert_eq!(lines.len(), 12, "seed {SEED:#x} wire line count");
    let baseline_label = format!("seed {SEED:#x} baseline parse");
    let parsed = rotation::parse_record(record.wire.as_bytes(), binding(&corpus), &authorizers)
        .expect(&baseline_label);
    let anchor_public = &corpus.keys["anchor"].public_key;

    let mut cases: Vec<(usize, String, &'static str)> = Vec::new();
    cases.push((0, "mcp-jack/server-key-rotation/min2".to_owned(), "domain"));
    cases.push((1, "!!!".to_owned(), "binding_encoding"));
    cases.push((1, encode_b64url(b"https://other.example.test/mcp"), "binding"));
    cases.push((2, "!!!".to_owned(), "binding_encoding"));
    cases.push((2, encode_b64url(b"https://other.example.test"), "binding"));
    for replacement in [
        "0",
        "01",
        "+1",
        "-1",
        "1.0",
        "1e0",
        "1E0",
        "9007199254740992",
        "99999999999999999999",
    ] {
        cases.push((3, replacement.to_owned(), "ordinal"));
    }
    cases.push((4, "x".to_owned(), "new_proof"));
    cases.push((5, "!".to_owned(), "key_id"));
    cases.push((5, encode_b64url(&prng_bytes(&mut prng)), "unknown_authorizer"));
    cases.push((6, "!".to_owned(), "key_id"));
    cases.push((6, encode_b64url(&prng_bytes(&mut prng)), "new_key_id"));
    let anchor_prefix = anchor_public.get(..42).expect("42-character prefix").to_owned();
    cases.push((7, anchor_prefix, "base64url"));
    cases.push((7, encode_b64url(&forced_invalid_key(&mut prng)), "new_key"));
    cases.push((8, "01".to_owned(), "timestamp"));
    cases.push((8, "-1".to_owned(), "timestamp"));
    cases.push((8, (parsed.published_at + 1).to_string(), "activation"));
    cases.push((9, "01".to_owned(), "timestamp"));
    cases.push((9, (parsed.activates_at + 1).to_string(), "activation"));
    cases.push((10, "!".to_owned(), "proof_encoding"));
    cases.push((11, "!".to_owned(), "proof_encoding"));
    for (line_index, replacement, expected) in cases {
        let mut mutated = lines.clone();
        *mutated.get_mut(line_index).expect("line") = replacement;
        let wire = mutated.join("\n");
        let label = format!("seed {SEED:#x} line {line_index} expects {expected}");
        assert_code(
            rotation::parse_record(wire.as_bytes(), binding(&corpus), &authorizers),
            expected,
            &label,
        );
    }

    // Первый символ proof меняют на другой валидный base64url-символ:
    // декодирование проходит, подпись ломается.
    for (line_index, expected) in [(10_usize, "new_proof"), (11, "old_authorization")] {
        let proof = lines.get(line_index).expect("proof line").clone();
        let first = proof.chars().next().expect("proof first character");
        let replacement = if first == 'A' { 'B' } else { 'A' };
        let flipped = format!("{replacement}{}", proof.get(1..).expect("proof tail"));
        assert_ne!(
            flipped, proof,
            "seed {SEED:#x} flip changed proof line {line_index}"
        );
        let mut mutated = lines.clone();
        *mutated.get_mut(line_index).expect("line") = flipped;
        let wire = mutated.join("\n");
        let label = format!("seed {SEED:#x} proof line {line_index} expects {expected}");
        assert_code(
            rotation::parse_record(wire.as_bytes(), binding(&corpus), &authorizers),
            expected,
            &label,
        );
    }

    let final_newline = record.wire.rfind('\n').expect("final newline");
    let without_last_line = record.wire.get(..final_newline).expect("prefix").to_owned();
    for (wire, expected) in [
        (format!("{}\n", record.wire), "trailing_lf"),
        (format!("\n{}", record.wire), "line_count"),
        (without_last_line, "line_count"),
    ] {
        let label = format!("seed {SEED:#x} whole wire expects {expected}");
        assert_code(
            rotation::parse_record(wire.as_bytes(), binding(&corpus), &authorizers),
            expected,
            &label,
        );
    }
}

struct HandParts<'a> {
    ordinal: u64,
    previous_hash: &'a str,
    old_kid: &'a str,
    old_signer: &'a InMemorySigner,
    new_kid: &'a str,
    new_public_b64u: &'a str,
    next_signer: &'a InMemorySigner,
    published_at: u64,
}

// Зеркало sign.rs: байты сообщений next-proof и authorize совпадают в точности.
fn hand_signed_wire(corpus: &Corpus, parts: HandParts<'_>) -> String {
    let body = [
        rotation::DOMAIN.to_owned(),
        encode_b64url(corpus.binding.endpoint.as_bytes()),
        encode_b64url(corpus.binding.aud.as_bytes()),
        parts.ordinal.to_string(),
        parts.previous_hash.to_owned(),
        parts.old_kid.to_owned(),
        parts.new_kid.to_owned(),
        parts.new_public_b64u.to_owned(),
        parts.published_at.to_string(),
        (parts.published_at + rotation::GRACE_SECONDS).to_string(),
    ]
    .join("\n");
    let next_message = format!("{}/next-proof\n{body}", rotation::DOMAIN);
    let next_signature = parts
        .next_signer
        .sign(next_message.as_bytes())
        .expect("next proof");
    let next_proof = encode_b64url(&next_signature);
    let old_message = format!("{}/authorize\n{body}\n{next_proof}", rotation::DOMAIN);
    let old_signature = parts
        .old_signer
        .sign(old_message.as_bytes())
        .expect("old proof");
    let old_proof = encode_b64url(&old_signature);
    format!("{body}\n{next_proof}\n{old_proof}")
}

fn chain_with_tail(
    corpus: &Corpus,
    root: &Checkpoint,
    records: &[Record],
    tail: &str,
) -> Result<Vec<Record>, RotationError> {
    let mut wires: Vec<&[u8]> = records.iter().map(|record| record.wire.as_bytes()).collect();
    wires.push(tail.as_bytes());
    rotation::verify_chain(&wires, binding(corpus), root, &BTreeMap::new())
}

#[test]
fn chain_order_duplication_gaps_and_signer_references_are_rejected() {
    let corpus = corpus();
    let (root, records) = generated_chain(&corpus, 5, |index| 1000 + index);
    assert_eq!(records.len(), 5, "seed {SEED:#x} chain length");
    let wires: Vec<&[u8]> = records.iter().map(|record| record.wire.as_bytes()).collect();
    let full_label = format!("seed {SEED:#x} full chain verifies");
    let verified = rotation::verify_chain(&wires, binding(&corpus), &root, &BTreeMap::new())
        .expect(&full_label);
    assert_eq!(verified.len(), 5, "seed {SEED:#x} verified length");

    let reorderings: &[(&str, for<'a> fn(&'a [&'a [u8]]) -> Vec<&'a [u8]>)] = &[
        ("swap first two wires", |wires: &[&[u8]]| {
            let mut reordered = wires.to_vec();
            reordered.swap(0, 1);
            reordered
        }),
        ("reverse all wires", |wires: &[&[u8]]| {
            let mut reordered = wires.to_vec();
            reordered.reverse();
            reordered
        }),
        ("duplicate the first wire", |wires: &[&[u8]]| {
            let mut reordered = wires.to_vec();
            let first = reordered.first().copied().expect("first wire");
            reordered.insert(1, first);
            reordered
        }),
        ("remove the third wire", |wires: &[&[u8]]| {
            let mut reordered = wires.to_vec();
            reordered.remove(2);
            reordered
        }),
        ("replace the second wire with the third", |wires: &[&[u8]]| {
            let mut reordered = wires.to_vec();
            let third = *reordered.get(2).expect("third wire");
            *reordered.get_mut(1).expect("second wire") = third;
            reordered
        }),
        ("append a copy of the last wire", |wires: &[&[u8]]| {
            let mut reordered = wires.to_vec();
            let last = *reordered.last().expect("last wire");
            reordered.push(last);
            reordered
        }),
    ];
    for (name, reorder) in reorderings {
        let mutated = reorder(&wires);
        let label = format!("seed {SEED:#x} {name}");
        assert_code(
            rotation::verify_chain(&mutated, binding(&corpus), &root, &BTreeMap::new()),
            "ordinal_sequence",
            &label,
        );
    }

    let (root3, records3) = generated_chain(&corpus, 3, |index| 1000 + index);
    assert_eq!(records3.len(), 3, "seed {SEED:#x} hand-signed base chain");
    let third = records3.get(2).expect("third record");
    let reuse_old = signer(3);
    let reused = signer(1);
    let reused_kid = key_id(&reused.public_key());
    let reused_public = encode_b64url(&reused.public_key());
    let key_reuse = hand_signed_wire(
        &corpus,
        HandParts {
            ordinal: 4,
            previous_hash: &third.hash,
            old_kid: &third.new_kid,
            old_signer: &reuse_old,
            new_kid: &reused_kid,
            new_public_b64u: &reused_public,
            next_signer: &reused,
            published_at: 1004,
        },
    );
    let label = format!("seed {SEED:#x} key reuse at ordinal 4");
    assert_code(
        chain_with_tail(&corpus, &root3, &records3, &key_reuse),
        "key_reuse",
        &label,
    );

    let non_adjacent_old = signer(2);
    let non_adjacent_next = signer(4);
    let non_adjacent_kid = key_id(&non_adjacent_next.public_key());
    let non_adjacent_public = encode_b64url(&non_adjacent_next.public_key());
    let adjacent_gap = hand_signed_wire(
        &corpus,
        HandParts {
            ordinal: 4,
            previous_hash: &third.hash,
            old_kid: &key_id(&non_adjacent_old.public_key()),
            old_signer: &non_adjacent_old,
            new_kid: &non_adjacent_kid,
            new_public_b64u: &non_adjacent_public,
            next_signer: &non_adjacent_next,
            published_at: 1004,
        },
    );
    let label = format!("seed {SEED:#x} non-adjacent authorizer");
    assert_code(
        chain_with_tail(&corpus, &root3, &records3, &adjacent_gap),
        "adjacency",
        &label,
    );

    let ordered_next = signer(4);
    let ordered_kid = key_id(&ordered_next.public_key());
    let ordered_public = encode_b64url(&ordered_next.public_key());
    let publication_order = hand_signed_wire(
        &corpus,
        HandParts {
            ordinal: 4,
            previous_hash: &third.hash,
            old_kid: &third.new_kid,
            old_signer: &reuse_old,
            new_kid: &ordered_kid,
            new_public_b64u: &ordered_public,
            next_signer: &ordered_next,
            published_at: third.published_at - 1,
        },
    );
    let label = format!("seed {SEED:#x} publication order regression");
    assert_code(
        chain_with_tail(&corpus, &root3, &records3, &publication_order),
        "publication_order",
        &label,
    );

    // Емкость retained-map: ровно MAX_RETAINED_KEYS с checkpoint kid внутри.
    let mut generated_keys: BTreeMap<String, [u8; 32]> = BTreeMap::new();
    let mut dropped_kid = String::new();
    for offset in 0..1153_u64 {
        let key = signer(1000 + offset);
        if offset == 0 {
            dropped_kid = key.kid().to_owned();
        }
        generated_keys.insert(key.kid().to_owned(), key.public_key());
    }
    assert_eq!(generated_keys.len(), 1153, "seed {SEED:#x} generated key count");
    let mut with_checkpoint = generated_keys.clone();
    with_checkpoint.insert(root.kid.clone(), root.public_key);
    with_checkpoint.remove(&dropped_kid);
    assert_eq!(with_checkpoint.len(), 1153, "seed {SEED:#x} retained with anchor");
    let kept_label = format!("seed {SEED:#x} retained map with the checkpoint kid");
    rotation::verify_chain(&[], binding(&corpus), &root, &with_checkpoint).expect(&kept_label);
    let label = format!("seed {SEED:#x} retained map without the checkpoint kid");
    assert_code(
        rotation::verify_chain(&[], binding(&corpus), &root, &generated_keys),
        "capacity",
        &label,
    );
    let mut oversized = generated_keys.clone();
    oversized.insert(root.kid.clone(), root.public_key);
    assert_eq!(oversized.len(), 1154, "seed {SEED:#x} retained past the limit");
    let label = format!("seed {SEED:#x} retained map one past the limit");
    assert_code(
        rotation::verify_chain(&[], binding(&corpus), &root, &oversized),
        "capacity",
        &label,
    );

    let filler = "A".repeat(100);
    let oversize_wires: Vec<&[u8]> = vec![filler.as_bytes(); 1154];
    let label = format!("seed {SEED:#x} wire count one past the limit");
    assert_code(
        rotation::verify_chain(&oversize_wires, binding(&corpus), &root, &BTreeMap::new()),
        "capacity",
        &label,
    );
    let limit_wires: Vec<&[u8]> = vec![filler.as_bytes(); 1153];
    let label = format!("seed {SEED:#x} wire count at the limit parses");
    assert_code(
        rotation::verify_chain(&limit_wires, binding(&corpus), &root, &BTreeMap::new()),
        "line_count",
        &label,
    );
}

#[test]
fn record_framing_bounds_hold_exactly_at_8192_bytes() {
    let corpus = corpus();
    let authorizers = BTreeMap::new();
    assert_eq!(rotation::MAX_RECORD_BYTES, 8192, "seed {SEED:#x} record limit");
    assert_code(
        rotation::parse_record(&[], binding(&corpus), &authorizers),
        "record_size",
        "seed {SEED:#x} empty wire",
    );
    assert_code(
        rotation::parse_record(&[b'A'; 8192], binding(&corpus), &authorizers),
        "line_count",
        "seed {SEED:#x} ascii wire at the size limit",
    );
    assert_code(
        rotation::parse_record(&[b'A'; 8193], binding(&corpus), &authorizers),
        "record_size",
        "seed {SEED:#x} ascii wire past the size limit",
    );
    assert_code(
        rotation::parse_record(&[0x80_u8; 8192], binding(&corpus), &authorizers),
        "non_ascii",
        "seed {SEED:#x} non-ascii wire at the size limit",
    );
}
