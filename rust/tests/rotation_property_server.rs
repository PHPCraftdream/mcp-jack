// Deterministic property tests of the server layer (snapshot codec, publication,
// key pages, private store): a fixed seed reproduces every refusal.
mod common;

use mcp_jack::client::{InMemorySigner, Signer};
use mcp_jack::encoding::{decode_b64url_fixed, key_id};
use mcp_jack::rotation::{
    self, Binding, Checkpoint, ClockTuple, OwnedBinding, Record, ResultCursor, RotationError,
    ServerSnapshot, SignerReference, TrustKey, TrustSnapshot,
};
use serde::Deserialize;
use std::collections::BTreeMap;

const WINDOW: u64 = 30;
const SEED: u64 = 0x5eed_00b3;

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
    valid_chains: BTreeMap<String, Vec<String>>,
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

fn anchor(corpus: &Corpus) -> Checkpoint {
    let key = &corpus.keys["anchor"];
    Checkpoint {
        ordinal: 0,
        hash: "-".to_owned(),
        kid: key.kid.clone(),
        public_key: decode_b64url_fixed(&key.public_key, 32)
            .expect("fixture key")
            .try_into()
            .expect("32 bytes"),
        published_at: 0,
    }
}

fn overlapping(corpus: &Corpus) -> Vec<Record> {
    let wires: Vec<&[u8]> = corpus.valid_chains["overlapping"]
        .iter()
        .map(String::as_bytes)
        .collect();
    rotation::verify_chain(&wires, binding(corpus), &anchor(corpus), &BTreeMap::new())
        .expect("independent valid chain")
}

// Deterministic PRNG: a fixed seed reproduces every refusal.
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

// More than 255 distinct indices: the seed is derived from the PRNG, not from a single byte.
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
        let record =
            rotation::create_record(binding(corpus), &previous, &old, &next, published_at(index))
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

fn prng_bytes(prng: &mut SplitMix64) -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    for value in &mut bytes {
        *value = u8::try_from(prng.below(256)).expect("byte");
    }
    bytes
}

fn flip_first_char(text: &str) -> String {
    let first = text.chars().next().expect("non-empty string");
    let replacement = if first == 'A' { 'B' } else { 'A' };
    let flipped = format!(
        "{replacement}{}",
        text.get(first.len_utf8()..).expect("tail")
    );
    assert_ne!(flipped, text, "flip must change the string");
    flipped
}

// Opaque string of a given BYTE length 1..=1024: lowercase letters and occasional 'é'
// (2 UTF-8 bytes), so the byte-length stays within the limit.
fn opaque_reference(prng: &mut SplitMix64) -> String {
    let target = usize::try_from(prng.below(1024) + 1).expect("reference length");
    let mut reference = String::new();
    while reference.len() < target {
        let remaining = target - reference.len();
        if remaining >= 2 && prng.below(16) == 0 {
            reference.push('\u{e9}');
        } else {
            let offset = u8::try_from(prng.below(26)).expect("letter offset");
            reference.push(char::from(b'a' + offset));
        }
    }
    assert_eq!(reference.len(), target, "reference byte length");
    reference
}

/// The first key is the checkpoint; each record adds the next one (P = published_at of the last).
fn trust_from(corpus: &Corpus, root: &Checkpoint, records: &[Record]) -> TrustSnapshot {
    let owned = OwnedBinding {
        endpoint: corpus.binding.endpoint.clone(),
        aud: corpus.binding.aud.clone(),
    };
    let mut keys = vec![TrustKey {
        ordinal: root.ordinal,
        kid: root.kid.clone(),
        public_key: root.public_key,
        not_before: if root.ordinal == 0 {
            0
        } else {
            root.published_at + rotation::GRACE_SECONDS
        },
        known_cutoff: None,
    }];
    let mut head = ResultCursor {
        ordinal: root.ordinal,
        hash: root.hash.clone(),
    };
    let mut high_water = root.published_at;
    for record in records {
        keys.last_mut().expect("anchor/tail").known_cutoff = Some(record.activates_at);
        keys.push(TrustKey {
            ordinal: record.ordinal,
            kid: record.new_kid.clone(),
            public_key: record.public_key,
            not_before: record.activates_at,
            known_cutoff: None,
        });
        head = ResultCursor {
            ordinal: record.ordinal,
            hash: record.hash.clone(),
        };
        high_water = record.published_at;
    }
    let revision = u64::try_from(records.len()).expect("small chain") + 1;
    TrustSnapshot {
        format_version: 1,
        binding: owned.clone(),
        window: WINDOW,
        checkpoint: root.clone(),
        head,
        records: records.iter().map(|record| record.wire.clone()).collect(),
        keys,
        revision,
        fenced: false,
        clock: ClockTuple {
            binding: owned,
            window: WINDOW,
            high_water,
            revision,
            unsafe_clock: false,
        },
    }
}

/// Each key maps to an opaque provider handle, not private-key material.
// Mutation name and its in-place application to the snapshot.
type Mutation = (&'static str, fn(&mut ServerSnapshot));

fn server_from(public: TrustSnapshot) -> ServerSnapshot {
    let signer_references = public
        .keys
        .iter()
        .map(|key| SignerReference {
            kid: key.kid.clone(),
            reference: format!("opaque-provider/{}", key.kid),
        })
        .collect();
    ServerSnapshot {
        format_version: 1,
        public,
        signer_references,
    }
}

fn validate(
    input: &ServerSnapshot,
    corpus: &Corpus,
    root: &Checkpoint,
) -> Result<ServerSnapshot, RotationError> {
    rotation::validate_server_snapshot(input, binding(corpus), WINDOW, root)
}

fn encode(
    input: &ServerSnapshot,
    corpus: &Corpus,
    root: &Checkpoint,
) -> Result<Vec<u8>, RotationError> {
    rotation::encode_server_snapshot(input, binding(corpus), WINDOW, root)
}

fn decode(
    bytes: &[u8],
    corpus: &Corpus,
    root: &Checkpoint,
) -> Result<ServerSnapshot, RotationError> {
    rotation::decode_server_snapshot(bytes, binding(corpus), WINDOW, root)
}

fn unavailable(result: Result<impl std::fmt::Debug, RotationError>, label: &str) {
    let error = result.expect_err(label);
    assert_eq!(error.code, "rotation_state_unavailable", "{label}");
}

// Required fields must remain unchanged; free fields (fenced,
// revision, clock.high_water/revision/unsafe, reference text) may differ.
fn assert_only_free_fields_changed(
    original: &ServerSnapshot,
    decoded: &ServerSnapshot,
    label: &str,
) {
    let mut changed: Vec<String> = Vec::new();
    let mut same = |name: &str, ok: bool| {
        if !ok {
            changed.push(name.to_owned());
        }
    };
    same(
        "public.binding",
        decoded.public.binding == original.public.binding,
    );
    same(
        "public.window",
        decoded.public.window == original.public.window,
    );
    same(
        "checkpoint.ordinal",
        decoded.public.checkpoint.ordinal == original.public.checkpoint.ordinal,
    );
    same(
        "checkpoint.hash",
        decoded.public.checkpoint.hash == original.public.checkpoint.hash,
    );
    same(
        "checkpoint.kid",
        decoded.public.checkpoint.kid == original.public.checkpoint.kid,
    );
    same(
        "checkpoint.public_key",
        decoded.public.checkpoint.public_key == original.public.checkpoint.public_key,
    );
    same(
        "checkpoint.published_at",
        decoded.public.checkpoint.published_at == original.public.checkpoint.published_at,
    );
    same(
        "head.ordinal",
        decoded.public.head.ordinal == original.public.head.ordinal,
    );
    same(
        "head.hash",
        decoded.public.head.hash == original.public.head.hash,
    );
    same(
        "public.records",
        decoded.public.records == original.public.records,
    );
    same(
        "keys.len",
        decoded.public.keys.len() == original.public.keys.len(),
    );
    for (index, decoded_key) in decoded.public.keys.iter().enumerate() {
        let original_key = original.public.keys.get(index).expect("original key");
        let position = format!("keys[{index}]");
        same(
            &format!("{position}.ordinal"),
            decoded_key.ordinal == original_key.ordinal,
        );
        same(
            &format!("{position}.kid"),
            decoded_key.kid == original_key.kid,
        );
        same(
            &format!("{position}.public_key"),
            decoded_key.public_key == original_key.public_key,
        );
        same(
            &format!("{position}.not_before"),
            decoded_key.not_before == original_key.not_before,
        );
        same(
            &format!("{position}.known_cutoff"),
            decoded_key.known_cutoff == original_key.known_cutoff,
        );
    }
    same(
        "clock.binding",
        decoded.public.clock.binding == original.public.clock.binding,
    );
    same(
        "clock.window",
        decoded.public.clock.window == original.public.clock.window,
    );
    same(
        "format_version",
        decoded.format_version == original.format_version,
    );
    same(
        "signer_references.len",
        decoded.signer_references.len() == original.signer_references.len(),
    );
    for (index, decoded_reference) in decoded.signer_references.iter().enumerate() {
        let original_reference = original
            .signer_references
            .get(index)
            .expect("original reference");
        same(
            &format!("signer_references[{index}].kid"),
            decoded_reference.kid == original_reference.kid,
        );
    }
    assert!(
        changed.is_empty(),
        "{label}: mutated must fields {changed:?}"
    );
}

#[test]
fn generated_server_snapshots_round_trip_and_freeze() {
    let corpus = corpus();
    let mut prng = SplitMix64::new(SEED);
    for count in [0_u64, 1, 2, 4] {
        let (root, records) = generated_chain(&corpus, count, |index| 1000 + index);
        let mut snapshot = server_from(trust_from(&corpus, &root, &records));
        for reference in &mut snapshot.signer_references {
            reference.reference = opaque_reference(&mut prng);
        }
        let label = format!("seed {SEED:#x} chain {count}");
        let validated = validate(&snapshot, &corpus, &root).expect(&label);
        let encoded = encode(&snapshot, &corpus, &root).expect(&label);
        let decoded = decode(&encoded, &corpus, &root).expect(&label);
        assert_eq!(
            decoded.signer_references, validated.signer_references,
            "{label} references survive the round trip"
        );
        assert_eq!(
            encode(&decoded, &corpus, &root).expect(&label),
            encoded,
            "{label} canonical re-encode"
        );
    }

    // Boundary: the first reference of exactly MAX_SIGNER_REFERENCE_BYTES is accepted;
    // one byte longer is refused by both validate and encode.
    let (root, records) = generated_chain(&corpus, 2, |index| 1000 + index);
    let mut boundary = server_from(trust_from(&corpus, &root, &records));
    let reference = boundary
        .signer_references
        .first_mut()
        .expect("anchor reference");
    reference.reference = "x".repeat(rotation::MAX_SIGNER_REFERENCE_BYTES);
    validate(&boundary, &corpus, &root).expect("inclusive reference limit");
    let mut oversized = boundary;
    let reference = oversized
        .signer_references
        .first_mut()
        .expect("anchor reference");
    reference.reference = "x".repeat(rotation::MAX_SIGNER_REFERENCE_BYTES + 1);
    let label = format!("seed {SEED:#x} reference past the limit");
    unavailable(validate(&oversized, &corpus, &root), &label);
    unavailable(encode(&oversized, &corpus, &root), &label);
}

#[test]
fn every_single_byte_mutation_of_a_stored_server_snapshot_is_refused_or_confined_to_free_fields() {
    let corpus = corpus();
    let root = anchor(&corpus);
    let input = ServerSnapshot {
        format_version: 1,
        public: trust_from(&corpus, &root, &[]),
        signer_references: vec![SignerReference {
            kid: root.kid.clone(),
            reference: "opaque-provider/anchor".to_owned(),
        }],
    };
    let label = format!("seed {SEED:#x} anchor encoding");
    let encoded = encode(&input, &corpus, &root).expect(&label);
    for (byte_index, byte) in encoded.iter().enumerate() {
        let mut mutated = encoded.clone();
        mutated[byte_index] = *byte ^ 1;
        let label = format!("seed {SEED:#x} anchor byte {byte_index}");
        if let Ok(decoded) = decode(&mutated, &corpus, &root) {
            assert_only_free_fields_changed(&input, &decoded, &label);
        }
    }

    let (ring_root, records) = generated_chain(&corpus, 2, |index| 1000 + index);
    let mut prng = SplitMix64::new(SEED);
    let document = server_from(trust_from(&corpus, &ring_root, &records));
    let label = format!("seed {SEED:#x} ring encoding");
    let encoded_document = encode(&document, &corpus, &ring_root).expect(&label);
    let length = u64::try_from(encoded_document.len()).expect("document length");
    for sample in 0..128_u64 {
        let byte_index = usize::try_from(prng.below(length)).expect("byte index");
        let mut mutated = encoded_document.clone();
        mutated[byte_index] ^= 0x80;
        let label = format!("seed {SEED:#x} ring sample {sample} byte {byte_index}");
        if let Ok(decoded) = decode(&mutated, &corpus, &ring_root) {
            assert_only_free_fields_changed(&document, &decoded, &label);
        }
    }

    let label = format!("seed {SEED:#x} anchor positive control");
    let decoded = decode(&encoded, &corpus, &root).expect(&label);
    assert_eq!(
        encode(&decoded, &corpus, &root).expect(&label),
        encoded,
        "{label} canonical"
    );
    let label = format!("seed {SEED:#x} ring positive control");
    let decoded = decode(&encoded_document, &corpus, &ring_root).expect(&label);
    assert_eq!(
        encode(&decoded, &corpus, &ring_root).expect(&label),
        encoded_document,
        "{label} canonical"
    );
}

#[test]
fn publication_accepts_exactly_one_fixed_p_record_and_refuses_every_single_field_violation() {
    let corpus = corpus();
    let run_shape = |shape: &str, root: &Checkpoint, records: Vec<Record>| {
        let states: Vec<ServerSnapshot> = (0..=records.len())
            .map(|count| server_from(trust_from(&corpus, root, &records[..count])))
            .collect();
        let publish = |from: &ServerSnapshot, to: &ServerSnapshot| {
            rotation::validate_server_publication(from, to, binding(&corpus), WINDOW, root)
        };
        for n in 0..records.len() {
            let from = states.get(n).expect("state");
            let to = states.get(n + 1).expect("successor state");
            let label = format!("seed {SEED:#x} {shape} publication {n}");
            let accepted = publish(from, to).expect(&label);
            let expected = u64::try_from(n).expect("small index") + 2;
            assert_eq!(accepted.public.revision, expected, "{label} revision");
        }
        let base = states.first().expect("base state").clone();
        let first = states.get(1).expect("first state").clone();
        let second = states.get(2).expect("second state").clone();
        let label = format!("seed {SEED:#x} {shape} two records in one publication");
        unavailable(publish(&base, &second), &label);
        let label = format!("seed {SEED:#x} {shape} unchanged state");
        unavailable(publish(&first, &first), &label);

        let mutations: &[Mutation] = &[
            ("revision+1", |value| value.public.revision += 1),
            ("revision 0", |value| value.public.revision = 0),
            ("clock.high_water+1", |value| {
                value.public.clock.high_water += 1
            }),
            ("clock.high_water-1", |value| {
                value.public.clock.high_water -= 1
            }),
            ("clock window changed", |value| {
                value.public.clock.window += 1
            }),
            ("clock.revision 0", |value| value.public.clock.revision = 0),
            ("clock.unsafe", |value| {
                value.public.clock.unsafe_clock = true
            }),
            ("fenced desired", |value| value.public.fenced = true),
            ("records pop", |value| {
                value.public.records.pop();
            }),
            ("records duplicate last", |value| {
                let last = value.public.records.last().expect("last record").clone();
                value.public.records.push(last);
            }),
            ("records push extra", |value| {
                value.public.records.push("x".to_owned());
            }),
            ("keys pop", |value| {
                value.public.keys.pop();
            }),
            ("keys swap last two", |value| {
                let length = value.public.keys.len();
                value.public.keys.swap(length - 2, length - 1);
            }),
            ("keys not_before+1", |value| {
                value.public.keys.last_mut().expect("new key").not_before += 1;
            }),
            ("keys not_before-1", |value| {
                value.public.keys.last_mut().expect("new key").not_before -= 1;
            }),
            ("head ordinal+1", |value| value.public.head.ordinal += 1),
            ("head hash changed", |value| {
                value.public.head.hash = flip_first_char(&value.public.head.hash);
            }),
            ("references pop", |value| {
                value.signer_references.pop();
            }),
            ("references swap", |value| {
                value.signer_references.swap(0, 1)
            }),
            ("references replaced text", |value| {
                value.signer_references[0].reference = "replacement".to_owned()
            }),
            ("references replaced kid", |value| {
                value.signer_references[0].kid = value.signer_references[1].kid.clone()
            }),
            ("references push extra", |value| {
                let extra = value.signer_references.first().expect("reference").clone();
                value.signer_references.push(extra);
            }),
        ];
        for (name, mutate) in mutations {
            let mut desired = first.clone();
            mutate(&mut desired);
            let label = format!("seed {SEED:#x} {shape} {name}");
            unavailable(publish(&base, &desired), &label);
        }

        // states[1] has only one record; the swap of the last two is checked on the pair 1 -> 2.
        let mut swapped = second.clone();
        let length = swapped.public.records.len();
        swapped.public.records.swap(length - 2, length - 1);
        let label = format!("seed {SEED:#x} {shape} records swap last two");
        unavailable(publish(&first, &swapped), &label);

        // Replacing the last record with a wire from a DIFFERENT generated chain.
        let (_, foreign) = generated_chain(&corpus, 4, |index| 2000 + index);
        let mut replaced = first.clone();
        let foreign_wire = foreign.first().expect("foreign record").wire.clone();
        *replaced.public.records.last_mut().expect("last record") = foreign_wire;
        let label = format!("seed {SEED:#x} {shape} records replace last");
        unavailable(publish(&base, &replaced), &label);

        // Bumping only the revision, without a new record — from the base side.
        let mut bumped = base.clone();
        bumped.public.revision += 1;
        let label = format!("seed {SEED:#x} {shape} revision only bump");
        unavailable(publish(&bumped, &first), &label);

        let mut fenced = base.clone();
        fenced.public.fenced = true;
        let label = format!("seed {SEED:#x} {shape} fenced base");
        unavailable(publish(&fenced, &first), &label);
    };
    run_shape("fixture", &anchor(&corpus), overlapping(&corpus));
    let (generated_root, generated) = generated_chain(&corpus, 4, |index| 1000 + index);
    run_shape("generated", &generated_root, generated);
}

#[test]
fn server_key_pages_serve_generated_rings_exactly_and_refuse_wrong_cursors() {
    let corpus = corpus();
    let mut prng = SplitMix64::new(SEED);
    let (root, records) = generated_chain(&corpus, 20, |index| 1000 + index);
    assert_eq!(records.len(), 20, "seed {SEED:#x} ring length");
    let snapshot = validate(
        &server_from(trust_from(&corpus, &root, &records)),
        &corpus,
        &root,
    )
    .expect("validated 20-record ring");
    let signer = snapshot.public.keys.first().expect("first key").public_key;
    let wires: Vec<String> = records.iter().map(|record| record.wire.clone()).collect();
    for k in 0..=20_u64 {
        let index = usize::try_from(k).expect("cursor index");
        let cursor = ResultCursor {
            ordinal: k,
            hash: if k == 0 {
                "-".to_owned()
            } else {
                records.get(index - 1).expect("cursor record").hash.clone()
            },
        };
        let label = format!("seed {SEED:#x} cursor {k}");
        let page = rotation::server_key_page(&snapshot, &cursor, &signer).expect(&label);
        let end = (index + rotation::MAX_PAGE_RECORDS).min(records.len());
        let expected = wires.get(index..end).expect("page wires");
        assert_eq!(page.records, expected, "{label} exact records");
        assert_eq!(
            page.complete,
            index + rotation::MAX_PAGE_RECORDS >= records.len(),
            "{label} complete flag"
        );
        assert_eq!(page.head_ordinal, 20, "{label} head ordinal");
        assert_eq!(
            page.head_hash,
            records.get(19).expect("tail record").hash,
            "{label} head hash"
        );
        assert_eq!(
            page.current_kid,
            snapshot.public.keys.first().expect("first key").kid,
            "{label} current kid"
        );
    }
    for k in 1..=20_u64 {
        let index = usize::try_from(k).expect("cursor index");
        let wrong = records
            .get((index + 3) % 20)
            .expect("wrong record")
            .hash
            .clone();
        let correct = records.get(index - 1).expect("cursor record").hash.clone();
        assert_ne!(wrong, correct, "seed {SEED:#x} wrong hash for cursor {k}");
        let cursor = ResultCursor {
            ordinal: k,
            hash: wrong,
        };
        let label = format!("seed {SEED:#x} wrong-hash cursor {k}");
        let error = rotation::server_key_page(&snapshot, &cursor, &signer).expect_err(&label);
        assert_eq!(error.code, "rotation_checkpoint_unavailable", "{label}");
    }
    let far = ResultCursor {
        ordinal: 21,
        hash: records.get(19).expect("tail record").hash.clone(),
    };
    let label = format!("seed {SEED:#x} cursor past the head");
    let error = rotation::server_key_page(&snapshot, &far, &signer).expect_err(&label);
    assert_eq!(error.code, "rotation_checkpoint_unavailable", "{label}");

    let unknown = prng_bytes(&mut prng);
    let cursor = ResultCursor {
        ordinal: 0,
        hash: "-".to_owned(),
    };
    let label = format!("seed {SEED:#x} unknown signer");
    let error = rotation::server_key_page(&snapshot, &cursor, &unknown).expect_err(&label);
    assert_eq!(error.code, "rotation_state_unavailable", "{label}");

    let prefix = records.get(..17).expect("17-record prefix");
    let bounded = validate(
        &server_from(trust_from(&corpus, &root, prefix)),
        &corpus,
        &root,
    )
    .expect("validated 17-record ring");
    let bounded_signer = bounded.public.keys.first().expect("first key").public_key;
    let label = format!("seed {SEED:#x} first bounded page");
    let first_page = rotation::server_key_page(
        &bounded,
        &ResultCursor {
            ordinal: 0,
            hash: "-".to_owned(),
        },
        &bounded_signer,
    )
    .expect(&label);
    assert_eq!(
        first_page.records.len(),
        16,
        "seed {SEED:#x} first page records"
    );
    assert!(!first_page.complete, "seed {SEED:#x} first page incomplete");
    let label = format!("seed {SEED:#x} second bounded page");
    let second_page = rotation::server_key_page(
        &bounded,
        &ResultCursor {
            ordinal: 1,
            hash: records.first().expect("first record").hash.clone(),
        },
        &bounded_signer,
    )
    .expect(&label);
    assert_eq!(
        second_page.records.len(),
        16,
        "seed {SEED:#x} second page records"
    );
    assert!(second_page.complete, "seed {SEED:#x} second page complete");
}

// Store tests are Linux-only: RotationServerStore is available only there.
// All imports are inside the module so the windows build sees no unused use.
#[cfg(target_os = "linux")]
mod linux_store {
    use super::{anchor, corpus, SplitMix64, SEED};
    use mcp_jack::rotation::{OwnedBinding, RotationServerStore, RotationServerStoreOptions};
    use std::fs;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    use std::path::{Path, PathBuf};

    struct Sandbox(PathBuf);

    impl Drop for Sandbox {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    // The store file must have mode 0600 and live in a 0700 directory:
    // private_file::directory checks both before reading.
    fn write_file(path: &Path, bytes: &[u8]) {
        use std::io::Write;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .expect("sandbox file");
        file.write_all(bytes).expect("sandbox write");
    }

    #[test]
    fn private_store_files_refuse_every_single_byte_corruption() {
        let corpus_data = corpus();
        let root = anchor(&corpus_data);
        let options = RotationServerStoreOptions {
            binding: OwnedBinding {
                endpoint: corpus_data.binding.endpoint.clone(),
                aud: corpus_data.binding.aud.clone(),
            },
            window: 30,
            checkpoint: root.clone(),
            anchor_reference: "opaque-provider/anchor".to_owned(),
        };
        let dir = std::env::temp_dir().join(format!(
            "mcp-jack-rotation-property-{}-{}",
            std::process::id(),
            line!()
        ));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .expect("sandbox dir");
        let sandbox = Sandbox(dir);

        let path = sandbox.0.join("ring");
        let label = format!("seed {SEED:#x} initialize store");
        RotationServerStore::initialize_unused(&path, options.clone(), || Ok(1000)).expect(&label);
        let original = fs::read(&path).expect("store file bytes");

        // Positive control: the original bytes open and give revision 1.
        let control = sandbox.0.join("control");
        write_file(&control, &original);
        let label = format!("seed {SEED:#x} control open");
        let mut store =
            RotationServerStore::open(&control, options.clone(), || Ok(1000)).expect(&label);
        let label = format!("seed {SEED:#x} control snapshot");
        let (control_snapshot, _) = store.snapshot().expect(&label);
        assert_eq!(
            control_snapshot.public.revision, 1,
            "seed {SEED:#x} control revision"
        );
        store.close().expect("control close");

        let mut prng = SplitMix64::new(SEED);
        let file_length = u64::try_from(original.len()).expect("file length");
        let mut exercised = 0_usize;
        for (byte_index, byte) in original.iter().enumerate() {
            let mut mutated = original.clone();
            mutated[byte_index] = *byte ^ 1;
            let case_path = sandbox.0.join(format!("case-{byte_index}"));
            write_file(&case_path, &mutated);
            let label = format!("seed {SEED:#x} byte {byte_index} xor 1");
            let error = RotationServerStore::open(&case_path, options.clone(), || Ok(1000))
                .err()
                .expect(&label);
            assert_eq!(error.code, "rotation_state_unavailable", "{label}");
            exercised += 1;
        }
        for sample in 0..24_u64 {
            let byte_index = usize::try_from(prng.below(file_length)).expect("byte index");
            let mut mutated = original.clone();
            mutated[byte_index] ^= 0x80;
            let case_path = sandbox.0.join(format!("sample-{sample}"));
            write_file(&case_path, &mutated);
            let label = format!("seed {SEED:#x} sample {sample} byte {byte_index} xor 128");
            let error = RotationServerStore::open(&case_path, options.clone(), || Ok(1000))
                .err()
                .expect(&label);
            assert_eq!(error.code, "rotation_state_unavailable", "{label}");
        }
        assert_eq!(
            exercised,
            original.len(),
            "seed {SEED:#x} full file sweep coverage"
        );
    }
}
