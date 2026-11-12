mod common;

use mcp_jack::client::{InMemorySigner, Signer};
use mcp_jack::encoding::key_id;
use mcp_jack::rotation::{
    self, Binding, Checkpoint, ClockTuple, DecodedResult, OwnedBinding, Record, ResultCursor,
    RotationError, ServerSnapshot, SignerReference, TrustKey, TrustSnapshot,
};
use serde::Deserialize;
use std::collections::BTreeMap;

const WINDOW: u64 = 30;

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
        public_key: mcp_jack::encoding::decode_b64url_fixed(&key.public_key, 32)
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

/// Реально подписанная цепочка с равным P: все ключи pending; возвращает и свой anchor.
fn signed_chain(corpus: &Corpus, count: u8) -> (Checkpoint, Vec<Record>) {
    let mut old = InMemorySigner::from_seed(&[0; 32]).expect("test signer");
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
        let next = InMemorySigner::from_seed(&[index; 32]).expect("distinct test signer");
        let record = rotation::create_record(binding(corpus), &previous, &old, &next, 1000)
            .expect("real Ed25519 overlap authorization");
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

/// Первый key — checkpoint; каждый record добавляет следующий (P = published_at последнего).
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

/// Каждому key соответствует opaque provider handle, не private-key material.
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

#[test]
fn protected_references_round_trip_without_entering_public_trust_or_aliasing() {
    let corpus = corpus();
    let root = anchor(&corpus);
    let input = server_from(trust_from(&corpus, &root, &overlapping(&corpus)));
    let encoded = encode(&input, &corpus, &root).expect("valid protected state");
    let loaded = decode(&encoded, &corpus, &root).expect("strict round trip");
    assert_eq!(loaded.signer_references, input.signer_references);
    assert_eq!(
        encode(&loaded, &corpus, &root).expect("canonical re-encode"),
        encoded
    );
    let public = rotation::encode_trust_snapshot(&loaded.public, binding(&corpus), WINDOW, &root)
        .expect("public trust encode");
    let public = String::from_utf8(public).expect("utf8 public trust");
    assert!(!public.contains("opaque-provider") && !public.contains("signer_refs"));
    // Reference — opaque handle: совпадение значений у разных kid не делает его key authority.
    let mut shared = input.clone();
    shared.signer_references[1].reference = shared.signer_references[0].reference.clone();
    validate(&shared, &corpus, &root).expect("opaque handles are not identities");
    let mut mutated = input;
    mutated.signer_references[0].reference.clear();
    mutated.public.records[0].clear();
    assert!(!loaded.signer_references[0].reference.is_empty());
    assert!(!loaded.public.records[0].is_empty());
}

#[test]
fn publication_accepts_exactly_one_fixed_p_overlapping_transition() {
    let corpus = corpus();
    let root = anchor(&corpus);
    let records = overlapping(&corpus);
    assert!(
        records[1].published_at < records[0].activates_at,
        "fixture must keep pending announcements overlapping"
    );
    let state = |count: usize| server_from(trust_from(&corpus, &root, &records[..count]));
    let publish = |from: &ServerSnapshot, to: &ServerSnapshot| {
        rotation::validate_server_publication(from, to, binding(&corpus), WINDOW, &root)
    };
    let (base, first, second) = (state(0), state(1), state(2));
    let accepted = publish(&base, &first).expect("first fixed-P publication");
    assert_eq!(accepted.public.revision, 2);
    publish(&first, &second).expect("pending-tail successor publication");
    unavailable(publish(&base, &second), "one publication batched two authorizations");
    unavailable(publish(&first, &first), "unchanged state treated as publication");
    unavailable(publish(&second, &first), "rollback treated as publication");
    let mutations: &[(&str, fn(&mut ServerSnapshot))] = &[
        ("revision skipped", |value| value.public.revision += 1),
        ("fixed P resampled or moved", |value| value.public.clock.high_water += 1),
        ("clock revision went backward", |value| value.public.clock.revision = 0),
        ("target fenced", |value| value.public.fenced = true),
        ("existing signer reference replaced", |value| {
            value.signer_references[0].reference = "replacement".to_owned()
        }),
    ];
    for (label, mutate) in mutations {
        let mut desired = first.clone();
        mutate(&mut desired);
        unavailable(publish(&base, &desired), label);
    }
    let mut fenced_base = base;
    fenced_base.public.fenced = true;
    unavailable(publish(&fenced_base, &first), "fenced base published");
}

#[test]
fn snapshot_rejects_missing_mismatched_oversized_and_inconsistent_references() {
    let corpus = corpus();
    let root = anchor(&corpus);
    let mutations: &[(&str, fn(&mut ServerSnapshot))] = &[
        ("format version", |value| value.format_version = 2),
        ("missing reference", |value| {
            value.signer_references.pop();
        }),
        ("kid mismatch", |value| {
            value.signer_references[0].kid = value.signer_references[1].kid.clone()
        }),
        ("empty reference", |value| value.signer_references[0].reference.clear()),
        ("oversized reference", |value| {
            value.signer_references[0].reference =
                "x".repeat(rotation::MAX_SIGNER_REFERENCE_BYTES + 1)
        }),
        ("oversized multibyte reference", |value| {
            value.signer_references[0].reference =
                "\u{e9}".repeat(rotation::MAX_SIGNER_REFERENCE_BYTES / 2 + 1)
        }),
        ("public key metadata", |value| value.public.keys[0].not_before += 1),
        ("record count", |value| {
            value.public.records.pop();
        }),
    ];
    for (label, mutate) in mutations {
        let mut input = server_from(trust_from(&corpus, &root, &overlapping(&corpus)));
        mutate(&mut input);
        unavailable(validate(&input, &corpus, &root), label);
        unavailable(encode(&input, &corpus, &root), label);
    }
    let mut boundary = server_from(trust_from(&corpus, &root, &overlapping(&corpus)));
    boundary.signer_references[0].reference = "x".repeat(rotation::MAX_SIGNER_REFERENCE_BYTES);
    validate(&boundary, &corpus, &root).expect("inclusive reference limit");
}

#[test]
fn codec_is_strict_order_independent_and_never_repairs_fences() {
    let corpus = corpus();
    let root = anchor(&corpus);
    let input = server_from(trust_from(&corpus, &root, &overlapping(&corpus)));
    let encoded = encode(&input, &corpus, &root).expect("encode");
    let encoded = String::from_utf8(encoded).expect("utf8 document");
    let negatives = [
        (r#""format_version":1"#, r#""format_version":1,"format_version":1"#),
        (r#""format_version":1"#, r#""format_version":1e0"#),
        (r#""reference":"#, r#""private_key":"forbidden","reference":"#),
        (r#""reference":"#, r#""reference":null,"reference":"#),
        (r#""signer_refs":["#, r#""extra":0,"signer_refs":["#),
    ];
    for (from, to) in negatives {
        let changed = encoded.replacen(from, to, 1);
        assert_ne!(changed, encoded, "negative token missing: {to}");
        unavailable(decode(changed.as_bytes(), &corpus, &root), to);
    }
    let trailing = format!("{encoded}x");
    for bytes in [&b""[..], b"[]", b"null", trailing.as_bytes()] {
        unavailable(decode(bytes, &corpus, &root), "malformed document");
    }
    let value: serde_json::Value = serde_json::from_str(&encoded).expect("positive schema");
    let pretty = serde_json::to_string_pretty(&value).expect("reordered pretty document");
    let reordered = decode(pretty.as_bytes(), &corpus, &root).expect("object order is not state");
    assert_eq!(
        encode(&reordered, &corpus, &root).expect("canonical re-encode"),
        encoded.as_bytes()
    );
    let mut fenced = input;
    fenced.public.fenced = true;
    fenced.public.clock.unsafe_clock = true;
    let stored = encode(&fenced, &corpus, &root).expect("inspection state encodes");
    let loaded = decode(&stored, &corpus, &root).expect("inspection state decodes");
    assert!(loaded.public.fenced && loaded.public.clock.unsafe_clock);
    assert!(!rotation::trust_clock_compatible(
        &loaded.public,
        &loaded.public.clock
    ));
}

fn arguments(ordinal: &str, hash: &str) -> String {
    format!(r#"{{"after_ordinal":{ordinal},"after_hash":"{hash}"}}"#)
}

#[test]
fn server_key_arguments_accept_only_one_canonical_cursor() {
    let corpus = corpus();
    let first = overlapping(&corpus).remove(0);
    let decode = |text: &str| rotation::decode_server_key_arguments(text.as_bytes());
    let cursor = |ordinal: u64, hash: &str| ResultCursor {
        ordinal,
        hash: hash.to_owned(),
    };
    assert_eq!(decode(&arguments("0", "-")).expect("zero"), cursor(0, "-"));
    assert_eq!(
        decode(&arguments("1", &first.hash)).expect("record cursor"),
        cursor(1, &first.hash)
    );
    // Порядок членов и whitespace не значимы; семантика не зависит от last-wins map.
    assert_eq!(
        decode(r#" { "after_hash" : "-" ,"after_ordinal" : 0 } "#).expect("reordered"),
        cursor(0, "-")
    );
    let maximum = rotation::MAX_ORDINAL.to_string();
    assert_eq!(
        decode(&arguments(&maximum, &first.hash))
            .expect("maximum safe integer")
            .ordinal,
        rotation::MAX_ORDINAL
    );
    // Последний символ canonical hash имеет нулевые trailing bits; "B" их нарушает.
    let trailing_bits = format!("{}B", &first.hash[..42]);
    assert_ne!(trailing_bits, first.hash);
    let bad = [
        String::new(),
        "null".to_owned(),
        "[]".to_owned(),
        "0".to_owned(),
        r#""x""#.to_owned(),
        "{}".to_owned(),
        r#"{"after_ordinal":0}"#.to_owned(),
        r#"{"after_hash":"-"}"#.to_owned(),
        r#"{"after_ordinal":0,"after_hash":"-","extra":1}"#.to_owned(),
        r#"{"after_ordinal":0,"after_ordinal":0,"after_hash":"-"}"#.to_owned(),
        r#"{"after_ordinal":0,"after_hash":"-","after_hash":"-"}"#.to_owned(),
        r#"{"after_ordinal":0,"after_hash":null}"#.to_owned(),
        r#"{"after_ordinal":null,"after_hash":"-"}"#.to_owned(),
        r#"{"after_ordinal":"0","after_hash":"-"}"#.to_owned(),
        r#"{"after_ordinal":0,"after_hash":0}"#.to_owned(),
        r#"{"after_ordinal":true,"after_hash":"-"}"#.to_owned(),
        r#"{"after_ordinal":[0],"after_hash":"-"}"#.to_owned(),
        r#"[0,"-"]"#.to_owned(),
        arguments("0.0", "-"),
        arguments("0e0", "-"),
        arguments("1E0", &first.hash),
        arguments("-0", "-"),
        arguments("-1", &first.hash),
        arguments("+1", &first.hash),
        arguments("01", &first.hash),
        arguments("9007199254740992", &first.hash),
        arguments("99999999999999999999", &first.hash),
        arguments("0", ""),
        arguments("0", &first.hash),
        arguments("0", "-="),
        arguments("1", "-"),
        arguments("1", ""),
        arguments("1", &format!("{}=", first.hash)),
        arguments("1", &first.hash[1..]),
        arguments("1", &format!("{}A", first.hash)),
        arguments("1", &format!("{}*", &first.hash[..42])),
        arguments("1", &trailing_bits),
    ];
    for text in &bad {
        let error = decode(text).expect_err(text);
        assert_eq!(error.code, "invalid_params", "{text}");
    }
    let error = rotation::decode_server_key_arguments(&[0xff]).expect_err("invalid utf-8");
    assert_eq!(error.code, "invalid_params");
}

fn page(
    snapshot: &ServerSnapshot,
    ordinal: u64,
    hash: &str,
    signer: &[u8; 32],
) -> Result<DecodedResult, RotationError> {
    let cursor = ResultCursor {
        ordinal,
        hash: hash.to_owned(),
    };
    rotation::server_key_page(snapshot, &cursor, signer)
}

#[test]
fn server_key_page_serves_one_ring_view_from_the_exact_cursor() {
    let corpus = corpus();
    let root = anchor(&corpus);
    let records = overlapping(&corpus);
    let snapshot = validate(
        &server_from(trust_from(&corpus, &root, &records)),
        &corpus,
        &root,
    )
    .expect("validated ring");
    let keys = &snapshot.public.keys;
    let full = page(&snapshot, 0, "-", &keys[0].public_key).expect("full page");
    assert_eq!(
        full,
        DecodedResult {
            current_kid: keys[0].kid.clone(),
            current_public_key: keys[0].public_key,
            records: vec![records[0].wire.clone(), records[1].wire.clone()],
            head_ordinal: 2,
            head_hash: records[1].hash.clone(),
            complete: true,
        }
    );
    let advanced = page(&snapshot, 1, &records[0].hash, &keys[2].public_key).expect("advanced");
    assert_eq!(advanced.records, vec![records[1].wire.clone()]);
    assert_eq!(advanced.current_kid, keys[2].kid);
    let caught_up = page(&snapshot, 2, &records[1].hash, &keys[0].public_key).expect("caught up");
    assert!(caught_up.records.is_empty() && caught_up.complete);
    assert_eq!(caught_up.head_hash, records[1].hash);
}

#[test]
fn server_key_page_is_bounded_to_16_records_and_always_advances() {
    let corpus = corpus();
    let (root, records) = signed_chain(&corpus, 20);
    let snapshot = validate(
        &server_from(trust_from(&corpus, &root, &records)),
        &corpus,
        &root,
    )
    .expect("validated 20-record ring");
    let signer = snapshot.public.keys[0].public_key;
    let wires = |range: std::ops::Range<usize>| -> Vec<String> {
        records[range].iter().map(|record| record.wire.clone()).collect()
    };
    let first = page(&snapshot, 0, "-", &signer).expect("first page");
    assert_eq!(first.records, wires(0..rotation::MAX_PAGE_RECORDS));
    assert!(!first.complete);
    assert_eq!(first.head_ordinal, 20);
    assert_eq!(first.head_hash, records[19].hash);
    let rest = page(&snapshot, 16, &records[15].hash, &signer).expect("remaining page");
    assert_eq!(rest.records, wires(16..20));
    assert!(rest.complete);
    // Ровно 16 записей до head: страница complete без пустого продолжения.
    let exact = validate(
        &server_from(trust_from(&corpus, &root, &records[..16])),
        &corpus,
        &root,
    )
    .expect("validated 16-record ring");
    let last = page(&exact, 0, "-", &signer).expect("exact page");
    assert_eq!(last.records.len(), 16);
    assert!(last.complete);
}

#[test]
fn server_key_page_refuses_cursors_outside_the_ring_and_foreign_signers() {
    let corpus = corpus();
    let root = anchor(&corpus);
    let records = overlapping(&corpus);
    let snapshot = validate(
        &server_from(trust_from(&corpus, &root, &records)),
        &corpus,
        &root,
    )
    .expect("validated ring");
    let signer = snapshot.public.keys[0].public_key;
    let (first, second) = (&records[0].hash, &records[1].hash);
    let refused: [(u64, &str); 8] = [
        (0, first),
        (0, ""),
        (1, "-"),
        (1, second),
        (2, first),
        (3, second),
        (rotation::MAX_ORDINAL, second),
        (1, "not a hash"),
    ];
    for (ordinal, hash) in refused {
        let error = page(&snapshot, ordinal, hash, &signer).expect_err("cursor outside ring");
        assert_eq!(error.code, "rotation_checkpoint_unavailable", "{ordinal}:{hash}");
    }
    // Подписант вне ring никогда не получает fallback на другой key.
    let mut outsider = signer;
    outsider[0] ^= 1;
    let error = page(&snapshot, 0, "-", &outsider).expect_err("foreign signer");
    assert_eq!(error.code, "rotation_state_unavailable");
}

#[test]
fn server_key_page_honors_a_retained_checkpoint() {
    let corpus = corpus();
    let records = overlapping(&corpus);
    let base = Checkpoint {
        ordinal: records[0].ordinal,
        hash: records[0].hash.clone(),
        kid: records[0].new_kid.clone(),
        public_key: records[0].public_key,
        published_at: records[0].published_at,
    };
    let snapshot = validate(
        &server_from(trust_from(&corpus, &base, &records[1..])),
        &corpus,
        &base,
    )
    .expect("validated retained ring");
    let signer = base.public_key;
    let kept = page(&snapshot, 1, &base.hash, &signer).expect("checkpoint cursor");
    assert_eq!(kept.records, vec![records[1].wire.clone()]);
    assert!(kept.complete);
    let head = page(&snapshot, 2, &records[1].hash, &signer).expect("head cursor");
    assert!(head.records.is_empty());
    for (ordinal, hash) in [(0, "-"), (1, records[1].hash.as_str())] {
        let error = page(&snapshot, ordinal, hash, &signer).expect_err("older or wrong cursor");
        assert_eq!(error.code, "rotation_checkpoint_unavailable", "{ordinal}");
    }
}
