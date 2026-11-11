mod common;

use mcp_jack::client::{InMemorySigner, Signer};
use mcp_jack::encoding::{body_hash, decode_b64url_fixed, encode_b64url, key_id};
use mcp_jack::rotation::{
    self, Binding, Checkpoint, ClockTuple, OwnedBinding, Record, ResultCursor, TrustKey,
    TrustSnapshot,
};
use serde::Deserialize;
use std::collections::BTreeMap;

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

fn checkpoint(corpus: &Corpus) -> Checkpoint {
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

fn snapshot_from(
    binding: Binding<'_>,
    root: &Checkpoint,
    records: &[Record],
    high_water: u64,
) -> TrustSnapshot {
    let owned = OwnedBinding {
        endpoint: binding.endpoint.to_owned(),
        aud: binding.aud.to_owned(),
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
    }
    TrustSnapshot {
        format_version: 1,
        binding: owned.clone(),
        window: 30,
        checkpoint: root.clone(),
        head,
        records: records.iter().map(|record| record.wire.clone()).collect(),
        keys,
        revision: 7,
        fenced: false,
        clock: ClockTuple {
            binding: owned,
            window: 30,
            high_water,
            revision: 1,
            unsafe_clock: false,
        },
    }
}

fn example(corpus: &Corpus) -> TrustSnapshot {
    let wires: Vec<&[u8]> = corpus.valid_chains["overlapping"]
        .iter()
        .map(String::as_bytes)
        .collect();
    let root = checkpoint(corpus);
    let records = rotation::verify_chain(&wires, binding(corpus), &root, &BTreeMap::new())
        .expect("independent valid chain");
    let high_water = records.last().expect("overlap records").published_at;
    snapshot_from(binding(corpus), &root, &records, high_water)
}

fn validate(
    input: &TrustSnapshot,
    corpus: &Corpus,
) -> Result<TrustSnapshot, rotation::RotationError> {
    rotation::validate_trust_snapshot(input, binding(corpus), 30, &checkpoint(corpus))
}

#[test]
fn whole_trust_validates_fixture_intervals_and_returns_owned_values() {
    let corpus = corpus();
    let mut input = example(&corpus);
    let output = validate(&input, &corpus).expect("whole trusted value");
    assert_eq!(output.records, corpus.valid_chains["overlapping"]);
    assert_eq!(output.head, input.head);
    assert_eq!(output.keys, input.keys);
    assert!(rotation::trust_clock_compatible(&output, &output.clock));
    input.records[0].clear();
    input.keys[0].kid.clear();
    input.checkpoint.kid.clear();
    input.binding.endpoint.clear();
    input.clock.binding.aud.clear();
    assert!(validate(&output, &corpus).is_ok());
    assert!(!output.records[0].is_empty());
    assert_eq!(output.keys[0].kid, checkpoint(&corpus).kid);
    assert_eq!(output.binding.endpoint, corpus.binding.endpoint);
    assert_eq!(output.clock.binding.aud, corpus.binding.aud);
}

#[test]
fn whole_trust_rejects_every_redundant_identity_time_or_shape_mutation() {
    let corpus = corpus();
    let mutations: &[fn(&mut TrustSnapshot)] = &[
        |value| value.format_version = 2,
        |value| value.binding.aud.push('x'),
        |value| value.window = 31,
        |value| value.checkpoint.published_at = 1,
        |value| value.checkpoint.public_key[0] ^= 1,
        |value| value.head.ordinal = 0,
        |value| value.head.hash.clear(),
        |value| value.records[0].push('\n'),
        |value| value.keys[0].ordinal = 1,
        |value| value.keys[0].kid.clear(),
        |value| value.keys[0].public_key[0] ^= 1,
        |value| value.keys[0].not_before = 1,
        |value| value.keys[0].known_cutoff = None,
        |value| value.keys.last_mut().expect("tail").known_cutoff = Some(0),
        |value| {
            value.keys.pop();
        },
        |value| value.revision = 0,
        |value| value.revision = rotation::MAX_ORDINAL + 1,
        |value| value.clock.binding.endpoint.clear(),
        |value| value.clock.window = 31,
        |value| value.clock.high_water = rotation::MAX_TIMESTAMP + 1,
        |value| value.clock.revision = rotation::MAX_ORDINAL + 1,
    ];
    for (index, mutate) in mutations.iter().enumerate() {
        let mut input = example(&corpus);
        mutate(&mut input);
        let error = validate(&input, &corpus).expect_err("mutated state accepted");
        assert_eq!(error.code, "rotation_state_unknown", "mutation {index}");
    }
    let input = example(&corpus);
    assert!(rotation::validate_trust_snapshot(
        &input,
        Binding {
            endpoint: &corpus.binding.endpoint,
            aud: "other"
        },
        30,
        &checkpoint(&corpus),
    )
    .is_err());
    assert!(
        rotation::validate_trust_snapshot(&input, binding(&corpus), 31, &checkpoint(&corpus))
            .is_err()
    );
    let mut root = checkpoint(&corpus);
    root.hash = "other".to_owned();
    assert!(rotation::validate_trust_snapshot(&input, binding(&corpus), 30, &root).is_err());
    let mut oversized = input;
    oversized.records = vec!["invalid".to_owned(); rotation::MAX_RETAINED_KEYS];
    assert_eq!(
        validate(&oversized, &corpus).expect_err("shape bound").code,
        "rotation_state_unknown"
    );
}

#[test]
fn copied_clock_compatibility_preserves_fences_and_is_not_readiness() {
    let corpus = corpus();
    let input = example(&corpus);
    let mut future = input.clock.clone();
    future.high_water += 1;
    future.revision += 1;
    assert!(rotation::trust_clock_compatible(&input, &future));
    let mutations: &[fn(&mut ClockTuple)] = &[
        |clock| clock.high_water -= 1,
        |clock| clock.revision = 0,
        |clock| clock.unsafe_clock = true,
        |clock| clock.binding.aud.clear(),
        |clock| clock.window = 31,
        |clock| clock.high_water = rotation::MAX_TIMESTAMP + 1,
        |clock| clock.revision = rotation::MAX_ORDINAL + 1,
    ];
    for mutate in mutations {
        let mut clock = input.clock.clone();
        mutate(&mut clock);
        assert!(!rotation::trust_clock_compatible(&input, &clock));
    }
    let mut fenced = input;
    fenced.fenced = true;
    fenced.clock.unsafe_clock = true;
    let inspected = validate(&fenced, &corpus).expect("inspection preserves flags");
    assert!(inspected.fenced);
    assert!(inspected.clock.unsafe_clock);
    assert!(!rotation::trust_clock_compatible(&inspected, &future));
}

#[test]
fn signed_pending_capacity_accepts_128_and_refuses_129_without_new_dependencies() {
    let corpus = corpus();
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
    for index in 1u8..=129 {
        let next = InMemorySigner::from_seed(&[index; 32]).expect("distinct test signer");
        let record = rotation::create_record(binding(&corpus), &previous, &old, &next, 1000)
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
    let accepted = snapshot_from(binding(&corpus), &root, &records[..128], 1000);
    assert!(rotation::validate_trust_snapshot(&accepted, binding(&corpus), 30, &root).is_ok());
    let refused = snapshot_from(binding(&corpus), &root, &records, 1000);
    assert_eq!(
        rotation::validate_trust_snapshot(&refused, binding(&corpus), 30, &root)
            .expect_err("129 pending keys accepted")
            .code,
        "rotation_state_unknown"
    );
    let mut active = refused;
    active.clock.high_water = 1000 + rotation::GRACE_SECONDS;
    assert!(rotation::validate_trust_snapshot(&active, binding(&corpus), 30, &root).is_ok());
}

#[test]
fn whole_trust_rechecks_proofs_even_when_redundant_head_hash_matches_tampered_bytes() {
    let corpus = corpus();
    let wire = &corpus.valid_chains["overlapping"][0];
    let root = checkpoint(&corpus);
    let records = rotation::verify_chain(
        &[wire.as_bytes()],
        binding(&corpus),
        &root,
        &BTreeMap::new(),
    )
    .expect("independent first record");
    for proof_line in [10, 11] {
        let mut input = snapshot_from(binding(&corpus), &root, &records, 2_000_000_000);
        let mut lines: Vec<String> = wire.split('\n').map(str::to_owned).collect();
        let mut proof = decode_b64url_fixed(&lines[proof_line], 64).expect("fixture proof");
        proof[0] ^= 1;
        lines[proof_line] = encode_b64url(&proof);
        input.records[0] = lines.join("\n");
        input.head.hash = body_hash(input.records[0].as_bytes());
        assert_eq!(
            validate(&input, &corpus)
                .expect_err("tampered proof accepted")
                .code,
            "rotation_state_unknown"
        );
    }
}

#[test]
fn independently_provisioned_nonzero_checkpoint_has_checked_activation_and_ordinal_domains() {
    let corpus = corpus();
    let records = rotation::verify_chain(
        &[corpus.valid_chains["overlapping"][0].as_bytes()],
        binding(&corpus),
        &checkpoint(&corpus),
        &BTreeMap::new(),
    )
    .expect("committed checkpoint source");
    let record = &records[0];
    let mut root = Checkpoint {
        ordinal: rotation::MAX_ORDINAL,
        hash: record.hash.clone(),
        kid: record.new_kid.clone(),
        public_key: record.public_key,
        published_at: rotation::MAX_TIMESTAMP - rotation::GRACE_SECONDS,
    };
    let input = snapshot_from(binding(&corpus), &root, &[], rotation::MAX_TIMESTAMP);
    let output = rotation::validate_trust_snapshot(&input, binding(&corpus), 30, &root)
        .expect("independently provisioned terminal checkpoint");
    assert_eq!(output.keys[0].not_before, rotation::MAX_TIMESTAMP);
    assert_eq!(output.keys[0].known_cutoff, None);
    root.published_at += 1;
    let too_late = snapshot_from(binding(&corpus), &root, &[], rotation::MAX_TIMESTAMP);
    assert!(rotation::validate_trust_snapshot(&too_late, binding(&corpus), 30, &root).is_err());
    root.published_at -= 1;
    root.ordinal += 1;
    let overflow_ordinal = snapshot_from(binding(&corpus), &root, &[], rotation::MAX_TIMESTAMP);
    assert!(
        rotation::validate_trust_snapshot(&overflow_ordinal, binding(&corpus), 30, &root).is_err()
    );
}
