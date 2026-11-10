mod common;

use ed25519_dalek::{Signer, SigningKey};
use mcp_jack::client::{ClientError, InMemorySigner, Signer as JackSigner};
use mcp_jack::encoding::{body_hash, decode_b64url, decode_b64url_fixed, encode_b64url};
use mcp_jack::rotation::{self, Binding, Checkpoint};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Deserialize)]
struct FixtureBinding {
    endpoint: String,
    aud: String,
}
#[derive(Deserialize)]
struct Key {
    kid: String,
    public_key: String,
}
#[derive(Deserialize)]
struct Negative {
    id: String,
    expected: String,
    setup: String,
    binding: FixtureBinding,
    wire_b64u: String,
}
#[derive(Deserialize)]
struct Controls {
    decreasing_prefix: String,
}
#[derive(Deserialize)]
struct Corpus {
    binding: FixtureBinding,
    keys: BTreeMap<String, Key>,
    valid_chains: BTreeMap<String, Vec<String>>,
    source_controls: Controls,
    malformed: Vec<Negative>,
}

fn corpus() -> Corpus {
    let bytes = std::fs::read(common::fixtures::fixture_path(
        "candidate/rotation-vectors.json",
    ))
    .expect("committed fixture");
    serde_json::from_slice(&bytes).expect("typed candidate corpus")
}
fn binding(value: &FixtureBinding) -> Binding<'_> {
    Binding {
        endpoint: &value.endpoint,
        aud: &value.aud,
    }
}
fn public(text: &str) -> [u8; 32] {
    decode_b64url_fixed(text, 32)
        .expect("fixture public key")
        .try_into()
        .expect("32 bytes")
}
fn checkpoint(corpus: &Corpus) -> Checkpoint {
    let anchor = &corpus.keys["anchor"];
    Checkpoint {
        ordinal: 0,
        hash: "-".into(),
        kid: anchor.kid.clone(),
        public_key: public(&anchor.public_key),
        published_at: 0,
    }
}

#[test]
fn independent_negative_fixture_codes() {
    let corpus = corpus();
    assert_eq!(corpus.malformed.len(), 19);
    let checkpoint = checkpoint(&corpus);
    let all_keys = corpus
        .keys
        .values()
        .map(|key| (key.kid.clone(), public(&key.public_key)))
        .collect();
    for row in &corpus.malformed {
        let wire = decode_b64url(&row.wire_b64u).expect("fixture wire encoding");
        let result = match row.setup.as_str() {
            "chain" => rotation::verify_chain(
                &[&wire],
                binding(&corpus.binding),
                &checkpoint,
                &BTreeMap::new(),
            )
            .map(|_| ()),
            "after-r1" => rotation::verify_chain(
                &[corpus.valid_chains["overlapping"][0].as_bytes(), &wire],
                binding(&corpus.binding),
                &checkpoint,
                &BTreeMap::new(),
            )
            .map(|_| ()),
            "decreasing" => rotation::verify_chain(
                &[corpus.source_controls.decreasing_prefix.as_bytes(), &wire],
                binding(&corpus.binding),
                &checkpoint,
                &BTreeMap::new(),
            )
            .map(|_| ()),
            "single" => rotation::parse_record(&wire, binding(&row.binding), &all_keys).map(|_| ()),
            other => panic!("unknown fixture setup {other}"),
        };
        assert_eq!(
            result.expect_err("negative fixture accepted").code,
            row.expected,
            "{}",
            row.id
        );
    }
}

#[test]
fn positive_exact_bytes_proofs_overlap_and_tie() {
    let corpus = corpus();
    let checkpoint = checkpoint(&corpus);
    assert_eq!(corpus.valid_chains.len(), 2);
    for (name, chain) in &corpus.valid_chains {
        let wires: Vec<&[u8]> = chain.iter().map(|wire| wire.as_bytes()).collect();
        let records = rotation::verify_chain(
            &wires,
            binding(&corpus.binding),
            &checkpoint,
            &BTreeMap::new(),
        )
        .expect("independent valid chain");
        assert_eq!(records.len(), 2);
        for (index, record) in records.iter().enumerate() {
            assert_eq!(record.wire, chain[index]);
            assert_eq!(record.hash, body_hash(chain[index].as_bytes()));
            let lines: Vec<&str> = record.wire.split('\n').collect();
            // Только публичный deterministic fixture seed, не production secret.
            let seed: [u8; 32] = Sha256::digest(
                format!("mcp-jack test key: candidate-server-next{}", index + 1).as_bytes(),
            )
            .into();
            let key = SigningKey::from_bytes(&seed);
            let proof = key.sign(
                format!(
                    "{}/next-proof\n{}",
                    rotation::DOMAIN,
                    lines[..10].join("\n")
                )
                .as_bytes(),
            );
            assert_eq!(encode_b64url(&proof.to_bytes()), lines[10]);
        }
        assert_eq!(
            rotation::selected_ordinal(&records, 173_799).expect("time"),
            0
        );
        if name == "tie" {
            assert_eq!(
                rotation::selected_ordinal(&records, 173_800).expect("time"),
                2
            );
            assert!(!rotation::assignment_valid(&records, 1, 173_800, 173_800));
        } else {
            assert!(rotation::assignment_valid(&records, 1, 173_800, 173_800));
            assert!(!rotation::assignment_valid(&records, 1, 177_399, 177_400));
            assert!(!rotation::assignment_valid(&records, 0, 173_799, 173_800));
        }
    }
}

#[test]
fn bounds_unknown_authorizer_and_retained_reuse() {
    let corpus = corpus();
    let checkpoint = checkpoint(&corpus);
    let first = corpus.valid_chains["overlapping"][0].as_bytes();
    assert_eq!(
        rotation::parse_record(first, binding(&corpus.binding), &BTreeMap::new())
            .expect_err("unknown authorizer")
            .code,
        "unknown_authorizer"
    );
    let oversized = vec![first; rotation::MAX_RETAINED_KEYS + 1];
    assert_eq!(
        rotation::verify_chain(
            &oversized,
            binding(&corpus.binding),
            &checkpoint,
            &BTreeMap::new()
        )
        .expect_err("capacity")
        .code,
        "capacity"
    );
    let mut invalid = checkpoint.clone();
    invalid.ordinal = rotation::MAX_ORDINAL + 1;
    assert_eq!(
        rotation::verify_chain(&[], binding(&corpus.binding), &invalid, &BTreeMap::new())
            .expect_err("ordinal domain")
            .code,
        "anchor_key_id"
    );
    let next = &corpus.keys["next1"];
    let retained = BTreeMap::from([(next.kid.clone(), public(&next.public_key))]);
    assert_eq!(
        rotation::verify_chain(&[first], binding(&corpus.binding), &checkpoint, &retained)
            .expect_err("retained reuse")
            .code,
        "key_reuse"
    );
    assert!(rotation::selected_ordinal(&[], rotation::MAX_TIMESTAMP + 1).is_err());
    assert!(!rotation::assignment_valid(
        &[],
        0,
        rotation::MAX_TIMESTAMP + 1,
        0
    ));
}

fn fixture_signer(name: &str) -> InMemorySigner {
    // Публичный fixture seed; production key material здесь не используется.
    let seed = Sha256::digest(format!("mcp-jack test key: candidate-server-{name}").as_bytes());
    InMemorySigner::from_seed(&seed).expect("fixture seed")
}

#[test]
fn opaque_record_creation_matches_complete_independent_chains() {
    let corpus = corpus();
    for (name, chain) in &corpus.valid_chains {
        let mut previous = checkpoint(&corpus);
        let mut old = fixture_signer("anchor");
        for (index, expected) in chain.iter().enumerate() {
            let next = fixture_signer(&format!("next{}", index + 1));
            let published = if index == 0 || name == "tie" {
                1000
            } else {
                4600
            };
            let record = rotation::create_record(
                binding(&corpus.binding),
                &previous,
                &old,
                &next,
                published,
            )
            .expect("opaque record creation");
            assert_eq!(&record.wire, expected);
            previous = Checkpoint {
                ordinal: record.ordinal,
                hash: record.hash,
                kid: record.new_kid,
                public_key: record.public_key,
                published_at: record.published_at,
            };
            old = next;
        }
    }
}

struct ObservedSigner {
    inner: InMemorySigner,
    events: std::sync::Arc<std::sync::Mutex<Vec<&'static str>>>,
    label: &'static str,
    corrupt: bool,
    fail: bool,
}

impl JackSigner for ObservedSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, ClientError> {
        self.events
            .lock()
            .expect("test event lock")
            .push(self.label);
        if self.fail {
            return Err(ClientError::Client("private provider detail".into()));
        }
        let mut proof = self.inner.sign(message)?;
        if self.corrupt {
            proof[0] ^= 1;
        }
        Ok(proof)
    }
    fn public_key(&self) -> [u8; 32] {
        self.inner.public_key()
    }
    fn kid(&self) -> &str {
        self.inner.kid()
    }
}

#[test]
fn signing_order_errors_and_no_retry_are_observable() {
    let corpus = corpus();
    let previous = checkpoint(&corpus);
    let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut old = ObservedSigner {
        inner: fixture_signer("anchor"),
        events: events.clone(),
        label: "old",
        corrupt: false,
        fail: false,
    };
    let mut next = ObservedSigner {
        inner: fixture_signer("next1"),
        events: events.clone(),
        label: "next",
        corrupt: false,
        fail: false,
    };
    assert_eq!(
        rotation::create_record(
            binding(&corpus.binding),
            &previous,
            &old,
            &next,
            rotation::MAX_TIMESTAMP
        )
        .expect_err("overflow")
        .code,
        "timestamp"
    );
    let mut invalid = previous.clone();
    invalid.hash = "wrong".into();
    assert_eq!(
        rotation::create_record(binding(&corpus.binding), &invalid, &old, &next, 1000)
            .expect_err("checkpoint")
            .code,
        "previous_hash"
    );
    assert!(events.lock().expect("test event lock").is_empty());

    next.corrupt = true;
    assert_eq!(
        rotation::create_record(binding(&corpus.binding), &previous, &old, &next, 1000)
            .expect_err("new proof")
            .code,
        "new_proof"
    );
    assert_eq!(*events.lock().expect("test event lock"), ["next"]);
    events.lock().expect("test event lock").clear();
    next.corrupt = false;
    next.fail = true;
    let failure = rotation::create_record(binding(&corpus.binding), &previous, &old, &next, 1000)
        .expect_err("provider failure");
    assert_eq!(failure.code, "signer");
    assert!(!failure.to_string().contains("private provider detail"));
    assert_eq!(*events.lock().expect("test event lock"), ["next"]);
    events.lock().expect("test event lock").clear();
    next.fail = false;
    let created = rotation::create_record(binding(&corpus.binding), &previous, &old, &next, 1000)
        .expect("valid providers");
    assert_eq!(created.wire, corpus.valid_chains["overlapping"][0]);
    assert_eq!(*events.lock().expect("test event lock"), ["next", "old"]);
    events.lock().expect("test event lock").clear();
    old.corrupt = true;
    assert_eq!(
        rotation::create_record(binding(&corpus.binding), &previous, &old, &next, 1000)
            .expect_err("old proof")
            .code,
        "old_authorization"
    );
    assert_eq!(*events.lock().expect("test event lock"), ["next", "old"]);
}
