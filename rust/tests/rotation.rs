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

#[test]
fn every_byte_mutation_is_rejected_without_poisoning_the_positive_record() {
    let corpus = corpus();
    let original = corpus.valid_chains["overlapping"][0].as_bytes();
    assert!(original.len() > 128 && original.len() <= 1024);
    let keys = corpus
        .keys
        .values()
        .map(|key| (key.kid.clone(), public(&key.public_key)))
        .collect();
    let before = rotation::parse_record(original, binding(&corpus.binding), &keys)
        .expect("untouched positive control");
    let mut exercised = 0;
    for (index, byte) in original.iter().enumerate() {
        let mut mutated = original.to_vec();
        mutated[index] = *byte ^ 1;
        assert!(
            rotation::parse_record(&mutated, binding(&corpus.binding), &keys).is_err(),
            "single-byte mutation accepted at {index}"
        );
        exercised += 1;
    }
    assert_eq!(exercised, original.len());
    let after = rotation::parse_record(original, binding(&corpus.binding), &keys)
        .expect("positive control after mutations");
    assert_eq!(before, after);
}

#[test]
fn lexical_number_mutations_fail_before_signature_verification() {
    let corpus = corpus();
    let original = &corpus.valid_chains["overlapping"][0];
    let keys = corpus
        .keys
        .values()
        .map(|key| (key.kid.clone(), public(&key.public_key)))
        .collect();
    for (field, code) in [(3_usize, "ordinal"), (8, "timestamp"), (9, "timestamp")] {
        for lexical in [
            "01",
            "+1",
            "-0",
            "1.0",
            "1e0",
            " 1",
            "1 ",
            "NaN",
            "Infinity",
            "9007199254740993",
        ] {
            let mut lines: Vec<&str> = original.split('\n').collect();
            lines[field] = lexical;
            let wire = lines.join("\n");
            let error = rotation::parse_record(wire.as_bytes(), binding(&corpus.binding), &keys)
                .expect_err("lexical mutation accepted");
            assert_eq!(error.code, code, "field={field} lexical={lexical}");
        }
    }
}

fn result_payload() -> String {
    let corpus = corpus();
    let anchor = &corpus.keys["anchor"];
    serde_json::json!({
        "current": {"kid": anchor.kid, "public_key": anchor.public_key},
        "records": [], "head": {"ordinal": 0, "hash": "-"}, "complete": true
    })
    .to_string()
}

fn result_body(payload: &str, mirror: &str, id: &str) -> Vec<u8> {
    let quoted = serde_json::to_string(mirror).expect("text JSON encoding");
    format!(r#"{{"jsonrpc":"2.0","id":{id},"result":{{"content":[{{"type":"text","text":{quoted}}}],"structuredContent":{payload},"isError":false}}}}"#).into_bytes()
}

#[test]
fn strict_result_shape_parity_and_scalar_request_ids() {
    let payload = result_payload();
    let value: serde_json::Value = serde_json::from_str(&payload).expect("fixture payload");
    let mirror = serde_json::to_string_pretty(&value).expect("reordered/whitespace mirror");
    let literal_id = serde_json::to_string(&format!("literal{}ud800", char::from(0x5c_u8)))
        .expect("escaped literal ID");
    for id in ["7", "1.5", r#""request-😀""#, r#""😀""#, &literal_id] {
        let mut body = result_body(&payload, &mirror, id);
        let result = rotation::decode_result(&body, id.as_bytes()).expect("valid result");
        assert_eq!(result.head_ordinal, 0);
        assert_eq!(result.head_hash, "-");
        assert!(result.complete);
        assert!(result.records.is_empty());
        assert_eq!(
            mcp_jack::encoding::key_id(&result.current_public_key),
            result.current_kid
        );
        body.fill(0);
        assert_eq!(result.current_kid, corpus().keys["anchor"].kid);
    }
    let body = result_body(&payload, &payload, "7");
    assert!(rotation::decode_result(&body, b"7e0").is_err());
}

#[test]
fn strict_result_rejects_duplicate_extra_type_lexical_and_surrogate_changes() {
    let payload = result_payload();
    for changed in [
        payload.replacen(
            "\"complete\":true",
            "\"complete\":true,\"complete\":true",
            1,
        ),
        payload.replacen("\"complete\":true", "\"complete\":null", 1),
        payload.replacen("\"complete\":true", "\"complete\":true,\"extra\":1", 1),
        payload.replacen("\"ordinal\":0", "\"ordinal\":0.0", 1),
        payload.replacen("\"ordinal\":0", "\"ordinal\":0e0", 1),
        payload.replacen("\"ordinal\":0", "\"ordinal\":-0", 1),
        payload.replacen("\"hash\":\"-\"", "\"hash\":\"wrong\"", 1),
        payload.replacen("\"records\":[]", r#""records":["\ud800"]"#, 1),
        payload.replacen("\"records\":[]", r#""records":["\udc00"]"#, 1),
    ] {
        assert_ne!(changed, payload, "mutation did not alter fixture");
        for (actual, mirror) in [(&changed, &changed), (&payload, &changed)] {
            let error = rotation::decode_result(&result_body(actual, mirror, "7"), b"7")
                .expect_err("invalid result accepted");
            assert_eq!(error.code, "rotation_result_invalid");
        }
    }
    let ordinary = String::from_utf8(result_body(&payload, &payload, "7")).expect("UTF8");
    for changed in [
        ordinary.replacen(
            "\"jsonrpc\":\"2.0\"",
            "\"jsonrpc\":\"2.0\",\"jsonrpc\":\"2.0\"",
            1,
        ),
        ordinary.replacen("\"isError\":false", "\"isError\":true", 1),
        ordinary.replacen("\"type\":\"text\"", "\"type\":\"text\",\"extra\":1", 1),
    ] {
        assert!(rotation::decode_result(changed.as_bytes(), b"7").is_err());
    }
    let mismatch = payload.replacen("\"complete\":true", "\"complete\":false", 1);
    assert!(rotation::decode_result(&result_body(&payload, &mismatch, "7"), b"7").is_err());
    assert!(rotation::decode_result(&[0xff], b"7").is_err());
}

#[test]
fn strict_result_has_inclusive_full_body_and_page_caps() {
    let payload = result_payload();
    let mut body = result_body(&payload, &payload, "7");
    body.resize(rotation::MAX_RESULT_BODY_BYTES, b' ');
    assert!(rotation::decode_result(&body, b"7").is_ok());
    body.push(b' ');
    assert!(rotation::decode_result(&body, b"7").is_err());
    let corpus = corpus();
    let mut value: serde_json::Value = serde_json::from_str(&payload).expect("payload");
    value["records"] = serde_json::json!(vec![corpus.valid_chains["overlapping"][0].clone(); 16]);
    let page = value.to_string();
    assert_eq!(
        rotation::decode_result(&result_body(&page, &page, "7"), b"7")
            .expect("16 record schema")
            .records
            .len(),
        16
    );
    value["records"]
        .as_array_mut()
        .expect("records array")
        .push(serde_json::Value::String(
            corpus.valid_chains["overlapping"][0].clone(),
        ));
    let page = value.to_string();
    assert!(rotation::decode_result(&result_body(&page, &page, "7"), b"7").is_err());
}

fn framing_result(
    records: &[rotation::Record],
    head: &rotation::ResultCursor,
    complete: bool,
) -> rotation::DecodedResult {
    let corpus = corpus();
    let anchor = &corpus.keys["anchor"];
    rotation::DecodedResult {
        current_kid: anchor.kid.clone(),
        current_public_key: public(&anchor.public_key),
        records: records.iter().map(|record| record.wire.clone()).collect(),
        head_ordinal: head.ordinal,
        head_hash: head.hash.clone(),
        complete,
    }
}

#[test]
fn page_framing_prefix_extension_retained_suffix_and_noop() {
    let corpus = corpus();
    let wires: Vec<&[u8]> = corpus.valid_chains["overlapping"]
        .iter()
        .map(|wire| wire.as_bytes())
        .collect();
    let records = rotation::verify_chain(
        &wires,
        binding(&corpus.binding),
        &checkpoint(&corpus),
        &BTreeMap::new(),
    )
    .expect("independent records");
    let zero = rotation::ResultCursor {
        ordinal: 0,
        hash: "-".into(),
    };
    let one = rotation::ResultCursor {
        ordinal: 1,
        hash: records[0].hash.clone(),
    };
    let two = rotation::ResultCursor {
        ordinal: 2,
        hash: records[1].hash.clone(),
    };
    let known = BTreeMap::from([(1, one.hash.clone()), (2, two.hash.clone())]);
    for (cursor, delivered, head, complete, start, terminal) in [
        (
            zero.clone(),
            records.clone(),
            two.clone(),
            true,
            0,
            two.clone(),
        ),
        (
            one.clone(),
            records.clone(),
            two.clone(),
            true,
            1,
            two.clone(),
        ),
        (
            two.clone(),
            records[1..].to_vec(),
            two.clone(),
            true,
            1,
            two.clone(),
        ),
        (
            zero.clone(),
            records[..1].to_vec(),
            two.clone(),
            false,
            0,
            one.clone(),
        ),
        (
            one.clone(),
            records[..1].to_vec(),
            two.clone(),
            false,
            1,
            one.clone(),
        ),
        (
            zero.clone(),
            Vec::new(),
            zero.clone(),
            true,
            0,
            zero.clone(),
        ),
    ] {
        let result = rotation::validate_page_framing(
            &framing_result(&delivered, &head, complete),
            &cursor,
            &delivered,
            &known,
        )
        .expect("valid framing");
        assert_eq!(result.extension_start, start);
        assert_eq!(result.terminal, terminal);
        assert_eq!(result.head, head);
        assert_eq!(result.complete, complete);
    }
}

#[test]
fn page_framing_gap_conflict_snapshot_and_capacity_refusals() {
    let corpus = corpus();
    let wires: Vec<&[u8]> = corpus.valid_chains["overlapping"]
        .iter()
        .map(|wire| wire.as_bytes())
        .collect();
    let records = rotation::verify_chain(
        &wires,
        binding(&corpus.binding),
        &checkpoint(&corpus),
        &BTreeMap::new(),
    )
    .expect("independent records");
    let zero = rotation::ResultCursor {
        ordinal: 0,
        hash: "-".into(),
    };
    let one = rotation::ResultCursor {
        ordinal: 1,
        hash: records[0].hash.clone(),
    };
    let two = rotation::ResultCursor {
        ordinal: 2,
        hash: records[1].hash.clone(),
    };
    let known = BTreeMap::from([(1, one.hash.clone()), (2, two.hash.clone())]);
    for (cursor, delivered, head, complete) in [
        (zero.clone(), records[1..].to_vec(), two.clone(), true),
        (two.clone(), records[..1].to_vec(), one.clone(), true),
        (zero.clone(), records.clone(), one.clone(), true),
        (zero.clone(), records.clone(), two.clone(), false),
        (zero.clone(), Vec::new(), one.clone(), false),
        (zero.clone(), Vec::new(), one.clone(), true),
    ] {
        assert_eq!(
            rotation::validate_page_framing(
                &framing_result(&delivered, &head, complete),
                &cursor,
                &delivered,
                &known
            )
            .expect_err("gap accepted")
            .code,
            "rotation_gap"
        );
    }
    let keys = corpus
        .keys
        .values()
        .map(|key| (key.kid.clone(), public(&key.public_key)))
        .collect();
    let conflict = rotation::parse_record(
        corpus.source_controls.decreasing_prefix.as_bytes(),
        binding(&corpus.binding),
        &keys,
    )
    .expect("valid signed conflict");
    let conflict_head = rotation::ResultCursor {
        ordinal: 1,
        hash: conflict.hash.clone(),
    };
    assert_ne!(conflict.hash, one.hash);
    assert_eq!(
        rotation::validate_page_framing(
            &framing_result(std::slice::from_ref(&conflict), &conflict_head, true),
            &one,
            &[conflict],
            &known
        )
        .expect_err("conflict accepted")
        .code,
        "rotation_conflict"
    );
    assert_eq!(
        rotation::validate_page_framing(
            &framing_result(&records[..1], &one, true),
            &zero,
            &records[1..],
            &known
        )
        .expect_err("mixed snapshot accepted")
        .code,
        "rotation_record_invalid"
    );
    let mut forged = records[0].clone();
    forged.hash = records[1].hash.clone();
    assert_eq!(
        rotation::validate_page_framing(
            &framing_result(&records[..1], &one, true),
            &zero,
            &[forged],
            &known
        )
        .expect_err("forged hash accepted")
        .code,
        "rotation_record_invalid"
    );
    let oversized = vec![records[0].clone(); 17];
    assert_eq!(
        rotation::validate_page_framing(
            &framing_result(&oversized, &one, true),
            &one,
            &oversized,
            &known
        )
        .expect_err("capacity exceeded")
        .code,
        "rotation_result_invalid"
    );
}

fn carrier_header(key: &dyn JackSigner, request_sig: &str, ts: i64, body: &[u8]) -> String {
    let message = mcp_jack::signing::response_signing_string(200, request_sig, key.kid(), ts, body);
    let signature = key
        .sign(message.as_bytes())
        .expect("actual response signature");
    mcp_jack::auth_header::format_response_auth(&mcp_jack::auth_header::ResponseAuth {
        kid: key.kid().to_owned(),
        ts,
        sig: encode_b64url(&signature),
    })
}

#[test]
fn carrier_known_key_precedes_freshness_signature_and_payload() {
    let key = fixture_signer("anchor");
    let other = fixture_signer("other");
    let user = fixture_signer("public-user");
    let request =
        mcp_jack::client::sign_request(&user, "public-aud", "POST", "/mcp", b"", &[0; 16], 100)
            .expect("actual signed request");
    let request_sig = &request.auth.sig;
    let mut known = BTreeMap::from([(
        key.kid().to_owned(),
        mcp_jack::client::RotationResponseKey {
            public_key: key.public_key(),
            not_before: 0,
            known_cutoff: Some(110),
        },
    )]);
    let body = b"{not-json";
    let check = |known: &BTreeMap<String, mcp_jack::client::RotationResponseKey>,
                 header: &str,
                 bytes: &[u8],
                 now| {
        mcp_jack::client::verify_rotation_carrier(
            known,
            200,
            &[header],
            request_sig,
            bytes,
            now,
            30,
        )
    };
    let header = carrier_header(&key, request_sig, 109, body);
    let result = check(&known, &header, body, 109).expect("valid carrier over raw non-JSON bytes");
    assert_eq!(result.kid, key.kid());
    assert_eq!(result.timestamp, 109);
    let unknown =
        mcp_jack::auth_header::format_response_auth(&mcp_jack::auth_header::ResponseAuth {
            kid: other.kid().to_owned(),
            ts: 0,
            sig: encode_b64url(&[0; 64]),
        });
    assert_eq!(
        check(&known, &unknown, body, 1000)
            .expect_err("unknown key")
            .code,
        "unknown_server_key"
    );
    let stale_bad =
        mcp_jack::auth_header::format_response_auth(&mcp_jack::auth_header::ResponseAuth {
            kid: key.kid().to_owned(),
            ts: 0,
            sig: encode_b64url(&[0; 64]),
        });
    assert_eq!(
        check(&known, &stale_bad, body, 1000)
            .expect_err("stale before bad signature")
            .code,
        "timestamp_out_of_window"
    );
    let bad = mcp_jack::auth_header::format_response_auth(&mcp_jack::auth_header::ResponseAuth {
        kid: key.kid().to_owned(),
        ts: 109,
        sig: encode_b64url(&[0; 64]),
    });
    assert_eq!(
        check(&known, &bad, body, 109)
            .expect_err("bad signature")
            .code,
        "bad_signature"
    );
    assert_eq!(
        check(&known, &header, b"changed", 109)
            .expect_err("changed exact body")
            .code,
        "bad_signature"
    );
    assert_eq!(
        check(&known, &header, body, 110)
            .expect_err("final cutoff equality")
            .code,
        "rotation_key_interval"
    );
    let at_cutoff = carrier_header(&key, request_sig, 110, body);
    assert_eq!(
        check(&known, &at_cutoff, body, 109)
            .expect_err("signed cutoff equality")
            .code,
        "rotation_key_interval"
    );
    known.insert(
        key.kid().to_owned(),
        mcp_jack::client::RotationResponseKey {
            public_key: key.public_key(),
            not_before: 100,
            known_cutoff: None,
        },
    );
    let lower = carrier_header(&key, request_sig, 100, body);
    assert_eq!(
        check(&known, &lower, body, 99)
            .expect("future ts lower bound within skew")
            .timestamp,
        100
    );
    let before = carrier_header(&key, request_sig, 99, body);
    assert_eq!(
        check(&known, &before, body, 100)
            .expect_err("before lower bound")
            .code,
        "rotation_key_interval"
    );
    known.insert(
        key.kid().to_owned(),
        mcp_jack::client::RotationResponseKey {
            public_key: key.public_key(),
            not_before: 110,
            known_cutoff: Some(110),
        },
    );
    assert_eq!(
        check(&known, &at_cutoff, body, 110)
            .expect_err("empty interval")
            .code,
        "rotation_key_interval"
    );
}

#[test]
fn carrier_rejects_invalid_local_snapshot_window_without_changing_static_verifier() {
    let key = fixture_signer("anchor");
    let body = b"public body";
    let header = carrier_header(&key, "request-signature", 100, body);
    let mut known = BTreeMap::from([(
        key.kid().to_owned(),
        mcp_jack::client::RotationResponseKey {
            public_key: key.public_key(),
            not_before: 0,
            known_cutoff: None,
        },
    )]);
    for window in [0, -1, 121] {
        assert_eq!(
            mcp_jack::client::verify_rotation_carrier(
                &known,
                200,
                &[&header],
                "request-signature",
                body,
                100,
                window
            )
            .expect_err("invalid local window")
            .code,
            "rotation_state_unknown"
        );
    }
    known.insert(
        key.kid().to_owned(),
        mcp_jack::client::RotationResponseKey {
            public_key: [0; 32],
            not_before: 0,
            known_cutoff: None,
        },
    );
    assert_eq!(
        mcp_jack::client::verify_rotation_carrier(
            &known,
            200,
            &[&header],
            "request-signature",
            body,
            100,
            30
        )
        .expect_err("invalid local public key")
        .code,
        "rotation_state_unknown"
    );
    assert!(mcp_jack::signing::verify_response(
        &key.public_key(),
        200,
        &[&header],
        "request-signature",
        body,
        100,
        30
    )
    .is_ok());
}

#[test]
fn strict_result_refuses_positional_arrays_at_every_candidate_object_boundary() {
    let payload = result_payload();
    let original: serde_json::Value = serde_json::from_slice(&result_body(&payload, &payload, "7"))
        .expect("independent valid envelope");
    let reference = serde_json::to_vec(&original).expect("reference JSON serialization");
    assert!(rotation::decode_result(&reference, b"7").is_ok());
    let cases: &[(&str, &[&str])] = &[
        ("", &["jsonrpc", "id", "result"]),
        ("/result", &["content", "structuredContent", "isError"]),
        ("/result/content/0", &["type", "text"]),
        ("/result/structuredContent", &["current", "records", "head", "complete"]),
        ("/result/structuredContent/current", &["kid", "public_key"]),
        ("/result/structuredContent/head", &["ordinal", "hash"]),
    ];
    for (path, names) in cases {
        let mut changed = original.clone();
        let object = changed.pointer(path).expect("candidate object");
        let values = names.iter().map(|name| object[*name].clone()).collect();
        *changed.pointer_mut(path).expect("candidate object") = serde_json::Value::Array(values);
        let body = serde_json::to_vec(&changed).expect("positional mutation");
        let error = rotation::decode_result(&body, b"7").expect_err("positional array accepted");
        assert_eq!(error.code, "rotation_result_invalid", "boundary {path}");
    }
    let original: serde_json::Value = serde_json::from_str(&payload).expect("reference payload");
    for (path, names) in [
        ("", &["current", "records", "head", "complete"][..]),
        ("/current", &["kid", "public_key"][..]),
        ("/head", &["ordinal", "hash"][..]),
    ] {
        let mut mirror = original.clone();
        let object = mirror.pointer(path).expect("mirror object");
        let values = names.iter().map(|name| object[*name].clone()).collect();
        *mirror.pointer_mut(path).expect("mirror object") = serde_json::Value::Array(values);
        let mirror = serde_json::to_string(&mirror).expect("mirror positional mutation");
        let error = rotation::decode_result(&result_body(&payload, &mirror, "7"), b"7")
            .expect_err("positional text mirror accepted");
        assert_eq!(error.code, "rotation_result_invalid", "mirror {path}");
    }
}
