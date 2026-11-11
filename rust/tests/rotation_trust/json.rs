use super::{binding, checkpoint, corpus, example, Corpus};
use mcp_jack::encoding::encode_b64url;
use mcp_jack::rotation::{self, TrustSnapshot};
use serde::Deserialize;
use serde_json::{json, Value};

// Независимая DTO shape из Go rotation/trust_json.go, не output encoder-а.
fn document(value: &TrustSnapshot) -> Value {
    json!({
        "format_version": value.format_version,
        "binding": {"endpoint": value.binding.endpoint, "aud": value.binding.aud},
        "window": value.window,
        "checkpoint": {"ordinal": value.checkpoint.ordinal, "hash": value.checkpoint.hash,
            "kid": value.checkpoint.kid, "public_key": encode_b64url(&value.checkpoint.public_key),
            "published_at": value.checkpoint.published_at},
        "head": {"ordinal": value.head.ordinal, "hash": value.head.hash},
        "records": value.records,
        "keys": value.keys.iter().map(|key| json!({"ordinal": key.ordinal, "kid": key.kid,
            "public_key": encode_b64url(&key.public_key), "not_before": key.not_before,
            "known_cutoff": key.known_cutoff})).collect::<Vec<_>>(),
        "trust_revision": value.revision,
        "fenced": value.fenced,
        "clock": {"binding": {"endpoint": value.clock.binding.endpoint, "aud": value.clock.binding.aud},
            "window": value.clock.window, "high_water": value.clock.high_water,
            "clock_revision": value.clock.revision, "unsafe": value.clock.unsafe_clock}
    })
}

fn decode(bytes: &[u8], corpus: &Corpus) -> Result<TrustSnapshot, rotation::RotationError> {
    rotation::decode_trust_snapshot(bytes, binding(corpus), 30, &checkpoint(corpus))
}

fn refuse(value: &Value, corpus: &Corpus) {
    let bytes = serde_json::to_vec(value).expect("test document");
    assert_eq!(decode(&bytes, corpus).expect_err("invalid document accepted").code,
        "rotation_state_unknown");
}

#[test]
fn local_codec_reads_reference_schema_and_roundtrips_owned_fenced_values() {
    let corpus = corpus();
    let mut input = example(&corpus);
    input.fenced = true;
    input.clock.unsafe_clock = true;
    let reference = document(&input);
    let bytes = serde_json::to_vec(&reference).expect("reference JSON");
    let decoded = decode(&bytes, &corpus).expect("strict reference decode");
    assert_eq!(document(&decoded), reference);
    let encoded = rotation::encode_trust_snapshot(&decoded, binding(&corpus), 30, &checkpoint(&corpus))
        .expect("validated encode");
    assert_eq!(serde_json::from_slice::<Value>(&encoded).expect("output JSON"), reference);
    let again = decode(&encoded, &corpus).expect("roundtrip");
    assert_eq!(document(&again), reference);
    assert_eq!(rotation::encode_trust_snapshot(&again, binding(&corpus), 30, &checkpoint(&corpus))
        .expect("deterministic reencode"), encoded);
    input.records[0].clear();
    input.keys[0].kid.clear();
    assert_eq!(document(&decoded), reference);
    assert!(!rotation::trust_clock_compatible(&decoded, &decoded.clock));
}

#[test]
fn local_codec_requires_all_known_fields_and_only_objects_at_each_boundary() {
    let corpus = corpus();
    let reference = document(&example(&corpus));
    let objects: &[(&str, &[&str])] = &[
        ("", &["format_version", "binding", "window", "checkpoint", "head", "records", "keys", "trust_revision", "fenced", "clock"]),
        ("/binding", &["endpoint", "aud"]),
        ("/checkpoint", &["ordinal", "hash", "kid", "public_key", "published_at"]),
        ("/head", &["ordinal", "hash"]),
        ("/keys/0", &["ordinal", "kid", "public_key", "not_before", "known_cutoff"]),
        ("/clock", &["binding", "window", "high_water", "clock_revision", "unsafe"]),
        ("/clock/binding", &["endpoint", "aud"]),
    ];
    for (path, names) in objects {
        for name in *names {
            let mut missing = reference.clone();
            missing.pointer_mut(path).expect("object").as_object_mut().expect("map").remove(*name);
            refuse(&missing, &corpus);
        }
        let mut extra = reference.clone();
        extra.pointer_mut(path).expect("object").as_object_mut().expect("map")
            .insert("unexpected".to_owned(), json!(0));
        refuse(&extra, &corpus);
        let object = reference.pointer(path).expect("object");
        let sequence: Vec<Value> = names.iter().map(|name| object[*name].clone()).collect();
        let mut positional = reference.clone();
        *positional.pointer_mut(path).expect("object") = Value::Array(sequence);
        refuse(&positional, &corpus);
        let mut null = reference.clone();
        *null.pointer_mut(path).expect("object") = Value::Null;
        refuse(&null, &corpus);
    }
    // Positive control: обычный serde struct действительно допускает array.
    #[derive(Deserialize)]
    struct Ordinary { value: u64 }
    assert_eq!(serde_json::from_str::<Ordinary>("[1]").expect("serde sequence control").value, 1);
    let mut nullable = reference.clone();
    nullable.pointer_mut("/keys/0").expect("key").as_object_mut().expect("map")
        .insert("known_cutoff".to_owned(), Value::Null);
    // Null синтаксически допустим, но здесь противоречит verified chain interval.
    refuse(&nullable, &corpus);
    assert!(reference.pointer("/keys").expect("keys").as_array().expect("array")
        .last().expect("tail")["known_cutoff"].is_null());
}

#[test]
fn local_codec_rejects_duplicate_escaped_members_and_noncanonical_numeric_lexemes() {
    let corpus = corpus();
    let reference = document(&example(&corpus));
    let text = serde_json::to_string(&reference).expect("reference JSON");
    for fragment in ["\"fenced\":false", "\"clock_revision\":1", "\"not_before\":0"] {
        assert!(text.contains(fragment));
        let duplicate = text.replacen(fragment, &format!("{fragment},{fragment}"), 1);
        assert!(decode(duplicate.as_bytes(), &corpus).is_err());
    }
    let escaped = text.replacen("\"fenced\":false", "\"fenced\":false,\"fenc\\u0065d\":false", 1);
    assert!(decode(escaped.as_bytes(), &corpus).is_err());
    for path in ["/format_version", "/window", "/checkpoint/ordinal", "/checkpoint/published_at",
        "/head/ordinal", "/keys/0/ordinal", "/keys/0/not_before", "/keys/0/known_cutoff",
        "/trust_revision", "/clock/window", "/clock/high_water", "/clock/clock_revision"] {
        let value = reference.pointer(path).expect("number").as_u64().expect("integer");
        let mut marked = reference.clone();
        *marked.pointer_mut(path).expect("numeric field") = Value::String("__numeric_lexeme__".to_owned());
        let marked = serde_json::to_string(&marked).expect("marked field");
        assert_eq!(marked.matches("\"__numeric_lexeme__\"").count(), 1);
        for lexeme in [format!("{value}.0"), format!("{value}e0"), "-0".to_owned(),
            "null".to_owned(), "true".to_owned(), "\"1\"".to_owned(), "9007199254740992".to_owned()] {
            let changed = marked.replace("\"__numeric_lexeme__\"", &lexeme);
            assert_eq!(decode(changed.as_bytes(), &corpus).expect_err("noncanonical number").code,
                "rotation_state_unknown", "{path}: {lexeme}");
        }
    }
    assert!(decode(text.replace("\"fenced\":false", "\"fenced\":null").as_bytes(), &corpus).is_err());
    assert!(decode(format!("{text}0").as_bytes(), &corpus).is_err());
    assert!(decode(b"\xff", &corpus).is_err());
    assert!(decode(text.replace("\"fenced\":false", "\"fenced\":\"\\ud800\"").as_bytes(), &corpus).is_err());
}

#[test]
fn local_codec_requires_independent_oob_and_validates_before_encode() {
    let corpus = corpus();
    let input = example(&corpus);
    let bytes = serde_json::to_vec(&document(&input)).expect("reference JSON");
    assert!(rotation::decode_trust_snapshot(&bytes, binding(&corpus), 31, &checkpoint(&corpus)).is_err());
    let wrong_binding = rotation::Binding { endpoint: &corpus.binding.endpoint, aud: "other" };
    assert!(rotation::decode_trust_snapshot(&bytes, wrong_binding, 30, &checkpoint(&corpus)).is_err());
    let mut wrong_root = checkpoint(&corpus);
    wrong_root.published_at = 1;
    assert!(rotation::decode_trust_snapshot(&bytes, binding(&corpus), 30, &wrong_root).is_err());
    let mut invalid = input;
    invalid.records[0].push('\n');
    assert!(rotation::encode_trust_snapshot(&invalid, binding(&corpus), 30, &checkpoint(&corpus)).is_err());
}

#[test]
fn local_codec_obeys_inclusive_16mib_bound_and_collection_caps() {
    let corpus = corpus();
    let input = example(&corpus);
    let reference = document(&input);
    let mut bytes = serde_json::to_vec(&reference).expect("reference JSON");
    bytes.resize(rotation::MAX_TRUST_SNAPSHOT_BYTES, b' ');
    assert_eq!(document(&decode(&bytes, &corpus).expect("inclusive limit")), reference);
    bytes.push(b' ');
    assert!(decode(&bytes, &corpus).is_err());
    assert!(decode(&[], &corpus).is_err());
    for field in ["keys", "records"] {
        let mut oversized = reference.clone();
        let member = oversized[field][0].clone();
        oversized[field] = Value::Array(vec![member; rotation::MAX_RETAINED_KEYS + 1]);
        refuse(&oversized, &corpus);
    }
}

#[test]
fn local_codec_roundtrip_preserves_valid_window_time_revision_flag_domains() {
    let corpus = corpus();
    let root = checkpoint(&corpus);
    let base = example(&corpus);
    for window in [1, 30, 120] {
        for high_water in [0, base.clock.high_water, rotation::MAX_TIMESTAMP] {
            for revision in [1, rotation::MAX_ORDINAL] {
                for fenced in [false, true] {
                    let mut input = base.clone();
                    input.window = window;
                    input.clock.window = window;
                    input.clock.high_water = high_water;
                    input.revision = revision;
                    input.fenced = fenced;
                    input.clock.unsafe_clock = fenced;
                    let encoded = rotation::encode_trust_snapshot(&input, binding(&corpus), window, &root)
                        .expect("valid domain encode");
                    let decoded = rotation::decode_trust_snapshot(&encoded, binding(&corpus), window, &root)
                        .expect("domain roundtrip");
                    assert_eq!(document(&decoded), document(&input));
                }
            }
        }
    }
}
