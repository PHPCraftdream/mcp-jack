use super::*;

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
            // Only a public deterministic fixture seed, not a production secret.
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
    assert_eq!(
        rotation::selected_ordinal(&[], rotation::MAX_TIMESTAMP + 1)
            .expect_err("out-of-range current time accepted")
            .code,
        "timestamp"
    );
    assert!(!rotation::assignment_valid(
        &[],
        0,
        rotation::MAX_TIMESTAMP + 1,
        0
    ));
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

fn expected_record_mutation_code(
    original: &[u8],
    mutated: &[u8],
    index: usize,
    binding: Binding<'_>,
    authorizers: &BTreeMap<String, [u8; 32]>,
) -> &'static str {
    fn decimal(text: &str, maximum: u64) -> Option<u64> {
        if text.is_empty()
            || (text.len() > 1 && text.starts_with('0'))
            || !text.bytes().all(|byte| byte.is_ascii_digit())
        {
            return None;
        }
        text.parse::<u64>().ok().filter(|value| *value <= maximum)
    }

    if mutated.is_empty() || mutated.len() > rotation::MAX_RECORD_BYTES {
        return "record_size";
    }
    if !mutated.is_ascii() {
        return "non_ascii";
    }
    let text = std::str::from_utf8(mutated).expect("ASCII mutation");
    if text.ends_with('\n') {
        return "trailing_lf";
    }
    let lines: Vec<&str> = text.split('\n').collect();
    if lines.len() != 12 {
        return "line_count";
    }
    let line = original[..index]
        .iter()
        .filter(|byte| **byte == b'\n')
        .count();
    match line {
        0 => "domain",
        1 | 2 => {
            let Ok(decoded) = decode_b64url(lines[line]) else {
                return "binding_encoding";
            };
            let limit = if line == 1 { 2048 } else { 1024 };
            if decoded.is_empty() || decoded.len() > limit {
                return "binding_encoding";
            }
            let Ok(decoded) = std::str::from_utf8(&decoded) else {
                return "utf8";
            };
            let expected = if line == 1 {
                binding.endpoint
            } else {
                binding.aud
            };
            if decoded == expected {
                "new_proof"
            } else {
                "binding"
            }
        }
        3 => match decimal(lines[3], rotation::MAX_ORDINAL) {
            Some(ordinal) if ordinal != 0 => "new_proof",
            _ => "ordinal",
        },
        4 => "new_proof",
        5 => {
            if decode_b64url_fixed(lines[5], 32).is_err() {
                return "key_id";
            }
            let Some(public) = authorizers.get(lines[5]) else {
                return "unknown_authorizer";
            };
            if key_id(public) != lines[5] || mcp_jack::ed25519::validate_public_key(public).is_err()
            {
                "unknown_authorizer"
            } else {
                "new_proof"
            }
        }
        6 => {
            if decode_b64url_fixed(lines[6], 32).is_err() {
                return "key_id";
            }
            let Ok(public) = decode_b64url_fixed(lines[7], 32) else {
                return "new_key";
            };
            if key_id(&public) != lines[6] {
                "new_key_id"
            } else {
                "new_proof"
            }
        }
        7 => {
            if lines[7].len() != 43 {
                return "base64url";
            }
            let Ok(public) = decode_b64url_fixed(lines[7], 32) else {
                return "new_key";
            };
            if mcp_jack::ed25519::validate_public_key(&public).is_err() {
                return "new_key";
            }
            if key_id(&public) != lines[6] {
                "new_key_id"
            } else {
                "new_proof"
            }
        }
        8 | 9 => {
            let Some(published_at) = decimal(lines[8], rotation::MAX_TIMESTAMP) else {
                return "timestamp";
            };
            let Some(activates_at) = decimal(lines[9], rotation::MAX_TIMESTAMP) else {
                return "timestamp";
            };
            if published_at
                .checked_add(rotation::GRACE_SECONDS)
                .filter(|value| *value <= rotation::MAX_TIMESTAMP)
                != Some(activates_at)
            {
                "activation"
            } else {
                "new_proof"
            }
        }
        10 => {
            if decode_b64url_fixed(lines[10], 64).is_err() {
                "proof_encoding"
            } else {
                "new_proof"
            }
        }
        11 => {
            if decode_b64url_fixed(lines[11], 64).is_err() {
                "proof_encoding"
            } else {
                "old_authorization"
            }
        }
        _ => unreachable!("12-line record has no other line index"),
    }
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
        let expected = expected_record_mutation_code(
            original,
            &mutated,
            index,
            binding(&corpus.binding),
            &keys,
        );
        let error = rotation::parse_record(&mutated, binding(&corpus.binding), &keys)
            .expect_err("single-byte mutation accepted");
        assert_eq!(error.code, expected, "single-byte mutation at {index}");
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
