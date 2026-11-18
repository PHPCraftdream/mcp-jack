use super::*;

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
    assert!(rotation::decode_result(&body, b"7e0").is_ok());
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
        let error = rotation::decode_result(changed.as_bytes(), b"7")
            .expect_err("invalid envelope accepted");
        assert_eq!(error.code, "rotation_result_invalid");
    }
    let mismatch = payload.replacen("\"complete\":true", "\"complete\":false", 1);
    let error = rotation::decode_result(&result_body(&payload, &mismatch, "7"), b"7")
        .expect_err("mismatched mirrors accepted");
    assert_eq!(error.code, "rotation_result_invalid");
    let error = rotation::decode_result(&[0xff], b"7").expect_err("invalid UTF-8 accepted");
    assert_eq!(error.code, "rotation_result_invalid");
}

#[test]
fn strict_result_has_inclusive_full_body_and_page_caps() {
    let payload = result_payload();
    let mut body = result_body(&payload, &payload, "7");
    body.resize(rotation::MAX_RESULT_BODY_BYTES, b' ');
    assert!(rotation::decode_result(&body, b"7").is_ok());
    body.push(b' ');
    let error = rotation::decode_result(&body, b"7").expect_err("oversized body accepted");
    assert_eq!(error.code, "rotation_result_invalid");
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
    let error = rotation::decode_result(&result_body(&page, &page, "7"), b"7")
        .expect_err("oversized page accepted");
    assert_eq!(error.code, "rotation_result_invalid");
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
        (
            "/result/structuredContent",
            &["current", "records", "head", "complete"],
        ),
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
