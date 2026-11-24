#[test]
fn webhook_grammar_mutations() {
    use mcp_jack::webhook::codes;
    use mcp_jack::webhook::signatures::{check_schemes, decode_signatures, parse_signature_header};

    let doc = crate::common::fixture("webhook-signature-vectors.json");
    let cases = doc["cases"].as_array().expect("signature cases");
    let mut saw_verify = 0usize;
    for case in cases.iter().filter(|case| case["kind"] == "verify") {
        saw_verify += 1;
        let header = case["input"]["envelope"]["signature_header"]
            .as_str()
            .expect("verify signature header");
        let expected_code = case["expect"]["code"].as_str().unwrap_or_default();
        let parsed = parse_signature_header(header);
        if expected_code == codes::MALFORMED_SIGNATURE_HEADER {
            assert_eq!(
                parsed.expect_err("malformed header fixture").code,
                codes::MALFORMED_SIGNATURE_HEADER
            );
            continue;
        }
        let entries = parsed.expect("valid grammar in verify fixture");
        let schemes = check_schemes(&entries);
        if expected_code == codes::UNSUPPORTED_SIGNATURE_SCHEME {
            assert_eq!(
                schemes
                    .expect_err("fixture expects unsupported scheme")
                    .code,
                codes::UNSUPPORTED_SIGNATURE_SCHEME
            );
            continue;
        }
        schemes.expect("known schemes in verify fixture");
        let decoded = decode_signatures(&entries);
        if expected_code == codes::MALFORMED_SIGNATURE {
            assert_eq!(
                decoded
                    .expect_err("fixture expects malformed signature")
                    .code,
                codes::MALFORMED_SIGNATURE
            );
        } else {
            decoded.expect("signature encodings are valid for this fixture verdict");
        }
    }
    assert!(saw_verify > 0);

    // Independent grammar oracle: exact token grammar, plus fixture malformed
    // vectors and exact typed errors for scheme/value validation.
    for (header, expected_code) in [
        ("", codes::MALFORMED_SIGNATURE_HEADER),
        (" v1,AAAA=", codes::MALFORMED_SIGNATURE_HEADER),
        ("v1,AAAA= ", codes::MALFORMED_SIGNATURE_HEADER),
        ("v1,AAAA=  v1,AAAA=", codes::MALFORMED_SIGNATURE_HEADER),
        ("v1,", codes::MALFORMED_SIGNATURE_HEADER),
        ("v1,AAAA=", ""),
        ("v3,AAAA=", ""),
        ("v1,not-base64", ""),
    ] {
        match parse_signature_header(header) {
            Err(error) => assert_eq!(error.code, expected_code, "{header:?}"),
            Ok(entries) => {
                assert!(
                    expected_code.is_empty(),
                    "unexpected parse rejection: {header:?}"
                );
                if header.starts_with("v3,") {
                    assert_eq!(
                        check_schemes(&entries).expect_err("unknown scheme").code,
                        codes::UNSUPPORTED_SIGNATURE_SCHEME
                    );
                } else {
                    assert_eq!(
                        decode_signatures(&entries)
                            .expect_err("bad signature encoding")
                            .code,
                        codes::MALFORMED_SIGNATURE
                    );
                }
            }
        }
    }
    let valid = parse_signature_header("v1,CeUDFQCQeytGTEJxiPcQFJvoIThfUCigpIxncZitsk8=")
        .expect("v1 fixture grammar");
    assert_eq!(
        decode_signatures(&valid).expect("valid v1 vector")[0]
            .bytes
            .len(),
        32
    );

    let w1 = crate::common::fixture("webhook-w1-vectors.json");
    let mut saw_w1 = 0usize;
    for case in w1["cases"].as_array().expect("w1 cases") {
        let kind = case["kind"].as_str().unwrap_or_default();
        if matches!(kind, "verify-w1" | "kat-w1") {
            saw_w1 += 1;
            if let Some(header) = case["input"]["header"]
                .as_str()
                .or_else(|| case["expect"]["header"].as_str())
            {
                let parsed = mcp_jack::webhook::w1::parse_header(header);
                if case["expect"]["code"] == mcp_jack::webhook::codes::MALFORMED_JACK_AUTH {
                    assert_eq!(
                        parsed.expect_err("malformed w1 fixture").code,
                        mcp_jack::webhook::codes::MALFORMED_JACK_AUTH,
                        "{}",
                        case["id"]
                    );
                } else {
                    assert!(parsed.is_ok(), "valid w1 fixture header {}", case["id"]);
                }
            }
        }
    }
    assert!(saw_w1 > 0);

    let mut corpus = Vec::new();
    for name in [
        "webhook-signature-vectors.json",
        "webhook-subscription-vectors.json",
        "webhook-w1-vectors.json",
    ] {
        crate::common::strings(&crate::common::fixture(name), &mut corpus);
    }
    corpus.push(include_bytes!("corpus/signatures.json").to_vec());
    let corpus: Vec<&[u8]> = corpus.iter().map(Vec::as_slice).collect();
    crate::common::assert_mutations(4, &corpus, |bytes| {
        let Ok(text) = std::str::from_utf8(bytes) else {
            return;
        };
        let _ = parse_signature_header(text);
        let _ = mcp_jack::webhook::w1::parse_header(text);
        let _ = mcp_jack::webhook::subscription::subscription_id_ok(text);
        let webhook_id_oracle = |s: &str| {
            (8..=128).contains(&s.len())
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        };
        let timestamp_oracle = |s: &str| {
            s == "0"
                || (!s.is_empty()
                    && s.len() <= 12
                    && s.as_bytes()[0] != b'0'
                    && s.bytes().all(|b| b.is_ascii_digit()))
        };
        let subscription_oracle = |s: &str| {
            s.strip_prefix("sub_").is_some_and(|rest| {
                rest.len() == 16
                    && rest
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
        };
        assert_eq!(
            mcp_jack::webhook::subscription::webhook_id_ok(text),
            webhook_id_oracle(text)
        );
        assert_eq!(
            mcp_jack::webhook::subscription::timestamp_ok(text),
            timestamp_oracle(text)
        );
        assert_eq!(
            mcp_jack::webhook::subscription::subscription_id_ok(text),
            subscription_oracle(text)
        );
    });
}
