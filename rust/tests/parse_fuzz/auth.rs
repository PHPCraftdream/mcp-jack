#[test]
fn open_auth_corpus_cases() {
    let corpus: serde_json::Value = serde_json::from_slice(include_bytes!("corpus/auth.json"))
        .expect("auth JSON corpus must parse");
    let order = corpus["order"].as_str().expect("order string");
    let valid = corpus["valid"].as_str().expect("valid string");

    let parsed = mcp_jack::stream::parse_open_auth(&[order]).expect("reordered parameters parse");
    assert_eq!(
        mcp_jack::stream::parse_open_auth(&[valid]),
        Ok(parsed.clone()),
        "order and valid corpus entries must represent the same auth"
    );

    let duplicate_kid = valid.replacen(
        ",ts=",
        ",kid=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,ts=",
        1,
    );
    assert!(mcp_jack::stream::parse_open_auth(&[&duplicate_kid]).is_err());

    let oversized_kid = valid.replacen(
        "kid=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        &format!("kid={}", "A".repeat(128)),
        1,
    );
    assert!(
        mcp_jack::stream::parse_open_auth(&[&oversized_kid]).is_err(),
        "accepted an overlong base64url auth parameter"
    );

    for (field, replacement) in [
        ("kid=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "kid=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        ("sid=AAAAAAAAAAAAAAAAAAAAAA", "sid=AAAAAAAAAAAAAAAAAAAA"),
        ("sig=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "sig=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
    ] {
        let malformed = valid.replacen(field, replacement, 1);
        assert!(
            mcp_jack::stream::parse_open_auth(&[&malformed]).is_err(),
            "accepted wrong canonical size for {field}"
        );
    }
}

#[test]
fn open_auth_roundtrip_mutations() {
    let doc = crate::common::fixture("stream-build-vectors.json");
    let mut corpus = Vec::new();
    crate::common::strings(&doc, &mut corpus);
    corpus.push(include_bytes!("corpus/auth.json").to_vec());
    let corpus: Vec<&[u8]> = corpus.iter().map(Vec::as_slice).collect();
    crate::common::assert_mutations(1, &corpus, |bytes| {
        let Ok(text) = std::str::from_utf8(bytes) else {
            return;
        };
        let values = [text];
        if let Ok(auth) = mcp_jack::stream::parse_open_auth(&values) {
            let formatted = mcp_jack::stream::format_open_auth(&auth);
            assert_eq!(mcp_jack::stream::parse_open_auth(&[&formatted]), Ok(auth));
        }
    });
}
