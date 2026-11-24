#[test]
fn webhook_grammar_mutations() {
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
        if let Ok(entries) = mcp_jack::webhook::signatures::parse_signature_header(text) {
            let _ = mcp_jack::webhook::signatures::check_schemes(&entries);
            let _ = mcp_jack::webhook::signatures::decode_signatures(&entries);
        }
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
        for prefix in ["v", "v1", "v1a", "v2a", "v3"] {
            let candidate = format!("{prefix},not-base64");
            if let Ok(entries) = mcp_jack::webhook::signatures::parse_signature_header(&candidate) {
                let _ = mcp_jack::webhook::signatures::check_schemes(&entries);
                let _ = mcp_jack::webhook::signatures::decode_signatures(&entries);
            }
        }
    });
}
