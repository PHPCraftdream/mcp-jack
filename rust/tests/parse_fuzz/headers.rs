#[test]
fn header_encoding_mutations() {
    let encoding = crate::common::fixture("header-encoding-vectors.json");
    if let Some(cases) = encoding.get("cases").and_then(serde_json::Value::as_array) {
        for case in cases {
            if case["kind"] == "decode" && case["expect"]["ok"] == false {
                if let Some(value) = case["header_value"].as_str() {
                    assert!(mcp_jack::modern::decode_header_value(value).is_err());
                }
            }
        }
    }
    let mut corpus = Vec::new();
    crate::common::strings(&encoding, &mut corpus);
    crate::common::strings(
        &crate::common::fixture("x-mcp-header-vectors.json"),
        &mut corpus,
    );
    corpus.push(include_bytes!("corpus/header.json").to_vec());
    let corpus: Vec<&[u8]> = corpus.iter().map(Vec::as_slice).collect();
    crate::common::assert_mutations(3, &corpus, |bytes| {
        let Ok(text) = std::str::from_utf8(bytes) else {
            return;
        };
        let encoded = mcp_jack::modern::encode_header_value(text);
        assert_eq!(
            mcp_jack::modern::decode_header_value(&encoded),
            Ok(text.to_string())
        );
        let _ = mcp_jack::modern::decode_header_value(text);
        let _ = mcp_jack::client::modern::text_of_value(
            &serde_json::Value::String(text.to_string()),
            "string",
        );
    });
}
