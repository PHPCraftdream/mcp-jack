#[test]
fn header_encoding_mutations() {
    use mcp_jack::client::modern::{project_arguments, validate_annotations};

    let encoding = crate::common::fixture("header-encoding-vectors.json");
    for case in encoding["cases"].as_array().expect("encoding cases") {
        if case["kind"] == "decode" && case["expect"]["ok"] == false {
            let value = case["header_value"].as_str().expect("header value");
            assert_eq!(
                mcp_jack::modern::decode_header_value(value),
                Err(mcp_jack::modern::DecodeHeaderValueError::BadEncoding)
            );
        }
    }

    let doc = crate::common::fixture("x-mcp-header-vectors.json");
    let cases = doc["cases"].as_array().expect("header cases");
    let mut handled = 0usize;
    for case in cases {
        let kind = case["kind"].as_str().expect("case kind");
        match kind {
            "validate" | "validate-event" => {
                let holder = if kind == "validate-event" {
                    "event"
                } else {
                    "tool"
                };
                let actual = validate_annotations(&case[holder]["inputSchema"]);
                if case["expect"]["valid"] == true {
                    assert!(actual.is_ok(), "{}: {actual:?}", case["id"]);
                    assert!(case["expect"]["reason"].is_null());
                } else {
                    assert_eq!(
                        actual.expect_err("invalid annotation").as_str(),
                        case["expect"]["reason"].as_str().expect("reason"),
                        "{}",
                        case["id"]
                    );
                }
                handled += 1;
            }
            "project" | "project-event" => {
                let holder = if kind == "project-event" {
                    "event"
                } else {
                    "tool"
                };
                let actual = project_arguments(&case[holder]["inputSchema"], &case["arguments"]);
                match case["expect"]["outcome"]
                    .as_str()
                    .expect("projection outcome")
                {
                    "headers" => {
                        let expected: Vec<(String, String)> = case["expect"]["headers"]
                            .as_array()
                            .expect("header pairs")
                            .iter()
                            .map(|pair| {
                                let pair = pair.as_array().expect("pair");
                                (
                                    pair[0].as_str().expect("name").to_owned(),
                                    pair[1].as_str().expect("value").to_owned(),
                                )
                            })
                            .collect();
                        assert_eq!(
                            actual.expect("projected headers"),
                            expected,
                            "{}",
                            case["id"]
                        );
                    }
                    "refuse" => assert_eq!(
                        actual.expect_err("projection refusal").as_str(),
                        case["expect"]["reason"].as_str().expect("reason"),
                        "{}",
                        case["id"]
                    ),
                    other => panic!("unknown projection outcome {other}"),
                }
                handled += 1;
            }
            other => panic!("unexpected header-vector kind {other}"),
        }
    }
    assert_eq!(handled, cases.len());

    let malformed_cases = ["=?base64?Q?bad?=", "=?base64?Q?Zm9v?="];
    for value in malformed_cases {
        assert_eq!(
            mcp_jack::modern::decode_header_value(value),
            Err(mcp_jack::modern::DecodeHeaderValueError::BadEncoding)
        );
    }
    // C4: a value that does not end with `?=` is plain text, even if it starts like a sentinel.
    assert_eq!(
        mcp_jack::modern::decode_header_value("=?base64?Q?Zm9v?=\r\n").expect("plain text"),
        "=?base64?Q?Zm9v?=\r\n"
    );

    let mut corpus = Vec::new();
    crate::common::strings(&encoding, &mut corpus);
    crate::common::strings(&doc, &mut corpus);
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
    });
}
