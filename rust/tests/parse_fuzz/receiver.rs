#[test]
fn receiver_header_body_mutations() {
    use mcp_jack::webhook::encoding::WebhookSecret;
    use mcp_jack::webhook::receiver::{Receiver, ReceiverConfig, ReceiverSecret};
    let sid = "sub_a3f1c8e2b0d49f7e";
    let secret = WebhookSecret::parse("whsec_XnU10kns2Fq27j9gLmtVokIK8FOLWR23RQF1a6WdHNY=")
        .expect("fixture secret");
    let config = || {
        let mut config = ReceiverConfig::default();
        config.secrets.push(ReceiverSecret {
            secret: secret.clone(),
            subscription_id: Some(sid.into()),
            callback_url: None,
        });
        config.routed.push(sid.into());
        Receiver::new(config).expect("configured receiver")
    };
    let timestamp = "1767225600";
    let valid_body = br#"{"eventId":"evt_1","name":"incident.created","timestamp":"2026-01-01T00:00:00Z","data":{"severity":"P1"}}"#;
    let verification_body = br#"{"type":"verification","challenge":"KfROIaIYzOA4LouilLN_Jw"}"#;
    let verification_id = "msg_verification_7Qk2mZ4rT9xV1bN6pL3sD8wY5cJ0hG2f";
    let verification_signature = "v1,/LA9YEiYEaS12utgc/Y7rXHYdj5KMIzq3qzWRxuwEfk=";
    let mut corpus = Vec::new();
    crate::common::strings(
        &crate::common::fixture("webhook-receiver-vectors.json"),
        &mut corpus,
    );
    crate::common::strings(
        &crate::common::fixture("webhook-signature-vectors.json"),
        &mut corpus,
    );
    let seed_doc: serde_json::Value =
        serde_json::from_slice(include_bytes!("corpus/receiver.json"))
            .expect("receiver corpus JSON");
    let mut seed_values = Vec::new();
    for case in seed_doc["cases"].as_array().expect("receiver cases") {
        for pair in case["headers"].as_array().expect("receiver headers") {
            let pair = pair.as_array().expect("header pair");
            seed_values.push(pair[0].as_str().expect("header name").as_bytes().to_vec());
            seed_values.push(pair[1].as_str().expect("header value").as_bytes().to_vec());
        }
        seed_values.push(serde_json::to_vec(&case["body"]).expect("serialize body seed"));
    }
    corpus.extend(seed_values);
    corpus.push(valid_body.to_vec());
    corpus.push(verification_body.to_vec());
    corpus.push(b"{}".to_vec());
    let corpus: Vec<&[u8]> = corpus.iter().map(Vec::as_slice).collect();
    crate::common::assert_mutations(5, &corpus, |body| {
        let fixture_verification = body == verification_body;
        let id = if fixture_verification {
            verification_id
        } else {
            "msg_7Qk2mZ4rT9xV1bN6pL3sD8wY5cJ0hG2f"
        };
        let signature = if fixture_verification {
            verification_signature
        } else {
            "v1,Bt7vsCONxET/3czQb/iQTyNMinnzGL2DglV13p/vKpk="
        };
        let headers = vec![
            ("webhook-id".into(), id.into()),
            ("webhook-timestamp".into(), timestamp.into()),
            ("webhook-signature".into(), signature.into()),
            ("x-mcp-subscription-id".into(), sid.into()),
        ];
        let outcome = config().handle(1767225600, &headers, body, |_| Ok(()));
        let parsed = serde_json::from_slice::<serde_json::Value>(body).ok();
        match parsed.as_ref() {
            Some(value)
                if value["type"] == "verification" && value["challenge"].as_str().is_some() =>
            {
                if body == verification_body {
                    assert_eq!(outcome.status, 200);
                    assert!(outcome.delivered.is_empty());
                    assert_eq!(
                        outcome.body,
                        serde_json::json!({"challenge": value["challenge"]})
                    );
                } else {
                    assert!(!(200..300).contains(&outcome.status));
                    assert!(outcome.delivered.is_empty());
                }
            }
            Some(value) if value.get("eventId").is_some() => {
                let expected = serde_json::json!({
                    "eventId": "evt_1",
                    "name": "incident.created",
                    "timestamp": "2026-01-01T00:00:00Z",
                    "data": {"severity": "P1"}
                });
                if body == valid_body && value == &expected {
                    assert_eq!(outcome.status, 200);
                    assert_eq!(outcome.delivered, vec![expected]);
                } else {
                    assert!(!(200..300).contains(&outcome.status));
                    assert!(outcome.delivered.is_empty());
                }
            }
            _ => {
                assert!(!(200..300).contains(&outcome.status));
                assert!(outcome.delivered.is_empty());
            }
        }
        for field in [0, 1, 2, 3] {
            let fuzz_value = "fuzz-mutated-header".to_owned();
            let mut mutated = headers.clone();
            mutated[field].1 = fuzz_value;
            let outcome = config().handle(1767225600, &mutated, body, |_| Ok(()));
            assert!(
                !(200..300).contains(&outcome.status),
                "accepted request with mutated required header {}",
                mutated[field].0
            );
        }
        let mut with_unknown = headers.clone();
        let fuzz_name = "x-fuzz-receiver".to_owned();
        let fuzz_value = "bounded-extra-header".to_owned();
        with_unknown.push((fuzz_name, fuzz_value));
        let baseline = config().handle(1767225600, &headers, body, |_| Ok(()));
        let extra = config().handle(1767225600, &with_unknown, body, |_| Ok(()));
        assert_eq!(
            (baseline.status, baseline.code.as_deref()),
            (extra.status, extra.code.as_deref())
        );
        for name in [
            "webhook-id",
            "webhook-timestamp",
            "webhook-signature",
            "x-mcp-subscription-id",
            "Webhook-Id",
            "WEBHOOK-TIMESTAMP",
            "Webhook-Signature",
            "X-MCP-Subscription-Id",
        ] {
            let mut duplicate = headers.clone();
            duplicate[2].1 = "v1,bogus".into();
            duplicate.push((name.into(), "!".into()));
            let answer = config().handle(1767225600, &duplicate, body, |_| Ok(()));
            assert_eq!(
                answer.code.as_deref(),
                Some(mcp_jack::webhook::codes::DUPLICATE_WEBHOOK_HEADER)
            );
        }
        let mut wrong = headers.clone();
        wrong[2].1 = "v1,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into();
        assert_ne!(
            config().handle(1767225600, &wrong, body, |_| Ok(())).status,
            200
        );
    });
    let id = "msg_7Qk2mZ4rT9xV1bN6pL3sD8wY5cJ0hG2f";
    let valid_headers = vec![
        ("webhook-id".into(), id.into()),
        ("webhook-timestamp".into(), timestamp.into()),
        (
            "webhook-signature".into(),
            "v1,Bt7vsCONxET/3czQb/iQTyNMinnzGL2DglV13p/vKpk=".into(),
        ),
        ("x-mcp-subscription-id".into(), sid.into()),
    ];
    let accepted = config().handle(1767225600, &valid_headers, valid_body, |_| Ok(()));
    assert_eq!(accepted.status, 200);
    assert_eq!(
        accepted.delivered,
        vec![serde_json::json!({
            "eventId": "evt_1",
            "name": "incident.created",
            "timestamp": "2026-01-01T00:00:00Z",
            "data": {"severity": "P1"}
        })]
    );
    let verification_headers = vec![
        ("webhook-id".into(), verification_id.into()),
        ("webhook-timestamp".into(), timestamp.into()),
        ("webhook-signature".into(), verification_signature.into()),
        ("X-MCP-Subscription-Id".into(), sid.into()),
    ];
    let verification =
        config().handle(1767225600, &verification_headers, verification_body, |_| {
            Ok(())
        });
    assert_eq!(verification.status, 200);
    assert!(verification.delivered.is_empty());
    assert_eq!(
        verification.body,
        serde_json::json!({"challenge": "KfROIaIYzOA4LouilLN_Jw"})
    );
    for (body, signature, expected) in [
        (
            br#"{"type":"gap","cursor":"cursor_7f3a"}"#.as_slice(),
            "v1,VAG1p8pjLPqKLd8AhyuyeCdjCXYMXEIUTjnCgUfGzY8=",
            serde_json::json!({"type":"gap","cursor":"cursor_7f3a"}),
        ),
        (
            br#"{"type":"terminated","error":{"code":-32024,"message":"Forbidden"}}"#.as_slice(),
            "v1,Hdqvp48n5yxsoslPCZfxKidbEYbIfplpYRESAZ3O1TI=",
            serde_json::json!({"type":"terminated","error":{"code":-32024,"message":"Forbidden"}}),
        ),
    ] {
        let headers = vec![
            ("webhook-id".into(), id.into()),
            ("webhook-timestamp".into(), timestamp.into()),
            ("webhook-signature".into(), signature.into()),
            ("X-MCP-Subscription-Id".into(), sid.into()),
        ];
        let outcome = config().handle(1767225600, &headers, body, |_| Ok(()));
        assert_eq!(outcome.status, 200);
        assert_eq!(outcome.delivered, vec![expected]);
    }
    let altered_body = valid_body
        .iter()
        .enumerate()
        .map(|(i, byte)| if i == 0 { *byte ^ 1 } else { *byte })
        .collect::<Vec<_>>();
    let altered = config().handle(1767225600, &valid_headers, &altered_body, |_| Ok(()));
    assert_eq!(
        altered.code.as_deref(),
        Some(mcp_jack::webhook::codes::BAD_SIGNATURE)
    );
    let mut header_corpus = Vec::new();
    let receiver_vectors = crate::common::fixture("webhook-receiver-vectors.json");
    crate::common::strings(&receiver_vectors, &mut header_corpus);
    let malformed = receiver_vectors["cases"]
        .as_array()
        .expect("receiver cases")
        .iter()
        .find(|case| case["id"] == "rcv-r13-malformed-body")
        .expect("independent malformed-body signature fixture");
    let step = &malformed["input"]["steps"][0];
    let fixture_headers: Vec<(String, String)> = step["headers"]
        .as_array()
        .expect("fixture headers")
        .iter()
        .map(|pair| {
            let pair = pair.as_array().expect("fixture header pair");
            (
                pair[0].as_str().expect("header name").to_owned(),
                pair[1].as_str().expect("header value").to_owned(),
            )
        })
        .collect();
    let malformed_body = step["body_text"].as_str().expect("malformed body");
    let malformed_outcome = config().handle(
        step["now"].as_i64().expect("fixture time"),
        &fixture_headers,
        malformed_body.as_bytes(),
        |_| Ok(()),
    );
    assert_eq!(malformed_outcome.status, 400);
    assert_eq!(
        malformed_outcome.code.as_deref(),
        Some(mcp_jack::webhook::codes::MALFORMED_BODY)
    );
    assert!(malformed_outcome.delivered.is_empty());
}
