#[test]
fn receiver_header_body_mutations() {
    use mcp_jack::webhook::encoding::{encode_b64_std, WebhookSecret};
    use mcp_jack::webhook::receiver::{Receiver, ReceiverConfig, ReceiverSecret};
    use mcp_jack::webhook::signatures::{
        decode_signatures, parse_signature_header, v1_sign, v1_verify, SignatureContent,
    };
    let sid = "sub_0000000000000000";
    let secret =
        WebhookSecret::parse(&format!("whsec_{}", encode_b64_std(&[9; 32]))).expect("test secret");
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
    let timestamp = "1000";
    let valid_body =
        br#"{"eventId":"evt-1","name":"event.name","timestamp":"2026-01-01T00:00:00Z","data":{}}"#;
    let mut corpus = Vec::new();
    crate::common::strings(
        &crate::common::fixture("webhook-receiver-vectors.json"),
        &mut corpus,
    );
    crate::common::strings(
        &crate::common::fixture("webhook-signature-vectors.json"),
        &mut corpus,
    );
    corpus.push(include_bytes!("corpus/receiver.json").to_vec());
    corpus.push(valid_body.to_vec());
    corpus.push(b"{}".to_vec());
    let corpus: Vec<&[u8]> = corpus.iter().map(Vec::as_slice).collect();
    crate::common::assert_mutations(5, &corpus, |body| {
        let id = "msg_abcdefgh1234567890abcdefgh1234";
        let signature = v1_sign(
            &secret,
            &SignatureContent {
                webhook_id: id,
                timestamp,
                body,
            },
        );
        let headers = vec![
            ("webhook-id".into(), id.into()),
            ("webhook-timestamp".into(), timestamp.into()),
            ("webhook-signature".into(), signature),
            ("x-mcp-subscription-id".into(), sid.into()),
        ];
        let outcome = config().handle(1000, &headers, body, |_| Ok(()));
        if (200..300).contains(&outcome.status) {
            let entries = decode_signatures(
                &parse_signature_header(&headers[2].1).expect("signature grammar"),
            )
            .expect("signature bytes");
            assert!(
                v1_verify(
                    &entries,
                    &secret,
                    &SignatureContent {
                        webhook_id: id,
                        timestamp,
                        body
                    }
                ),
                "accepted request lacks independently verified exact-body v1 MAC"
            );
            assert_eq!(outcome.delivered.len(), 1);
        }
        for field in [0, 1, 2, 3] {
            // Lossy UTF-8 conversion makes every arbitrary byte sequence a deterministic string.
            let fuzz_value = format!("fuzz-{}", String::from_utf8_lossy(body));
            let mut mutated = headers.clone();
            mutated[field].1 = fuzz_value;
            let outcome = config().handle(1000, &mutated, body, |_| Ok(()));
            if (200..300).contains(&outcome.status) {
                let entries = decode_signatures(
                    &parse_signature_header(&mutated[2].1).expect("signature grammar"),
                )
                .expect("signature bytes");
                assert!(
                    v1_verify(
                        &entries,
                        &secret,
                        &SignatureContent {
                            webhook_id: &mutated[0].1,
                            timestamp: &mutated[1].1,
                            body,
                        }
                    ),
                    "accepted mutated request lacks exact id/timestamp/body v1 MAC"
                );
            }
            assert!(
                !(200..300).contains(&outcome.status),
                "accepted request with mutated required header {}",
                mutated[field].0
            );
        }
        let mut with_unknown = headers.clone();
        let fuzz_hex = crate::common::hex(body);
        let fuzz_name = format!("x-fuzz-{fuzz_hex}");
        let fuzz_value = format!("bytes-{fuzz_hex}");
        with_unknown.push((fuzz_name, fuzz_value));
        let baseline = config().handle(1000, &headers, body, |_| Ok(()));
        let extra = config().handle(1000, &with_unknown, body, |_| Ok(()));
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
            let answer = config().handle(1000, &duplicate, body, |_| Ok(()));
            assert_eq!(
                answer.code.as_deref(),
                Some(mcp_jack::webhook::codes::DUPLICATE_WEBHOOK_HEADER)
            );
        }
        let mut wrong = headers.clone();
        wrong[2].1 = "v1,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into();
        assert_ne!(config().handle(1000, &wrong, body, |_| Ok(())).status, 200);
    });
    let id = "msg_abcdefgh1234567890abcdefgh1234";
    let valid_signature = v1_sign(
        &secret,
        &SignatureContent {
            webhook_id: id,
            timestamp,
            body: valid_body,
        },
    );
    let valid_headers = vec![
        ("webhook-id".into(), id.into()),
        ("webhook-timestamp".into(), timestamp.into()),
        ("webhook-signature".into(), valid_signature),
        ("x-mcp-subscription-id".into(), sid.into()),
    ];
    let accepted = config().handle(1000, &valid_headers, valid_body, |_| Ok(()));
    assert!((200..300).contains(&accepted.status));
    let decoded =
        decode_signatures(&parse_signature_header(&valid_headers[2].1).expect("signature grammar"))
            .expect("signature bytes");
    assert!(v1_verify(
        &decoded,
        &secret,
        &SignatureContent {
            webhook_id: id,
            timestamp,
            body: valid_body
        }
    ));
    let mut header_corpus = Vec::new();
    crate::common::strings(
        &crate::common::fixture("webhook-receiver-vectors.json"),
        &mut header_corpus,
    );
    for body in [b"{}".as_slice(), b"not json".as_slice()] {
        let sig = v1_sign(
            &secret,
            &SignatureContent {
                webhook_id: id,
                timestamp,
                body,
            },
        );
        let headers = vec![
            ("webhook-id".into(), id.into()),
            ("webhook-timestamp".into(), timestamp.into()),
            ("webhook-signature".into(), format!("v1,{sig}")),
            ("x-mcp-subscription-id".into(), sid.into()),
        ];
        let outcome = config().handle(1000, &headers, body, |_| Ok(()));
        assert_eq!(
            outcome.code.as_deref(),
            Some(mcp_jack::webhook::codes::MALFORMED_BODY)
        );
    }
}
