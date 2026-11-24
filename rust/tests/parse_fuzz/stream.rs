#[test]
fn signed_stream_mutations() {
    use mcp_jack::stream::{StreamCode, StreamVerifier, StreamVerifierConfig};
    use std::sync::Arc;

    let doc = crate::common::fixture("stream-vectors.json");
    let case = doc["cases"]
        .as_array()
        .expect("stream cases")
        .iter()
        .find(|case| case["expect"]["terminal"]["state"] == "ok")
        .expect("successful stream fixture");
    let state = &case["state"];
    let response = &case["response"];
    let kid = state["pinned_server_kid"].as_str().expect("pinned kid");
    let public_bytes = mcp_jack::encoding::decode_b64url(
        state["pinned_server_public_key"]
            .as_str()
            .expect("public key"),
    )
    .expect("fixture public key");
    let public_key: [u8; 32] = public_bytes.try_into().expect("32-byte public key");
    let verifying_key = public_key;
    let request_sig = state["request_sig"].as_str().expect("request signature");
    let now = state["now"].as_i64().expect("deterministic fixture clock");
    let expected: Vec<String> = case["expect"]["messages"]
        .as_array()
        .expect("expected messages")
        .iter()
        .map(|message| message.as_str().expect("message string").to_owned())
        .collect();
    let mut body = Vec::new();
    for chunk in response["stream_b64u"].as_array().expect("body chunks") {
        body.extend_from_slice(
            &mcp_jack::encoding::decode_b64url(chunk.as_str().expect("base64url chunk"))
                .expect("valid fixture chunk"),
        );
    }
    let headers: Vec<(String, String)> = response["headers"]
        .as_array()
        .expect("response headers")
        .iter()
        .map(|pair| {
            let pair = pair.as_array().expect("header pair");
            (
                pair[0].as_str().expect("header name").to_owned(),
                pair[1].as_str().expect("header value").to_owned(),
            )
        })
        .collect();
    let status = response["status"].as_u64().expect("response status") as u16;
    let config = || {
        let mut config = StreamVerifierConfig::pinned(kid, verifying_key, request_sig);
        config.now = Arc::new(move || now);
        config
    };
    let mut verifier = StreamVerifier::new(config());
    verifier
        .open(status, &headers)
        .expect("fixture stream open");
    let step = verifier.push(&body, 0);
    let mut delivered = step.messages;
    if step.terminal.is_none() {
        delivered.extend(verifier.finish(None).messages);
    }
    assert_eq!(
        delivered, expected,
        "valid fixture must deliver all oracle messages"
    );

    // Explicit negative control: alter a signature in the actual first frame.
    let mut bad_signature = body.clone();
    let sig_at = bad_signature
        .windows(4)
        .position(|window| window == b"sig=")
        .expect("frame signature");
    bad_signature[sig_at + 4] ^= 1;
    let mut verifier = StreamVerifier::new(config());
    verifier
        .open(status, &headers)
        .expect("fixture stream open");
    let step = verifier.push(&bad_signature, 0);
    assert!(step.messages.is_empty());
    assert_eq!(
        step.terminal.map(|failure| failure.code),
        Some(StreamCode::BadSignature)
    );

    let seed_doc: serde_json::Value =
        serde_json::from_slice(include_bytes!("corpus/stream.json")).expect("stream corpus JSON");
    let mut seed_bytes = vec![seed_doc["wire"]
        .as_str()
        .expect("wire SSE frame")
        .as_bytes()
        .to_vec()];
    seed_bytes.push(
        seed_doc["open"]
            .as_str()
            .expect("open auth")
            .as_bytes()
            .to_vec(),
    );
    seed_bytes.push(body.clone());
    let seed_refs: Vec<&[u8]> = seed_bytes.iter().map(Vec::as_slice).collect();
    crate::common::assert_mutations(0, &seed_refs, |mutated| {
        let mut verifier = StreamVerifier::new(config());
        assert!(verifier.open(status, &headers).is_ok());
        let step = verifier.push(mutated, 0);
        let mut outputs = step.messages;
        let terminal = if let Some(failure) = step.terminal {
            Some(failure.code)
        } else {
            let finished = verifier.finish(None);
            outputs.extend(finished.messages);
            finished.terminal.map(|failure| failure.code)
        };
        if let Some(code) = terminal {
            assert!(StreamCode::ALL.contains(&code));
        }
        assert!(
            expected.starts_with(&outputs),
            "messages are not an oracle prefix: {outputs:?}"
        );
    });

    use ed25519_dalek::SigningKey;
    use mcp_jack::stream::{StaticStreamSigner, StreamBuilder};
    let signer = StaticStreamSigner::new(SigningKey::from_bytes(&[7; 32]), None);

    // LF is preserved as message data but rejected by the stdio line consumer.
    let (_, open) = StreamBuilder::open(
        200,
        request_sig,
        signer.kid(),
        now,
        "AAAAAAAAAAAAAAAAAAAAAA",
        &signer,
    )
    .expect("static signer");
    let mut builder = StreamBuilder::resume("AAAAAAAAAAAAAAAAAAAAAA", &open.sig);
    let (_, frame) = builder.frame(now, "line\nnext", &signer).expect("LF frame");
    let (_, end) = builder.end(now, &signer).expect("LF end");
    let lf_body = format!("{frame}{end}");
    let mut message_config =
        StreamVerifierConfig::pinned(signer.kid(), signer.verifying_key(), request_sig);
    message_config.now = Arc::new(move || now);
    let mut verifier = StreamVerifier::new(message_config);
    verifier
        .open(200, &[("Jack-Auth".into(), open.jack_auth.clone())])
        .expect("signed open for Message");
    let result = verifier.push(lf_body.as_bytes(), 0);
    assert_eq!(result.messages, vec!["line\nnext"]);
    assert!(result.terminal.is_none());

    let mut stdio_config =
        StreamVerifierConfig::pinned(signer.kid(), signer.verifying_key(), request_sig);
    stdio_config.now = Arc::new(move || now);
    stdio_config.consumer = mcp_jack::stream::StreamConsumer::Stdio;
    let mut verifier = StreamVerifier::new(stdio_config);
    verifier
        .open(200, &[("Jack-Auth".into(), open.jack_auth)])
        .expect("signed open for Stdio");
    let result = verifier.push(lf_body.as_bytes(), 0);
    assert!(result.messages.is_empty());
    assert!(result
        .terminal
        .is_some_and(|failure| failure.code == StreamCode::BadFrame));

    // SSE treats CR as a line terminator and the public parser cannot preserve
    // it as message data; retain the honest typed-error control.
    let (_, open) = StreamBuilder::open(
        200,
        request_sig,
        signer.kid(),
        now,
        "AAAAAAAAAAAAAAAAAAAAAA",
        &signer,
    )
    .expect("static signer");
    let mut builder = StreamBuilder::resume("AAAAAAAAAAAAAAAAAAAAAA", &open.sig);
    let (_, frame) = builder.frame(now, "line\rnext", &signer).expect("CR frame");
    let (_, end) = builder.end(now, &signer).expect("CR end");
    let cr_body = format!("{frame}{end}");
    let mut cfg = StreamVerifierConfig::pinned(signer.kid(), signer.verifying_key(), request_sig);
    cfg.now = Arc::new(move || now);
    let mut verifier = StreamVerifier::new(cfg);
    verifier
        .open(200, &[("Jack-Auth".into(), open.jack_auth)])
        .expect("signed open");
    let result = verifier.push(cr_body.as_bytes(), 0);
    assert!(result.messages.is_empty());
    assert!(result
        .terminal
        .is_some_and(|failure| StreamCode::ALL.contains(&failure.code)));
}
