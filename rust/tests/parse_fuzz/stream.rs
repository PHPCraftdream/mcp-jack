#[test]
fn signed_stream_mutations() {
    use ed25519_dalek::SigningKey;
    use mcp_jack::stream::{
        StaticStreamSigner, StreamBuilder, StreamVerifier, StreamVerifierConfig,
    };
    use std::sync::Arc;
    let key = SigningKey::from_bytes(&[7; 32]);
    let signer = StaticStreamSigner::new(key, None);
    let request_sig = "request-signature";
    let (mut builder, open) = StreamBuilder::open(
        200,
        request_sig,
        signer.kid(),
        1000,
        "AAAAAAAAAAAAAAAAAAAAAA",
        &signer,
    )
    .expect("static signer");
    let open_header = open.jack_auth.clone();
    let (_, first) = builder.frame(1000, "first", &signer).expect("frame");
    let (_, second) = builder.frame(1001, "second", &signer).expect("frame");
    let (_, end) = builder.end(1001, &signer).expect("end");
    let signed_body = format!("{first}{second}{end}");
    let mut cfg = StreamVerifierConfig::pinned(signer.kid(), signer.verifying_key(), request_sig);
    cfg.now = Arc::new(|| 1001);
    let mut verifier = StreamVerifier::new(cfg);
    verifier
        .open(200, &[("Jack-Auth".into(), open_header.clone())])
        .expect("signed open");
    let mut result = verifier.push(signed_body.as_bytes(), 0);
    let mut delivered = result.messages;
    if result.terminal.is_none() {
        result = verifier.finish(None);
        delivered.extend(result.messages);
    }
    assert_eq!(delivered, ["first", "second"]);

    // SSE treats CR as a line terminator (spec/05 §2.14), so CR in
    // StreamBuilder data is transformed by framing and cannot reach a verified
    // message through the public verifier. Only assert a typed parser error.
    let mut cr_builder = StreamBuilder::resume("AAAAAAAAAAAAAAAAAAAAAA", &open.sig);
    let (_, cr_frame) = cr_builder
        .frame(1002, "line\rnext", &signer)
        .expect("CR frame");
    let (_, cr_end) = cr_builder.end(1002, &signer).expect("CR end");
    let cr_body = format!("{cr_frame}{cr_end}");
    let mut cfg = StreamVerifierConfig::pinned(signer.kid(), signer.verifying_key(), request_sig);
    cfg.now = Arc::new(|| 1002);
    let mut verifier = StreamVerifier::new(cfg);
    verifier
        .open(200, &[("Jack-Auth".into(), open_header.clone())])
        .expect("signed open");
    let cr_result = verifier.push(cr_body.as_bytes(), 0);
    assert!(cr_result.messages.is_empty());
    assert!(cr_result
        .terminal
        .is_some_and(|failure| mcp_jack::stream::StreamCode::ALL.contains(&failure.code)));

    // LF is representable in a signed SSE frame: Message delivers it, while
    // Stdio verifies/counts the frame and then aborts before delivery.
    let mut raw_builder = StreamBuilder::resume("AAAAAAAAAAAAAAAAAAAAAA", &open.sig);
    let (_, raw_frame) = raw_builder
        .frame(1002, "line\nnext", &signer)
        .expect("raw LF frame");
    let (_, raw_end) = raw_builder.end(1002, &signer).expect("raw LF end");
    let raw_body = format!("{raw_frame}{raw_end}");
    for consumer in [
        mcp_jack::stream::StreamConsumer::Message,
        mcp_jack::stream::StreamConsumer::Stdio,
    ] {
        let mut cfg =
            StreamVerifierConfig::pinned(signer.kid(), signer.verifying_key(), request_sig);
        cfg.consumer = consumer;
        cfg.now = Arc::new(|| 1002);
        let mut verifier = StreamVerifier::new(cfg);
        verifier
            .open(200, &[("Jack-Auth".into(), open_header.clone())])
            .expect("signed open");
        let step = verifier.push(raw_body.as_bytes(), 0);
        if consumer == mcp_jack::stream::StreamConsumer::Message {
            assert_eq!(step.messages, ["line\nnext"]);
            assert!(step.terminal.is_none());
        } else {
            assert_eq!(
                step.terminal.map(|failure| failure.code),
                Some(mcp_jack::stream::StreamCode::BadFrame)
            );
            assert!(step.messages.is_empty());
        }
    }
    let doc = crate::common::fixture("stream-vectors.json");
    let mut corpus = Vec::new();
    crate::common::strings(&doc, &mut corpus);
    corpus.push(include_bytes!("corpus/stream.json").to_vec());
    corpus.push(signed_body.into_bytes());
    let corpus: Vec<&[u8]> = corpus.iter().map(Vec::as_slice).collect();
    crate::common::assert_mutations(0, &corpus, |bytes| {
        let mut cfg =
            StreamVerifierConfig::pinned(signer.kid(), signer.verifying_key(), request_sig);
        cfg.now = Arc::new(|| 1001);
        let mut verifier = StreamVerifier::new(cfg);
        let opened = verifier.open(200, &[("Jack-Auth".into(), open_header.clone())]);
        assert!(opened.is_ok());
        let step = verifier.push(bytes, 0);
        let mut outputs = step.messages;
        let mut terminals = Vec::new();
        if let Some(failure) = step.terminal {
            terminals.push(failure.code);
        } else {
            let finished = verifier.finish(None);
            outputs.extend(finished.messages);
            if let Some(failure) = finished.terminal {
                terminals.push(failure.code);
            }
        }
        assert!(terminals
            .iter()
            .all(|code| mcp_jack::stream::StreamCode::ALL.contains(code)));
        let known = ["first".to_string(), "second".to_string()];
        assert!(
            known.starts_with(&outputs),
            "delivered outputs are not a prefix of known signed messages: {outputs:?}"
        );
        if let Ok(text) = std::str::from_utf8(bytes) {
            let values = [text];
            let _ = mcp_jack::stream::parse_open_auth(&values);
            let _ = mcp_jack::stream::accepts_s1(&values);
        }
    });
}
