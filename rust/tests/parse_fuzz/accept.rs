fn oracle_values(values: &[&str]) -> bool {
    values.iter().any(|value| {
        let bytes = value.as_bytes();
        let mut i = 0;
        while bytes.get(i) == Some(&b' ') {
            i += 1;
        }
        let mut found = false;
        loop {
            let start = i;
            while bytes
                .get(i)
                .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'-')
            {
                i += 1;
            }
            if start == i {
                return false;
            }
            found |= &bytes[start..i] == b"s1";
            if i == bytes.len() {
                return found;
            }
            while bytes.get(i) == Some(&b' ') {
                i += 1;
            }
            if bytes.get(i) != Some(&b',') {
                return false;
            }
            i += 1;
            while bytes.get(i) == Some(&b' ') {
                i += 1;
            }
        }
    })
}

#[test]
fn accept_token_mutations() {
    let mut corpus = Vec::new();
    crate::common::strings(&crate::common::fixture("stream-vectors.json"), &mut corpus);
    corpus.push(include_bytes!("corpus/accept.json").to_vec());
    let corpus: Vec<&[u8]> = corpus.iter().map(Vec::as_slice).collect();
    crate::common::assert_mutations(2, &corpus, |bytes| {
        let Ok(text) = std::str::from_utf8(bytes) else {
            return;
        };
        assert_eq!(
            mcp_jack::stream::accepts_s1(&[text]),
            oracle_values(&[text])
        );
        let _ = mcp_jack::stream::parse_jack_accept(&[text]);
    });
    for (values, expected) in [
        (&["S1"][..], false),
        (&["s1 "][..], false),
        (&["s1,"][..], false),
        (&["s1\t"][..], false),
        (&["s1"][..], true),
        (&["s1, s2"][..], true),
        (&["s2", "s1"][..], true),
        (&["s1", "s2"][..], true),
        (&["s2", "v1"][..], false),
        (&["s2", "v1", "s3"][..], false),
    ] {
        assert_eq!(mcp_jack::stream::accepts_s1(values), expected, "{values:?}");
        assert_eq!(oracle_values(values), expected, "oracle {values:?}");
    }
}
