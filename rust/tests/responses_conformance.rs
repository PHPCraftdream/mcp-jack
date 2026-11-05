mod common;

use common::fixtures::*;

#[test]
fn response_vectors() {
    let v = load_response_vectors().expect("load response-vectors.json");
    assert!(!v.cases.is_empty(), "response-vectors.json has no cases");
    for c in &v.cases {
        // Header names are case-insensitive per the runner contract.
        let values: Vec<&str> = c
            .response
            .headers
            .iter()
            .filter(|h| h.name.eq_ignore_ascii_case("Jack-Auth"))
            .map(|h| h.value.as_str())
            .collect();
        let key_vec =
            mcp_jack::encoding::decode_b64url_fixed(c.state.pinned_server_public_key.as_str(), 32)
                .unwrap_or_else(|e| panic!("case {}: bad pinned key b64u: {:?}", c.id, e));
        let key: [u8; 32] = key_vec
            .try_into()
            .unwrap_or_else(|_| panic!("case {}: pinned key is not 32 bytes", c.id));
        let body = mcp_jack::encoding::decode_b64url(c.response.body_b64u.as_str())
            .unwrap_or_else(|e| panic!("case {}: bad body b64u: {:?}", c.id, e));
        let result = mcp_jack::signing::verify_response(
            &key,
            c.response.status,
            &values,
            c.state.request_sig.as_str(),
            &body,
            c.state.now,
            c.state.window_seconds,
        );
        match c.expect.result.as_str() {
            "accept" => assert!(
                result.is_ok(),
                "case {}: expected accept, got {:?}",
                c.id,
                result
            ),
            "reject" => match result {
                Ok(()) => panic!(
                    "case {}: expected reject with code {:?}, got Ok",
                    c.id, c.expect.code
                ),
                Err(err) => assert_eq!(
                    err.code, c.expect.code,
                    "case {}: reject code mismatch",
                    c.id
                ),
            },
            other => panic!("case {}: unknown expect.result {:?}", c.id, other),
        }
    }
}

#[test]
fn response_default_window() {
    let v = load_response_vectors().expect("load response-vectors.json");
    let c = v
        .cases
        .iter()
        .find(|c| c.id == "res-accept")
        .expect("case res-accept not found in response-vectors.json");
    let values: Vec<&str> = c
        .response
        .headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("Jack-Auth"))
        .map(|h| h.value.as_str())
        .collect();
    let key_vec =
        mcp_jack::encoding::decode_b64url_fixed(c.state.pinned_server_public_key.as_str(), 32)
            .expect("decode pinned key");
    let key: [u8; 32] = key_vec.try_into().expect("pinned key is 32 bytes");
    let body =
        mcp_jack::encoding::decode_b64url(c.response.body_b64u.as_str()).expect("decode body");

    // Window 0 means the default 30 s inside verify_response (Go: window <= 0).
    assert!(
        mcp_jack::signing::verify_response(
            &key,
            c.response.status,
            &values,
            c.state.request_sig.as_str(),
            &body,
            c.state.now + 30,
            0,
        )
        .is_ok(),
        "case res-accept: now+30 must be within the default window"
    );
    let late = mcp_jack::signing::verify_response(
        &key,
        c.response.status,
        &values,
        c.state.request_sig.as_str(),
        &body,
        c.state.now + 31,
        0,
    )
    .expect_err("case res-accept: now+31 must fall outside the default window");
    assert_eq!(
        late.code,
        mcp_jack::error::codes::TIMESTAMP_OUT_OF_WINDOW,
        "case res-accept: expected timestamp_out_of_window"
    );
}
