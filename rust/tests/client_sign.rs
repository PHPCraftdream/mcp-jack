//! Port of Go client/sign_test.go: the client header builder reproduces every
//! derivable fixture accept case byte for byte (Ed25519 is deterministic, so
//! fixed inputs fix the bytes), the signing string matches the fixture debug
//! lines, and the suite covers tamper detection and reject-case
//! non-reproducibility. The signing string binds the HEADER's own ts and
//! nonce, so reproduction signs with the parsed header ts — the verifier's
//! state.now is not part of the signing string and boundary fixtures
//! deliberately sign at now ± window.

mod common;

use common::fixtures::*;
use common::harness::*;

use mcp_jack::auth_header::{parse_request_auth, RequestAuth};
use mcp_jack::client::auth::sign_request;
use mcp_jack::client::signer::{InMemorySigner, Signer};
use mcp_jack::encoding::{decode_b64url, decode_b64url_fixed};
use mcp_jack::signing::request_signing_string;

/// One derivable accept case: fixture request plus the parsed header, signer,
/// decoded body and nonce (Go: matchedCase).
struct MatchedCase {
    case: RequestCase,
    auth: RequestAuth,
    signer: InMemorySigner,
    body: Vec<u8>,
    nonce: Vec<u8>,
}

/// The Jack-Auth header of a fixture request, if it carries one (Go:
/// fixtureHeader).
fn fixture_header(req: &FixtureRequest) -> Option<&str> {
    req.headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("Jack-Auth"))
        .map(|h| h.value.as_str())
}

/// Accept cases with a parseable Jack-Auth header whose kid is in keys.json
/// and whose nonce decodes to 16 bytes (Go: matchedAcceptCases).
fn matched_accept_cases() -> Vec<MatchedCase> {
    let vecs = load_request_vectors().expect("load request-vectors.json");
    let keys = fixture_keys();
    let mut out = Vec::new();
    for tc in &vecs.cases {
        if tc.expect.result != "accept" {
            continue;
        }
        let Some(hv) = fixture_header(&tc.request) else {
            continue;
        };
        let auth = parse_request_auth(&[hv])
            .unwrap_or_else(|e| panic!("{}: fixture header must parse: {e}", tc.id));
        if !keys.contains_key(&auth.kid) {
            continue;
        }
        let nonce = decode_b64url_fixed(&auth.nonce, 16)
            .unwrap_or_else(|e| panic!("{}: nonce: {e:?}", tc.id));
        let body = decode_body(&tc.id, &tc.request.body_b64u);
        let signer = signer_by_kid(&auth.kid);
        out.push(MatchedCase {
            case: tc.clone(),
            auth,
            signer,
            body,
            nonce,
        });
    }
    assert!(!out.is_empty(), "no derivable accept cases matched");
    out
}

/// Reproduces a fixture case's header via sign_request with the case's
/// pinned inputs (Go's SignRequest call in each test).
fn reproduce(m: &MatchedCase) -> mcp_jack::client::auth::SignedRequest {
    sign_request(
        &m.signer,
        &m.case.state.aud,
        &m.case.request.method,
        &m.case.request.target,
        &m.body,
        &m.nonce,
        // The signing string binds the header's own ts (and nonce): boundary
        // fixtures sign at ts = now ± window, so state.now is NOT the signing ts.
        m.auth.ts,
    )
    .unwrap_or_else(|e| panic!("{}: sign_request: {e}", m.case.id))
}

/// Go: TestSignRequestReproducesFixtureHeaders.
#[test]
fn sign_request_reproduces_fixture_headers() {
    for m in matched_accept_cases() {
        let signed = reproduce(&m);
        let want = fixture_header(&m.case.request).expect("matched case has a header");
        assert_eq!(
            signed.header_value, want,
            "case {}: header mismatch:\n got: {}\nwant: {}",
            m.case.id, signed.header_value, want
        );
    }
}

/// Go: TestSigningStringMatchesFixtureDebug.
#[test]
fn signing_string_matches_fixture_debug() {
    for m in matched_accept_cases() {
        let signed = reproduce(&m);
        let want = m.case.debug.signing_string_lines.join("\n");
        assert_eq!(
            signed.signing_string, want,
            "case {}: signing string mismatch:\n got: {:?}\nwant: {:?}",
            m.case.id, signed.signing_string, want
        );
    }
}

/// Go: TestSignRequestTamperDetection — fixture signature validity, body
/// tampering sensitivity, and reject-case non-reproducibility.
#[test]
fn sign_request_tamper_detection() {
    let matched = matched_accept_cases();

    // (a) The fixture signature must verify over the recomputed signing
    // string (= sign_request's signing string; the same call fixes the bytes).
    for m in &matched {
        let signed = reproduce(m);
        let fixture_sig = decode_b64url_fixed(&m.auth.sig, 64)
            .unwrap_or_else(|e| panic!("{}: decode sig: {e:?}", m.case.id));
        assert!(
            mcp_jack::ed25519::verify(
                &m.signer.public_key(),
                signed.signing_string.as_bytes(),
                &fixture_sig
            ),
            "{}: fixture sig does not verify over recomputed string",
            m.case.id
        );
    }

    // (b) Tampering one body byte must change the produced header. Go skips
    // empty bodies; every fixture accept body is non-empty, but mirror the
    // guard anyway.
    let m = matched
        .iter()
        .find(|m| !m.body.is_empty())
        .expect("a non-empty accept body for the tamper case");
    let mut body2 = m.body.clone();
    let last = body2.len() - 1;
    body2[last] ^= 0x01;
    let header = reproduce(m).header_value;
    let header2 = sign_request(
        &m.signer,
        &m.case.state.aud,
        &m.case.request.method,
        &m.case.request.target,
        &body2,
        &m.nonce,
        m.auth.ts,
    )
    .unwrap_or_else(|e| panic!("{}: sign_request tampered: {e}", m.case.id))
    .header_value;
    assert_ne!(
        header2, header,
        "{}: tampered body produced identical header",
        m.case.id
    );

    // (c) Signature-tamper reject cases must NOT reproduce. Selection rule,
    // traced per case in spec/tools/gen-fixtures.mjs (buildRequest +
    // REQUEST_CASES): the case is selected only if its expect.code is
    // bad_signature AND its fixture signature fails verification over the
    // signing string recomputed from the SENT header fields (kid/ts/nonce) and
    // the SENT body with the fixture aud. Cases rejected for grammar, window,
    // replay, key state or policy may carry a perfectly reproducible header —
    // their rejection is server-side state or grammar, not bytes — so they are
    // skipped. Traced selections (gen-fixtures.mjs REQUEST_CASES lines):
    // sig-tampered-body (signs svc.status, sends svc.restart),
    // sig-tampered-target (signs /mcp, sends /mcp?admin=1),
    // sig-tampered-method (signs POST, sends GET),
    // sig-wrong-aud (signs AUD2, verifier pins AUD),
    // sig-wrong-key (signed by bob, header kid of alice),
    // sig-flipped-bit (one bit of the signature flipped),
    // sig-noncanonical-s (S replaced by S+L, strict verify rejects),
    // sig-swapped-nonce (header nonce differs from signed nonce),
    // sig-swapped-ts (header ts differs from signed ts),
    // replay-not-recorded-on-bad-sig (flipped signature).
    let vecs = load_request_vectors().expect("load request-vectors.json");
    let keys = fixture_keys();
    let mut tampered: Vec<String> = Vec::new();
    for tc in &vecs.cases {
        if tc.expect.result != "reject" || tc.expect.code != "bad_signature" {
            continue;
        }
        let Some(hv) = fixture_header(&tc.request) else {
            continue;
        };
        let Ok(auth) = parse_request_auth(&[hv]) else {
            continue;
        };
        let Some(pub_key) = keys.get(&auth.kid) else {
            continue;
        };
        let Ok(nonce) = decode_b64url_fixed(&auth.nonce, 16) else {
            continue;
        };
        let Ok(body) = decode_b64url(&tc.request.body_b64u) else {
            continue;
        };
        let Ok(fixture_sig) = decode_b64url_fixed(&auth.sig, 64) else {
            continue;
        };
        // Mechanism probe: recompute from the SENT fields; the tamper family
        // is exactly the set whose fixture signature does not verify over it.
        let recomputed = request_signing_string(
            &tc.request.method,
            &tc.request.target,
            &tc.state.aud,
            &auth.kid,
            auth.ts,
            &auth.nonce,
            &body,
        );
        if mcp_jack::ed25519::verify(pub_key, recomputed.as_bytes(), &fixture_sig) {
            continue;
        }
        let signer = signer_by_kid(&auth.kid);
        let signed = sign_request(
            &signer,
            &tc.state.aud,
            &tc.request.method,
            &tc.request.target,
            &body,
            &nonce,
            auth.ts,
        )
        .unwrap_or_else(|e| panic!("{}: sign_request: {e}", tc.id));
        assert_ne!(
            signed.header_value, hv,
            "{}: tampered header unexpectedly reproduced",
            tc.id
        );
        tampered.push(tc.id.clone());
    }
    // Every traced tamper case must be selected by the mechanism probe.
    for id in [
        "sig-tampered-body",
        "sig-tampered-target",
        "sig-tampered-method",
        "sig-wrong-aud",
        "sig-wrong-key",
        "sig-flipped-bit",
        "sig-noncanonical-s",
        "sig-swapped-nonce",
        "sig-swapped-ts",
        "replay-not-recorded-on-bad-sig",
    ] {
        assert!(
            tampered.iter().any(|s| s == id),
            "tamper case {id} was not selected by the mechanism probe"
        );
    }
}
