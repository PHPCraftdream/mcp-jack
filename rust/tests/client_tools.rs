//! Port of Go client/tools_test.go (six tests): the typed jack.* tool calls
//! reproduce the admin-vectors fixtures byte for byte and decode their
//! structuredContent results; error paths map to Http/Tool errors.

mod common;

use std::sync::{Arc, Mutex};

use common::fixtures::*;
use common::harness::*;

use mcp_jack::auth_header::{format_request_auth, parse_request_auth};
use mcp_jack::client::error::ClientError;
use mcp_jack::client::rpc::{Client, Config};
use mcp_jack::client::signer::{InMemorySigner, Signer};
use mcp_jack::client::tools::EnrollResult;
use mcp_jack::client::transport::Transport;
use mcp_jack::encoding::{decode_b64url_fixed, encode_b64url};
use serde_json::json;

/// One captured incoming request (Go's gotHeader/gotMethod/gotTarget/gotBody);
/// method and target are the values the fake transport actually observed.
#[derive(Clone)]
struct CapturedRequest {
    header: String,
    method: String,
    target: String,
    body: Vec<u8>,
}

type Captured = Arc<Mutex<Option<CapturedRequest>>>;

/// The Jack-Auth header of a fixture step's request (Go: fixtureHeaderValue).
fn fixture_header_value(step: &Step) -> String {
    step.request
        .headers
        .iter()
        .find(|h| h.name == "Jack-Auth")
        .map(|h| h.value.clone())
        .unwrap_or_else(|| panic!("fixture request has no \"Jack-Auth\" header"))
}

/// The base64url nonce of a fixture Jack-Auth header (Go: fixtureNonce).
fn fixture_nonce(header_value: &str) -> String {
    parse_request_auth(&[header_value])
        .unwrap_or_else(|e| panic!("fixture header {header_value:?} must parse: {e}"))
        .nonce
}

/// The exact request body bytes of a fixture step (Go: fixtureBody).
fn fixture_body(step: &Step) -> Vec<u8> {
    decode_body("step", &step.request.body_b64u)
}

/// A Client pinned to srv with the given signer and fixture nonce, clocked at
/// fixtureNow (Go: newFixtureClient).
fn new_fixture_client(srv: &Arc<TestServer>, signer: InMemorySigner, nonce_b64u: &str) -> Client {
    let transport: Arc<dyn Transport> = Arc::clone(srv) as Arc<dyn Transport>;
    Client::new(Config {
        base_url: TEST_URL.to_string(),
        aud: FIXTURE_AUD.to_string(),
        signer: Arc::new(signer),
        server_key: srv.pub_key,
        transport,
        now: Some(fixed_clock(FIXTURE_NOW)),
        // The admin-list test issues two calls, so the fixture nonce is
        // queued twice (Go queues it once, which exhausts its queue). The
        // fake server does no replay detection, so reuse is harmless here.
        nonce: Some(queued_nonce(&[nonce_b64u, nonce_b64u])),
        window_seconds: 30,
    })
    .expect("valid fixture client")
}

/// The first step of the named admin case (Go: adminCase + steps[0]).
fn admin_case_step(case_id: &str) -> Step {
    let vecs = load_admin_vectors().expect("load admin-vectors.json");
    let case = vecs
        .cases
        .iter()
        .find(|c| c.id == case_id)
        .unwrap_or_else(|| panic!("admin vectors have no case {case_id:?}"));
    assert!(!case.steps.is_empty(), "case {case_id} has no steps");
    case.steps[0].clone()
}

/// Installs a handler that captures the request and answers with a signed
/// JSON-RPC result wrapping `structured` (Go's srv.Handle bodies).
fn install_capturing_handler(
    srv: &Arc<TestServer>,
    structured: serde_json::Value,
    captured: Captured,
) {
    srv.set_handler(Box::new(move |srv, method, target, auth, body| {
        *captured.lock().expect("mutex") = Some(CapturedRequest {
            header: format_request_auth(auth),
            method: method.to_string(),
            target: target.to_string(),
            body: body.to_vec(),
        });
        srv.write_signed_json(auth, 200, &rpc_result_body(&structured))
    }));
}

/// Compares the captured request against the fixture: header byte-for-byte,
/// method/target exactly as observed by the fake, body bytes identical (Go:
/// assertFixtureRequest; the decoded-DeepEqual check is subsumed by the exact
/// byte comparison).
fn assert_fixture_request(step: &Step, got: &CapturedRequest) {
    assert_eq!(got.header, fixture_header_value(step), "Jack-Auth header");
    assert_eq!(got.method, step.request.method, "method");
    assert_eq!(got.target, step.request.target, "target");
    assert_eq!(
        got.body,
        fixture_body(step),
        "body bytes differ from fixture bytes"
    );
}

/// Go: TestEnrollMatchesFixture.
#[test]
fn enroll_matches_fixture() {
    let step = admin_case_step("enroll-ok");
    let structured = step
        .expect
        .structured
        .clone()
        .expect("enroll-ok expects structured");
    let srv = TestServer::new();
    let captured: Captured = Arc::new(Mutex::new(None));
    install_capturing_handler(&srv, structured, Arc::clone(&captured));

    let header_value = fixture_header_value(&step);
    let newbie = signer_by_name("newbie");
    let client = new_fixture_client(&srv, newbie.clone(), &fixture_nonce(&header_value));

    let res = client
        .enroll(
            "NTpoPAFYwVkAdj8kps_x_Q_pgjkaWP-pvdbaV0eQau4",
            "newbie",
            &newbie,
        )
        .expect("enroll");

    let got = captured.lock().expect("mutex").clone().expect("captured");
    assert_fixture_request(&step, &got);

    // The kid/name/kind/scopes oracle is keys.json + the fixture's
    // expect.structured (Go hardcodes the same values).
    assert_eq!(
        res,
        EnrollResult {
            kid: signer_by_name("newbie").kid().to_string(),
            name: "newbie".to_string(),
            kind: "human".to_string(),
            scopes: vec!["read".to_string()],
        }
    );
}

/// Go: TestRotateMatchesFixture.
#[test]
fn rotate_matches_fixture() {
    let step = admin_case_step("rotate-ok");
    let structured = step
        .expect
        .structured
        .clone()
        .expect("rotate-ok expects structured");
    let srv = TestServer::new();
    let captured: Captured = Arc::new(Mutex::new(None));
    install_capturing_handler(&srv, structured, Arc::clone(&captured));

    let header_value = fixture_header_value(&step);
    let alice = signer_by_name("alice");
    let newbie = signer_by_name("newbie");
    let client = new_fixture_client(&srv, alice.clone(), &fixture_nonce(&header_value));

    let res = client.rotate_key(&newbie).expect("rotate");

    let got = captured.lock().expect("mutex").clone().expect("captured");
    assert_fixture_request(&step, &got);

    // Independently re-derive the proof from the primitives (spec 03
    // section 3.1): the client must have signed exactly
    // rotate_proof_string(aud, old kid, new kid, fixtureNow).
    let wire: serde_json::Value =
        serde_json::from_slice(&got.body).expect("captured body decodes as json-rpc");
    let args = &wire["params"]["arguments"];
    assert_eq!(
        args["public_key"],
        json!(encode_b64url(&newbie.public_key())),
        "arguments[public_key] must be the newbie public key"
    );
    let proof = args["proof"]
        .as_str()
        .expect("arguments[proof] is a string");
    let proof_bytes = decode_b64url_fixed(proof, 64).expect("proof decodes to 64 bytes");
    let msg =
        mcp_jack::signing::rotate_proof_string(FIXTURE_AUD, alice.kid(), newbie.kid(), FIXTURE_NOW);
    assert!(
        mcp_jack::ed25519::verify(&newbie.public_key(), msg.as_bytes(), &proof_bytes),
        "rotate proof does not verify under the newbie key over {msg:?}"
    );
    assert_eq!(res.kid, newbie.kid(), "KidResult.kid");
}

/// Go: TestWhoAmIDecodesResult.
#[test]
fn whoami_decodes_result() {
    let srv = TestServer::new();
    let newbie_kid = signer_by_name("newbie").kid().to_string();
    let structured = json!({
        "kid": newbie_kid,
        "name": "newbie",
        "kind": "human",
        "scopes": ["read"],
        "not_before": null,
        "not_after": null,
    });
    srv.set_handler(Box::new(move |srv, _method, _target, auth, _body| {
        srv.write_signed_json(auth, 200, &rpc_result_body(&structured))
    }));
    let client = new_fixture_client(&srv, signer_by_name("newbie"), "assryd677-uYrqD4v-7HYw");
    let res = client.whoami().expect("whoami");
    assert_eq!(res.kid, newbie_kid);
    assert_eq!(res.name, "newbie");
    assert_eq!(res.kind, "human");
    assert_eq!(res.scopes, vec!["read".to_string()]);
    assert_eq!(res.not_before, None);
    assert_eq!(res.not_after, None);
}

/// Go: TestAdminListDecodesWrappers.
#[test]
fn admin_list_decodes_wrappers() {
    let srv = TestServer::new();
    srv.set_handler(Box::new(|srv, _method, _target, auth, body| {
        let users = json!({
            "users": [{
                "kid": "k1",
                "public_key": "p1",
                "name": "alice",
                "kind": "human",
                "scopes": ["read"],
                "not_before": null,
                "not_after": 1750000000,
            }]
        });
        let invites = json!({
            "invites": [{
                "invite_id": "iv1",
                "scopes": ["read"],
                "kind": "human",
                "created_by": "k1",
                "created_at": 1767225500,
                "expires_at": 1767228600,
            }]
        });
        let text = String::from_utf8_lossy(body);
        let structured = if text.contains(r#""jack.admin.user.list""#) {
            users
        } else {
            invites
        };
        srv.write_signed_json(auth, 200, &rpc_result_body(&structured))
    }));
    let client = new_fixture_client(&srv, signer_by_name("alice"), "assryd677-uYrqD4v-7HYw");

    let users = client.admin_user_list().expect("admin_user_list");
    assert_eq!(1, users.len());
    assert_eq!("human", users[0].kind);
    assert_eq!(Some(1750000000), users[0].not_after);

    let invites = client.admin_invite_list().expect("admin_invite_list");
    assert_eq!(1, invites.len());
    assert_eq!("iv1", invites[0].invite_id);
    assert_eq!(1767228600, invites[0].expires_at);
}

/// Go: TestToolCallHTTPError.
#[test]
fn tool_call_http_error() {
    let srv = TestServer::new();
    srv.set_handler(Box::new(|srv, _method, _target, auth, _body| {
        srv.write_signed_json(
            auth,
            403,
            br#"{"error":{"code":"insufficient_scope","message":"no"}}"#,
        )
    }));
    let client = new_fixture_client(&srv, signer_by_name("alice"), "assryd677-uYrqD4v-7HYw");
    let err = client
        .admin_user_get("k1")
        .expect_err("403 must surface as ClientError::Http");
    match err {
        ClientError::Http(h) => {
            assert_eq!(h.status, 403);
            assert_eq!(h.code, "insufficient_scope");
        }
        other => panic!("expected ClientError::Http, got {other:?}"),
    }
}

/// Go: TestToolCallToolError.
#[test]
fn tool_call_tool_error() {
    let srv = TestServer::new();
    srv.set_handler(Box::new(|srv, _method, _target, auth, _body| {
        // Go's exact raw body, NOT rpc_result_body: isError true short-circuits.
        srv.write_signed_json(
            auth,
            200,
            br#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"boom"}],"isError":true}}"#,
        )
    }));
    let client = new_fixture_client(&srv, signer_by_name("alice"), "assryd677-uYrqD4v-7HYw");
    let err = client
        .whoami()
        .expect_err("isError true must surface as ClientError::Tool");
    match err {
        ClientError::Tool(t) => assert_eq!(t.message, "boom"),
        other => panic!("expected ClientError::Tool, got {other:?}"),
    }
}
