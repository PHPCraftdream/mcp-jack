//! Unit tests of the R7.3 rejection of a published JWK and of the R7.6
//! cross-check over the raw published JWKs (spec 06 R7.3, R7.6).
//!
//! The card publishes key material the R7.3 validator refuses, so the accepted
//! set is empty while the raw published set still carries the member: the R7.6
//! cross-check must see it and fail instead of comparing a silently narrowed
//! set.

use serde_json::json;

use crate::webhook::card::crosscheck::cross_check_webhook_key_jwks;
use crate::webhook::card::tests::{
    card_body, card_key, jwk, jwk_with_alg, response, source, ScriptedTransport, NOW,
};
use crate::webhook::codes;

/// A published JWK carrying `alg: "RS256"` is rejected as `alg` but stays in
/// `published`, and the R7.6 cross-check over that set is a
/// `webhook_key_mismatch` for a tool result that publishes the same key
/// without the invalid member (spec 06 R7.3, R7.6).
#[test]
fn a_published_jwk_with_an_invalid_alg_is_rejected_and_fails_the_cross_check() {
    let key = card_key("card key with alg");
    let published = vec![jwk_with_alg(&key, "RS256")];
    let transport = ScriptedTransport::new(vec![response(card_body(&published))]);
    let source = source(&transport);

    let snapshot = source.current(NOW);
    assert!(
        snapshot.accepted.is_empty(),
        "the R7.3 validator accepted an RS256 key"
    );
    assert_eq!(snapshot.rejected.len(), 1);
    assert_eq!(snapshot.rejected[0].kid.as_deref(), Some(key.kid.as_str()));
    assert_eq!(snapshot.rejected[0].reason, "alg");
    assert_eq!(snapshot.published, published);

    let tool_result = json!({
        "webhook_key": {
            "signing_keys": { "keys": [jwk(&key)] },
        },
    });
    let error = match cross_check_webhook_key_jwks(&snapshot.published, Some(&tool_result), true) {
        Ok(()) => panic!("the cross-check accepted a published RS256 key"),
        Err(error) => error,
    };
    assert_eq!(error.http_status, 401);
    assert_eq!(error.code, codes::WEBHOOK_KEY_MISMATCH);
}
