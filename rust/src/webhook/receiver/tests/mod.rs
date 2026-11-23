//! Unit tests of the receiver building block (spec 06 R1.2, R1.10,
//! R3.16-R3.18).
//!
//! `body` covers the bounded collector of R1.2 and R3.6, `dispatch` the
//! acknowledgement state machine of R1.10 and the deduplication of R3.16.
//! Every delivery is signed with the same fixture secret and replayed on one
//! receiver, so state recorded by earlier calls stays observable
//! (spec 06 section 3).

mod body;
mod dispatch;

use crate::webhook::encoding::WebhookSecret;
use crate::webhook::receiver::config::ReceiverSecret;
use crate::webhook::receiver::{Receiver, ReceiverConfig};
use crate::webhook::signatures::{v1_sign, SignatureContent};

/// A secret the profile accepts: `whsec_` plus the canonical padded standard
/// base64 of 24 bytes (spec 06 R2.1).
pub(crate) const SECRET: &str = "whsec_+Zzlgla8N3pwerY+qnV84RsV/0dtERRT";

/// The subscription id every delivery of these tests is addressed to
/// (spec 06 R3.5).
pub(crate) const SUBSCRIPTION_ID: &str = "sub_a3f1c8e2b0d49f7e";

/// The receiver clock time of every delivery, equal to [`TIMESTAMP`] so the
/// freshness window of R3.9 holds trivially.
pub(crate) const NOW: i64 = 1_767_225_600;

/// The `webhook-timestamp` of every delivery (spec 06 R1.5).
pub(crate) const TIMESTAMP: &str = "1767225600";

/// The `webhook-id` of the first delivery (spec 06 R1.4).
pub(crate) const WEBHOOK_ID: &str = "msg_7Qk2mZ4rT9xV1bN6pL3sD8wY5cJ0hG2f";

/// A second `webhook-id`, distinct from [`WEBHOOK_ID`] (spec 06 R1.4).
pub(crate) const OTHER_WEBHOOK_ID: &str = "msg_1Ab2Cd3Ef4Gh5Ij6Kl7Mn8Op9Qr0St1U";

/// One well-formed event occurrence body: an event carries no `type` member,
/// so the four required members are all it has (spec 06 R1.3).
pub(crate) const EVENT_BODY: &[u8] =
    br#"{"eventId":"evt_1","name":"push","timestamp":"2026-01-01T00:00:00Z","data":{}}"#;

/// A nonce of the R5.3 shape, used by the verification envelope
/// (spec 06 R5.3).
pub(crate) const CHALLENGE: &str = "AAAAAAAAAAAAAAAAAAAAAA";

/// Returns the fixture secret, which every delivery is signed with
/// (spec 06 R2.1).
pub(crate) fn secret() -> WebhookSecret {
    WebhookSecret::parse(SECRET).expect("the fixture secret passes the profile")
}

/// Builds one receiver routing the fixture subscription id with a registered
/// secret (spec 06 R3.7, R3.8).
pub(crate) fn receiver() -> Receiver {
    Receiver::new(ReceiverConfig {
        secrets: vec![ReceiverSecret {
            secret: secret(),
            subscription_id: Some(SUBSCRIPTION_ID.to_owned()),
            callback_url: None,
        }],
        routed: vec![SUBSCRIPTION_ID.to_owned()],
        ..ReceiverConfig::default()
    })
    .expect("the default receiver configuration is valid")
}

/// Builds the four required headers of one delivery, signed with the fixture
/// secret (spec 06 R1.1, R2.2).
pub(crate) fn headers(webhook_id: &str, body: &[u8]) -> Vec<(String, String)> {
    let content = SignatureContent {
        webhook_id,
        timestamp: TIMESTAMP,
        body,
    };
    vec![
        ("Webhook-Id".to_owned(), webhook_id.to_owned()),
        ("Webhook-Timestamp".to_owned(), TIMESTAMP.to_owned()),
        ("Webhook-Signature".to_owned(), v1_sign(&secret(), &content)),
        (
            "X-MCP-Subscription-Id".to_owned(),
            SUBSCRIPTION_ID.to_owned(),
        ),
    ]
}

/// Builds one verification envelope body carrying [`CHALLENGE`]
/// (spec 06 R5.3, R5.6).
pub(crate) fn verification_body() -> Vec<u8> {
    format!(r#"{{"type":"verification","challenge":"{CHALLENGE}"}}"#).into_bytes()
}
