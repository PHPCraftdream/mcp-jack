//! The fixed verification route order of spec 06 section 5 (R5.1, R5.2):
//! cache, allowlist, out-of-band hook, well-known document, challenge
//! handshake, and the delivery gate that a verification message passes
//! before any event is delivered.
//!
//! Everything here is pure and mirrors
//! `spec/tools/modern/webhooks/ref/verification.mjs` exactly: each earlier
//! route has already been evaluated by the caller, so this module only
//! applies the order and reports the first success.

use crate::webhook::verification::nonce::EchoVerdict;
use crate::webhook::MessageKind;

/// The successful route of one verification attempt (spec 06 R5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationRoute {
    /// A prior success for the same `(principal, canonical_url)`
    /// (spec 06 R5.2).
    Cache,
    /// An operator allowlist entry matches (spec 06 R5.7).
    Allowlist,
    /// The application's out-of-band hook answered true (spec 06 R5.8).
    OutOfBand,
    /// The origin publishes a covered path prefix (spec 06 R5.9, R5.10).
    WellKnown,
    /// The endpoint echoed a single-use nonce (spec 06 R5.3, R5.4).
    Challenge,
}

impl VerificationRoute {
    /// Returns the wire spelling of the route: `cache`, `allowlist`,
    /// `out_of_band`, `well_known` or `challenge` (spec 06 R5.2).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cache => "cache",
            Self::Allowlist => "allowlist",
            Self::OutOfBand => "out_of_band",
            Self::WellKnown => "well_known",
            Self::Challenge => "challenge",
        }
    }
}

/// The inputs of one route decision, each already evaluated by the caller
/// (spec 06 R5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteInput<'a> {
    /// True when the cache holds the pair (spec 06 R5.2).
    pub cache: bool,
    /// True when an allowlist entry matches (spec 06 R5.7).
    pub allowlist_matched: bool,
    /// The out-of-band hook result, `None` when no hook is installed
    /// (spec 06 R5.8).
    pub hook: Option<bool>,
    /// True when a well-known document covers the path; the fetch verdict is
    /// a precondition (spec 06 R5.9, R5.10).
    pub document_covers: Option<bool>,
    /// The challenge verdict, `None` when no challenge was attempted
    /// (spec 06 R5.3, R5.4).
    pub challenge: Option<&'a EchoVerdict>,
}

/// The outcome of one route decision (spec 06 R5.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteVerdict {
    /// True when one route verified the pair (spec 06 R5.2).
    pub verified: bool,
    /// The successful route, `None` when no route verified
    /// (spec 06 R5.2).
    pub route: Option<VerificationRoute>,
    /// The fixed-literal failure reason: the challenge reason when a
    /// challenge was attempted, else `no_route` (spec 06 R5.2).
    pub reason: Option<String>,
}

/// Applies the fixed route order and reports the first success
/// (spec 06 R5.2).
///
/// The order is cache, allowlist, out-of-band hook, well-known document,
/// challenge handshake; a `None` hook is not installed and a `None` document
/// verdict is not a cover. On failure the reason is the challenge reason
/// when a challenge was attempted, else `no_route` (spec 06 R5.2).
pub fn verification_route(input: &RouteInput<'_>) -> RouteVerdict {
    let hit = |route| RouteVerdict {
        verified: true,
        route: Some(route),
        reason: None,
    };
    if input.cache {
        return hit(VerificationRoute::Cache);
    }
    if input.allowlist_matched {
        return hit(VerificationRoute::Allowlist);
    }
    if input.hook == Some(true) {
        return hit(VerificationRoute::OutOfBand);
    }
    if input.document_covers == Some(true) {
        return hit(VerificationRoute::WellKnown);
    }
    if let Some(challenge) = input.challenge {
        if challenge.ok {
            return hit(VerificationRoute::Challenge);
        }
    }
    RouteVerdict {
        verified: false,
        route: None,
        reason: Some(match input.challenge {
            Some(challenge) => challenge
                .reason
                .clone()
                .unwrap_or_else(|| "no_route".to_string()),
            None => "no_route".to_string(),
        }),
    }
}

/// What a sender does with one message after the pair's verification status
/// is known (spec 06 R5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateAction {
    /// Deliver the message (spec 06 R5.1).
    Deliver,
    /// Answer the verification envelope in place with the nonce
    /// (spec 06 R5.1, R5.4).
    SendChallenge,
    /// Refuse to deliver (spec 06 R5.1).
    Refuse,
}

impl GateAction {
    /// Returns the wire spelling of the action: `deliver`, `send-challenge`
    /// or `refuse` (spec 06 R5.1).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deliver => "deliver",
            Self::SendChallenge => "send-challenge",
            Self::Refuse => "refuse",
        }
    }
}

/// Returns what a sender does with a message of `kind` for a pair whose
/// verification status is `verified` (spec 06 R5.1).
///
/// A verification message is answered in place whether or not the pair is
/// verified, because that answer is the challenge and not an event delivery;
/// an unverified event, `gap` or `terminated` is refused, and a verified one
/// is delivered (spec 06 R5.1).
pub fn gate(kind: MessageKind, verified: bool) -> GateAction {
    if kind == MessageKind::Verification {
        return GateAction::SendChallenge;
    }
    if verified {
        GateAction::Deliver
    } else {
        GateAction::Refuse
    }
}
