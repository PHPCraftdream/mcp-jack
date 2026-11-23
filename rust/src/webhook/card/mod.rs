//! Server Card key discovery of spec 06 section 7 (R7.1-R7.6): the R7.3 JWK
//! validator and accepted key record, the R7.1-R7.2-R7.5 card discovery and
//! fetch decision, the R7.2-R7.4 operational key source, and the optional R7.6
//! `jack.server.webhook_key` cross-check.
//!
//! The decisions are pure: the caller — or the injected
//! [`source::CardTransport`] — performs the fetch and holds the
//! Jack-authenticated channel of R7.6, and every decision carries only
//! fixed-literal codes and reasons, never a card byte.

pub mod crosscheck;
pub mod discovery;
pub mod jwk;
pub mod keys;
pub mod source;

#[cfg(test)]
mod tests;

pub use crosscheck::{cross_check_webhook_key, cross_check_webhook_key_jwks};
pub use discovery::{
    card_cache_ttl, default_card_url, fetch_decision, parse_cidr_list, published_jwks, same_origin,
    select_remote, webhook_info, AcceptedCidr, CardFetchInput, CidrList, FetchedCard, RejectedCidr,
    WebhookInfo, MAX_CARD_BYTES, MAX_CARD_TTL_SECONDS,
};
pub use jwk::{
    accept_jwk_set, card_key_for_kid, validate_jwk, AcceptedKeys, KeyRejection, WebhookKeyRecord,
    EVENTS_EXTENSION,
};
pub use keys::{KeySnapshot, KeySource, StaticKeys};
pub use source::{CardResponse, CardSource, CardTransport, CARD_FETCH_SECONDS};
