//! Server Card key discovery of spec 06 section 7 (R7.1-R7.6): the R7.3 JWK
//! validator and accepted key record, the R7.1-R7.2-R7.5 card discovery and
//! fetch decision, and the optional R7.6 `jack.server.webhook_key`
//! cross-check.
//!
//! Everything here is pure: the caller performs the fetch and holds the
//! Jack-authenticated channel of R7.6, and gets a decision that carries only
//! fixed-literal codes and reasons, never a card byte.

pub mod crosscheck;
pub mod discovery;
pub mod jwk;

pub use crosscheck::cross_check_webhook_key;
pub use discovery::{
    card_cache_ttl, default_card_url, fetch_decision, parse_cidr_list, same_origin, select_remote,
    webhook_info, AcceptedCidr, CardFetchInput, CidrList, FetchedCard, RejectedCidr, WebhookInfo,
    MAX_CARD_BYTES, MAX_CARD_TTL_SECONDS,
};
pub use jwk::{
    accept_jwk_set, card_key_for_kid, validate_jwk, AcceptedKeys, KeyRejection, WebhookKeyRecord,
    EVENTS_EXTENSION,
};
