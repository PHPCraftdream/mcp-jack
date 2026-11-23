//! Unit tests of the operational Server Card key source
//! (spec 06 R7.1-R7.4).
//!
//! Every test drives one `CardSource` over the scripted transport of the
//! parent module, so the observable facts are the fetch count, the accepted
//! `kid`s, the raw published JWKs and the rejection code.

use serde_json::json;

use crate::webhook::card::keys::KeySnapshot;
use crate::webhook::card::tests::{
    cached_response, card_body, card_key, jwk, response, source, ScriptedTransport, NOW,
};
use crate::webhook::codes;

/// Returns the accepted `kid`s of `snapshot`, in source order
/// (spec 06 R7.3).
fn accepted_kids(snapshot: &KeySnapshot) -> Vec<&str> {
    snapshot
        .accepted
        .iter()
        .map(|key| key.kid.as_str())
        .collect()
}

/// One valid card is fetched once and reports both its accepted keys and the
/// raw JWKs it published (spec 06 R7.1-R7.3).
#[test]
fn a_valid_card_is_fetched_once_and_reports_its_keys_and_published_jwks() {
    let first = card_key("card key one");
    let second = card_key("card key two");
    let published = vec![jwk(&first), jwk(&second)];
    let transport = ScriptedTransport::new(vec![response(card_body(&published))]);
    let source = source(&transport);

    let snapshot = source.current(NOW);
    assert_eq!(
        transport.calls(),
        1,
        "one read performed more than one fetch"
    );
    assert_eq!(
        accepted_kids(&snapshot),
        vec![first.kid.as_str(), second.kid.as_str()]
    );
    assert!(snapshot.rejected.is_empty(), "a valid card rejected a key");
    assert_eq!(snapshot.published, published);
}

/// The cache honours the `max-age` of the response: a read inside the lifetime
/// reuses the snapshot and a read at the lifetime fetches again
/// (spec 06 R7.2).
#[test]
fn the_cache_honours_the_max_age_of_the_response() {
    let key = card_key("cache key");
    let transport =
        ScriptedTransport::new(vec![cached_response(card_body(&[jwk(&key)]), "max-age=60")]);
    let source = source(&transport);

    let first = source.current(NOW);
    assert_eq!(transport.calls(), 1);

    let inside = source.current(NOW + 59);
    assert_eq!(transport.calls(), 1, "a read inside the max-age refetched");
    assert_eq!(inside, first);

    let at_lifetime = source.current(NOW + 60);
    assert_eq!(
        transport.calls(),
        2,
        "a read at the max-age reused the cache"
    );
    assert_eq!(at_lifetime, first);
}

/// Rotation of R7.4: while the card publishes the old and the new key both are
/// accepted, and once it drops the old key only the new one is
/// (spec 06 R7.4).
#[test]
fn rotation_accepts_both_keys_until_the_old_one_is_dropped() {
    let old = card_key("rotation old");
    let new = card_key("rotation new");
    let transport = ScriptedTransport::new(vec![
        response(card_body(&[jwk(&old), jwk(&new)])),
        response(card_body(&[jwk(&new)])),
    ]);
    let source = source(&transport);

    let both = source
        .refresh(NOW)
        .expect("the overlapping card is accepted");
    assert_eq!(
        accepted_kids(&both),
        vec![old.kid.as_str(), new.kid.as_str()]
    );

    let only_new = source
        .refresh(NOW + 1)
        .expect("the rotated card is accepted");
    assert_eq!(transport.calls(), 2);
    assert_eq!(accepted_kids(&only_new), vec![new.kid.as_str()]);

    let cached = source.current(NOW + 2);
    assert_eq!(
        transport.calls(),
        2,
        "the fresh rotated snapshot was refetched"
    );
    assert_eq!(accepted_kids(&cached), vec![new.kid.as_str()]);
}

/// A response flagged as overflowing is `too_large` even when its truncated
/// prefix parses as a card, and the previously cached set stays in place
/// (spec 06 R7.2).
#[test]
fn an_overflowing_response_is_too_large_and_keeps_the_cached_set() {
    let key = card_key("cached key");
    let body = card_body(&[jwk(&key)]);
    let mut overflowing_body = body.clone();
    overflowing_body.extend_from_slice(b"{}");
    let mut overflowing = response(overflowing_body);
    overflowing.overflow = true;

    let transport = ScriptedTransport::new(vec![response(body), overflowing]);
    let source = source(&transport);

    let good = source.current(NOW);
    assert_eq!(accepted_kids(&good), vec![key.kid.as_str()]);

    let error = source
        .refresh(NOW)
        .expect_err("an overflowing body was accepted");
    assert_eq!(error.http_status, 0);
    assert_eq!(error.code, codes::TOO_LARGE);
    assert_eq!(transport.calls(), 2);

    let kept = source.current(NOW + 1);
    assert_eq!(kept, good, "the failed refresh emptied the cached set");
    assert_eq!(transport.calls(), 2);
}

/// A configured card url of another origin is refused before any fetch
/// (spec 06 R7.2).
#[test]
fn a_configured_card_url_of_another_origin_is_refused() {
    let transport = ScriptedTransport::new(vec![response(card_body(&[]))]);
    let source = source(&transport);

    let error = match source.with_card_url("https://other.example.test/server-card") {
        Ok(_) => panic!("a cross-origin card url was accepted"),
        Err(error) => error,
    };
    assert_eq!(error.http_status, 0);
    assert_eq!(error.code, codes::CROSS_ORIGIN);
    assert_eq!(error.reason(), Some("origin_mismatch"));
    assert_eq!(transport.calls(), 0, "a refused card url was fetched");
}

/// A card whose only remote is another origin matches no remote: `refresh`
/// reports `no_remote` and `current` answers the empty snapshot
/// (spec 06 R7.1, R7.2).
#[test]
fn a_card_without_a_matching_remote_is_an_error_and_current_is_empty() {
    let body = json!({"remotes": [{"url": "https://other.example.test/mcp"}]})
        .to_string()
        .into_bytes();
    let transport = ScriptedTransport::new(vec![response(body)]);
    let source = source(&transport);

    let error = source
        .refresh(NOW)
        .expect_err("a card without the MCP remote was accepted");
    assert_eq!(error.code, codes::NO_REMOTE);

    let empty = source.current(NOW + 1);
    assert_eq!(empty, KeySnapshot::empty());
    assert_eq!(transport.calls(), 2);
}
