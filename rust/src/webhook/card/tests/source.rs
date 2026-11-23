//! Unit tests of the operational Server Card key source
//! (spec 06 R7.1-R7.4).
//!
//! Every test drives one `CardSource` over the scripted transport of the
//! parent module, so the observable facts are the fetch count, the accepted
//! `kid`s, the raw published JWKs and the rejection code.

use serde_json::json;

use crate::webhook::card::discovery::MAX_CARD_TTL_SECONDS;
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

/// A key set is served inside its TTL; once the TTL has passed and the refresh
/// fails, the set is not trusted any more and `current` reports no accepted
/// key (spec 06 R7.2, R7.3).
#[test]
fn a_key_set_is_served_inside_its_ttl_and_not_trusted_after_a_failed_refresh() {
    let key = card_key("retired key");
    let transport = ScriptedTransport::failing_from(vec![response(card_body(&[jwk(&key)]))], 1);
    let source = source(&transport);

    let served = source.current(NOW);
    assert_eq!(accepted_kids(&served), vec![key.kid.as_str()]);
    assert_eq!(transport.calls(), 1);

    let inside = source.current(NOW + MAX_CARD_TTL_SECONDS - 1);
    assert_eq!(
        transport.calls(),
        1,
        "a read inside the TTL refetched the card"
    );
    assert_eq!(inside, served, "a read inside the TTL dropped the key set");

    // The TTL is reached, the refresh runs and fails, so the retired key is
    // no longer trusted and the receiver answers `no_server_keys` (R7.3).
    let retired = source.current(NOW + MAX_CARD_TTL_SECONDS);
    assert_eq!(
        transport.calls(),
        2,
        "a read at the TTL reused the cached key set"
    );
    assert_eq!(retired, KeySnapshot::empty());
    assert!(
        retired.accepted.is_empty(),
        "a retired key stayed trusted after a failed refresh"
    );
}

/// A `max-age=60` response makes the entry stale after 60 s: the failing
/// refresh at `now + 61` reports no accepted key, while `now + 59` still
/// serves the cached set (spec 06 R7.2).
#[test]
fn a_max_age_of_sixty_seconds_makes_the_entry_stale_after_sixty_seconds() {
    let key = card_key("max-age key");
    let transport = ScriptedTransport::failing_from(
        vec![cached_response(card_body(&[jwk(&key)]), "max-age=60")],
        1,
    );
    let source = source(&transport);

    let served = source.current(NOW);
    assert_eq!(accepted_kids(&served), vec![key.kid.as_str()]);

    let inside = source.current(NOW + 59);
    assert_eq!(transport.calls(), 1, "a read inside the max-age refetched");
    assert_eq!(accepted_kids(&inside), vec![key.kid.as_str()]);

    let expired = source.current(NOW + 61);
    assert_eq!(
        transport.calls(),
        2,
        "a read past the max-age reused the cache"
    );
    assert_eq!(expired, KeySnapshot::empty());
}

/// A `max-age=1000` response is clamped to the 300 s cap of R7.2: `now + 299`
/// still serves the set and the failing refresh at `now + 301` does not
/// (spec 06 R7.2).
#[test]
fn a_max_age_above_the_cap_is_clamped_to_three_hundred_seconds() {
    let key = card_key("clamped key");
    let transport = ScriptedTransport::failing_from(
        vec![cached_response(card_body(&[jwk(&key)]), "max-age=1000")],
        1,
    );
    let source = source(&transport);

    let served = source.current(NOW);
    assert_eq!(accepted_kids(&served), vec![key.kid.as_str()]);

    let inside = source.current(NOW + 299);
    assert_eq!(transport.calls(), 1, "a read inside the clamp refetched");
    assert_eq!(accepted_kids(&inside), vec![key.kid.as_str()]);

    let expired = source.current(NOW + 301);
    assert_eq!(
        transport.calls(),
        2,
        "a read past the clamp reused the cache"
    );
    assert_eq!(expired, KeySnapshot::empty());
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
/// prefix parses as a card, and the cached set it holds is still fresh at the
/// next read (spec 06 R7.2).
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
