//! `C8` private-only caching (spec 04 section 6, spec 01 section 5): the cache
//! key is the exact request, and the result it stores is bound to that request
//! because a Jack response is signed over the request signature it answers.

use mcp_jack::user_key::ServerSigningKey;
use serde_json::json;

use mcp_jack::auth_header::{format_response_auth, ResponseAuth};
use mcp_jack::client::modern::{CacheKey, PrivateResultCache};
use mcp_jack::encoding::{encode_b64url, key_id};
use mcp_jack::modern::Era;
use mcp_jack::signing::{response_signing_string, verify_response};

/// The fixed server signing seed (Ed25519 needs exactly 32 bytes).
const SEED_HEX: &str = "1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809";

/// The response timestamp every response here is signed at.
const TS: i64 = 1_767_225_600;

/// The acceptance window every verification here uses.
const WINDOW: i64 = 30;

/// Decodes the 64 hex digits of `SEED_HEX` into the 32-byte signing seed.
fn seed() -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, pair) in SEED_HEX.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(pair).expect("hex pair"), 16)
            .expect("hex digit");
    }
    out
}

#[test]
fn client_cache_private_only() {
    // Part 1: the key discipline of a private result cache.
    let mut cache = PrivateResultCache::new();
    assert_eq!(cache.len(), 0);
    assert!(cache.is_empty());

    let key = CacheKey::new("tools/call", "{\"name\":\"a\"}", Era::Modern);
    let result = json!({"content": []});
    cache.insert(key.clone(), result.clone(), 1_000, 5_000);

    assert_eq!(cache.len(), 1);
    assert!(!cache.is_empty());
    assert_eq!(cache.get(&key, 5_000), Some(&result));

    // A different method, params text or era is a different request, so the
    // stored result never answers it.
    for other in [
        CacheKey::new("events/poll", "{\"name\":\"a\"}", Era::Modern),
        CacheKey::new("tools/call", "{\"name\":\"b\"}", Era::Modern),
        CacheKey::new("tools/call", "{\"name\":\"a\"}", Era::Legacy),
    ] {
        assert!(cache.get(&other, 5_000).is_none(), "{other:?}");
    }

    // The stored ttl of 1_000 ms expires at now_ms == 6_000: usable one
    // millisecond before it, gone from the expiry instant on.
    assert_eq!(cache.get(&key, 5_999), Some(&result));
    assert!(cache.get(&key, 6_000).is_none());

    // A `ttl_ms` of zero stores nothing at all: the result MUST NOT be reused.
    let zero = CacheKey::new("tools/call", "{\"name\":\"zero\"}", Era::Modern);
    cache.insert(zero.clone(), result.clone(), 0, 5_000);
    assert_eq!(cache.len(), 1);
    assert!(cache.get(&zero, 5_000).is_none());

    // Part 2: the binding the cache relies on. A response is signed over the
    // answering request's signature (spec 01 section 5), so a result bound to
    // request A cannot answer request B — which is exactly what forbids a
    // shared or HTTP-level cache (spec 04 `C8`).
    let signing = ServerSigningKey::from_bytes(&seed());
    let server_pub = *signing.verifying_key().as_bytes();
    let kid = key_id(&server_pub);
    assert_eq!(kid.len(), 43);

    let request_sig_a = encode_b64url(&[7u8; 32]);
    let request_sig_b = encode_b64url(&[9u8; 32]);
    assert_eq!(request_sig_a.len(), 43);
    assert_eq!(request_sig_b.len(), 43);
    assert_ne!(request_sig_a, request_sig_b);

    let body = br#"{"jsonrpc":"2.0","id":1,"result":{"content":[]}}"#;
    let msg = response_signing_string(200, &request_sig_a, &kid, TS, body);
    let header = format_response_auth(&ResponseAuth {
        kid: kid.clone(),
        ts: TS,
        sig: encode_b64url(&signing.sign(msg.as_bytes())),
    });
    let headers = [header.as_str()];

    assert_eq!(
        verify_response(&server_pub, 200, &headers, &request_sig_a, body, TS, WINDOW),
        Ok(())
    );
    assert!(
        verify_response(&server_pub, 200, &headers, &request_sig_b, body, TS, WINDOW).is_err(),
        "a response signed over request A must not verify for request B"
    );
}
