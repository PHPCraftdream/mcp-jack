mod common;

use common::fixtures::*;

fn hex_bytes(id: &str, s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() / 2);
    let chars: Vec<char> = s.chars().collect();
    for pair in chars.chunks(2) {
        if pair.len() != 2 {
            panic!("case {}: odd hex length {:?}", id, s);
        }
        let hi = pair[0]
            .to_digit(16)
            .unwrap_or_else(|| panic!("case {}: bad hex digit {:?}", id, s));
        let lo = pair[1]
            .to_digit(16)
            .unwrap_or_else(|| panic!("case {}: bad hex digit {:?}", id, s));
        out.push(((hi << 4) | lo) as u8);
    }
    out
}

#[test]
fn key_vectors() {
    let v = load_key_vectors().expect("load key-vectors.json");
    assert!(!v.cases.is_empty(), "key-vectors.json has no cases");
    for c in &v.cases {
        let bytes = hex_bytes(&c.id, &c.public_key_hex);
        let result = mcp_jack::ed25519::validate_public_key(&bytes);
        match c.expect.as_str() {
            "valid" => assert!(
                result.is_ok(),
                "case {}: expected valid, got {:?}",
                c.id,
                result
            ),
            "rejected" => match result {
                Ok(()) => panic!("case {}: expected rejected, got Ok", c.id),
                Err(err) => {
                    assert_eq!(err.http_status, 400, "case {}: http_status", c.id);
                    assert_eq!(
                        err.code,
                        mcp_jack::error::codes::KEY_REJECTED,
                        "case {}: code",
                        c.id
                    );
                }
            },
            other => panic!("case {}: unknown expect {:?}", c.id, other),
        }
    }
}

#[test]
fn keys_json_derivation() {
    let keys = load_keys().expect("load keys.json");
    assert!(!keys.keys.is_empty(), "keys.json has no keys");
    for key in &keys.keys {
        let seed = hex_bytes(&key.name, &key.seed_hex);
        let seed: [u8; 32] = seed.try_into().unwrap_or_else(|_| {
            panic!("key {}: seed_hex is not 32 bytes", key.name);
        });
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
        let derived = signing.verifying_key().as_bytes().to_vec();
        let fixture_pub = mcp_jack::encoding::decode_b64url_fixed(key.public_key.as_str(), 32)
            .unwrap_or_else(|e| panic!("key {}: bad public_key b64u: {:?}", key.name, e));
        assert_eq!(
            derived, fixture_pub,
            "key {}: derived public key differs from fixture",
            key.name
        );
        assert_eq!(
            mcp_jack::encoding::key_id(&fixture_pub),
            key.kid,
            "key {}: kid mismatch",
            key.name
        );
        assert!(
            mcp_jack::ed25519::validate_public_key(&fixture_pub).is_ok(),
            "key {}: derived key rejected by validate_public_key",
            key.name
        );
    }
}
