//! Port of Go client/signer_test.go TestSignerFromFixtureKeys: every keys.json
//! entry derives a signer whose public key and kid match the fixture (the
//! conformance fixture is the oracle). The other Go signer tests (Generate,
//! bad seed, sign round trip) are already inline unit tests in
//! rust/src/client/signer.rs and are not duplicated here.

mod common;

use common::fixtures::*;
use common::harness::*;

use mcp_jack::client::signer::{InMemorySigner, Signer};
use mcp_jack::encoding::encode_b64url;

#[test]
fn signer_from_fixture_keys() {
    let keys = load_keys().expect("load keys.json");
    assert!(!keys.keys.is_empty(), "keys.json has no keys");
    for k in &keys.keys {
        assert_eq!(
            64,
            k.seed_hex.len(),
            "key {}: seed_hex must be 64 hex chars",
            k.name
        );
        let seed = hex_bytes(&k.seed_hex);
        assert_eq!(
            32,
            seed.len(),
            "key {}: decoded seed must be 32 bytes",
            k.name
        );
        let signer = InMemorySigner::from_seed(&seed)
            .unwrap_or_else(|e| panic!("key {}: from_seed: {e}", k.name));
        assert_eq!(
            encode_b64url(&signer.public_key()),
            k.public_key,
            "key {}: public key",
            k.name
        );
        assert_eq!(signer.kid(), k.kid, "key {}: kid", k.name);
        assert!(
            mcp_jack::ed25519::validate_public_key(&signer.public_key()).is_ok(),
            "key {}: validate_public_key",
            k.name
        );
    }
}
