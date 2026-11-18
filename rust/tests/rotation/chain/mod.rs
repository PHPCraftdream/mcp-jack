use ed25519_dalek::{Signer, SigningKey};
use mcp_jack::client::{ClientError, InMemorySigner, Signer as JackSigner};
use mcp_jack::encoding::{body_hash, decode_b64url, decode_b64url_fixed, encode_b64url, key_id};
use mcp_jack::rotation::{self, Binding, Checkpoint};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Deserialize)]
struct FixtureBinding {
    endpoint: String,
    aud: String,
}
#[derive(Deserialize)]
struct Key {
    kid: String,
    public_key: String,
}
#[derive(Deserialize)]
struct Negative {
    id: String,
    expected: String,
    setup: String,
    binding: FixtureBinding,
    wire_b64u: String,
}
#[derive(Deserialize)]
struct Controls {
    decreasing_prefix: String,
}
#[derive(Deserialize)]
struct Corpus {
    binding: FixtureBinding,
    keys: BTreeMap<String, Key>,
    valid_chains: BTreeMap<String, Vec<String>>,
    source_controls: Controls,
    malformed: Vec<Negative>,
}

fn corpus() -> Corpus {
    let bytes = std::fs::read(crate::common::fixtures::fixture_path(
        "candidate/rotation-vectors.json",
    ))
    .expect("committed fixture");
    serde_json::from_slice(&bytes).expect("typed candidate corpus")
}
fn binding(value: &FixtureBinding) -> Binding<'_> {
    Binding {
        endpoint: &value.endpoint,
        aud: &value.aud,
    }
}
fn public(text: &str) -> [u8; 32] {
    decode_b64url_fixed(text, 32)
        .expect("fixture public key")
        .try_into()
        .expect("32 bytes")
}
fn checkpoint(corpus: &Corpus) -> Checkpoint {
    let anchor = &corpus.keys["anchor"];
    Checkpoint {
        ordinal: 0,
        hash: "-".into(),
        kid: anchor.kid.clone(),
        public_key: public(&anchor.public_key),
        published_at: 0,
    }
}

fn fixture_signer(name: &str) -> InMemorySigner {
    // Public fixture seed; production key material is not used here.
    let seed = Sha256::digest(format!("mcp-jack test key: candidate-server-{name}").as_bytes());
    InMemorySigner::from_seed(&seed).expect("fixture seed")
}

mod records;
mod results;
