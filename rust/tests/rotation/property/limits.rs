// Deterministic boundary tests of the pending/retired/retained limits of the trust
// snapshot. The chain of 1153 signed records is generated once;
// the expected runtime of the whole test is around 1-2 minutes in a debug build
// (Ed25519 signing and verification dominate), seconds in release.

use mcp_jack::client::{InMemorySigner, Signer};
use mcp_jack::encoding::key_id;
use mcp_jack::rotation::{
    self, Binding, Checkpoint, ClockTuple, OwnedBinding, Record, ResultCursor, TrustKey,
    TrustSnapshot,
};
use serde::Deserialize;

const SEED: u64 = 0x5eed_00b4;
const WINDOW: u64 = 30;

#[derive(Deserialize)]
struct FixtureBinding {
    endpoint: String,
    aud: String,
}

#[derive(Deserialize)]
struct Corpus {
    binding: FixtureBinding,
}

fn corpus() -> Corpus {
    let bytes = std::fs::read(crate::common::fixtures::fixture_path(
        "candidate/rotation-vectors.json",
    ))
    .expect("committed independent candidate fixture");
    serde_json::from_slice(&bytes).expect("typed corpus")
}

fn binding(corpus: &Corpus) -> Binding<'_> {
    Binding {
        endpoint: &corpus.binding.endpoint,
        aud: &corpus.binding.aud,
    }
}

// Deterministic PRNG: a fixed seed reproduces every refusal.
fn splitmix64_value(input: u64) -> u64 {
    let mut value = input.wrapping_add(0x9E37_79B9_7F4A_7C15);
    value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    value ^ (value >> 31)
}

// More than 255 distinct indices: the seed is derived from the PRNG, not from a single byte.
fn signer_seed(index: u64) -> [u8; 32] {
    let mut seed = [0_u8; 32];
    for lane in 0..4_u64 {
        let mixed = splitmix64_value(index * 4 + lane);
        let start = usize::try_from(lane * 8).expect("small offset");
        seed[start..start + 8].copy_from_slice(&mixed.to_be_bytes());
    }
    seed
}

fn signer(index: u64) -> InMemorySigner {
    InMemorySigner::from_seed(&signer_seed(index)).expect("test signer")
}

fn generated_chain(
    corpus: &Corpus,
    count: u64,
    mut published_at: impl FnMut(u64) -> u64,
) -> (Checkpoint, Vec<Record>) {
    let mut old = signer(0);
    let root = Checkpoint {
        ordinal: 0,
        hash: "-".to_owned(),
        kid: key_id(&old.public_key()),
        public_key: old.public_key(),
        published_at: 0,
    };
    let mut previous = root.clone();
    let mut records = Vec::new();
    for index in 1..=count {
        let next = signer(index);
        let record =
            rotation::create_record(binding(corpus), &previous, &old, &next, published_at(index))
                .expect("generated rotation record");
        previous = Checkpoint {
            ordinal: record.ordinal,
            hash: record.hash.clone(),
            kid: record.new_kid.clone(),
            public_key: record.public_key,
            published_at: record.published_at,
        };
        records.push(record);
        old = next;
    }
    (root, records)
}

/// The first key is the checkpoint; each record adds the next one (P = published_at of the last).
fn trust_from(corpus: &Corpus, root: &Checkpoint, records: &[Record]) -> TrustSnapshot {
    let owned = OwnedBinding {
        endpoint: corpus.binding.endpoint.clone(),
        aud: corpus.binding.aud.clone(),
    };
    let mut keys = vec![TrustKey {
        ordinal: root.ordinal,
        kid: root.kid.clone(),
        public_key: root.public_key,
        not_before: if root.ordinal == 0 {
            0
        } else {
            root.published_at + rotation::GRACE_SECONDS
        },
        known_cutoff: None,
    }];
    let mut head = ResultCursor {
        ordinal: root.ordinal,
        hash: root.hash.clone(),
    };
    let mut high_water = root.published_at;
    for record in records {
        keys.last_mut().expect("anchor/tail").known_cutoff = Some(record.activates_at);
        keys.push(TrustKey {
            ordinal: record.ordinal,
            kid: record.new_kid.clone(),
            public_key: record.public_key,
            not_before: record.activates_at,
            known_cutoff: None,
        });
        head = ResultCursor {
            ordinal: record.ordinal,
            hash: record.hash.clone(),
        };
        high_water = record.published_at;
    }
    let revision = u64::try_from(records.len()).expect("small chain") + 1;
    TrustSnapshot {
        format_version: 1,
        binding: owned.clone(),
        window: WINDOW,
        checkpoint: root.clone(),
        head,
        records: records.iter().map(|record| record.wire.clone()).collect(),
        keys,
        revision,
        fenced: false,
        clock: ClockTuple {
            binding: owned,
            window: WINDOW,
            high_water,
            revision,
            unsafe_clock: false,
        },
    }
}

#[test]
fn limits_hold_exactly_at_pending_retired_and_retained_boundaries() {
    let corpus = corpus();
    let (root, records) = generated_chain(&corpus, 1153, |index| 1000 + index);
    assert_eq!(records.len(), 1153, "seed {SEED:#x} generated chain length");

    // Pending boundary: high_water 1000 is below every activation (173800 + i),
    // so exactly 128 keys count as pending with 128 records.
    let mut pending_edge = trust_from(&corpus, &root, records.get(..128).expect("128 prefix"));
    pending_edge.clock.high_water = 1000;
    let label = format!("seed {SEED:#x} 128 pending keys accepted");
    rotation::validate_trust_snapshot(&pending_edge, binding(&corpus), WINDOW, &root)
        .expect(&label);
    let mut pending_over = trust_from(&corpus, &root, records.get(..129).expect("129 prefix"));
    pending_over.clock.high_water = 1000;
    let label = format!("seed {SEED:#x} 129 pending keys refused");
    let error = rotation::validate_trust_snapshot(&pending_over, binding(&corpus), WINDOW, &root)
        .expect_err(&label);
    assert_eq!(error.code, "rotation_state_unknown", "{label} exact code");

    // Retired + retained boundary: 1152 records with high_water = 1000 + 1024
    // + GRACE_SECONDS give exactly 1024 retired and exactly 128 pending, while keys.len()
    // == MAX_RETAINED_KEYS — the accepted-side retained limit.
    let mut retired_edge = trust_from(&corpus, &root, records.get(..1152).expect("1152 prefix"));
    retired_edge.clock.high_water = 1000 + 1024 + rotation::GRACE_SECONDS;
    let label = format!("seed {SEED:#x} boundary snapshot accepted");
    let validated =
        rotation::validate_trust_snapshot(&retired_edge, binding(&corpus), WINDOW, &root)
            .expect(&label);
    assert_eq!(
        validated.keys.len(),
        rotation::MAX_RETAINED_KEYS,
        "seed {SEED:#x} keys at the retained limit"
    );
    let mut pending = 0_usize;
    let mut retired = 0_usize;
    // Counting exactly as in validate_trust_snapshot; snapshot is not PartialEq.
    for key in &validated.keys {
        if key.not_before > validated.clock.high_water {
            pending += 1;
        } else if key
            .known_cutoff
            .is_some_and(|cutoff| cutoff <= validated.clock.high_water)
        {
            retired += 1;
        }
    }
    assert_eq!(
        pending, 128,
        "seed {SEED:#x} pending {pending} at the boundary"
    );
    assert_eq!(
        retired, 1024,
        "seed {SEED:#x} retired {retired} at the boundary"
    );

    // Retained + 1: the shape check records.len() >= MAX_RETAINED_KEYS fires
    // before any parsing and signatures — all 1153 wire entries are genuine.
    let shape_input = trust_from(&corpus, &root, &records);
    let label = format!("seed {SEED:#x} retained plus one refused");
    let error = rotation::validate_trust_snapshot(&shape_input, binding(&corpus), WINDOW, &root)
        .expect_err(&label);
    assert_eq!(error.code, "rotation_state_unknown", "{label} exact code");
}
