//! Unit tests for `crate::client::stream`: the stream source surface and the
//! `SigningTransport` opt-in of spec 05 section 1.1, and the verified iterator
//! of section 4.

mod source;
mod verified;

use std::sync::{Arc, Mutex};

use crate::user_key::ServerSigningKey;

use crate::client::transport::Clock;
use crate::stream::{SignedOpen, StaticStreamSigner, StreamBuilder, StreamVerifierConfig};

// TEST ONLY: spec/fixtures/keys.json ("svc", "alice" and "root").
const SVC_SEED_HEX: &str = "cc9e39e830a43e09c6372b14852ef80a2bb8e7b1aa4c04bf076f33e0aad2c901";
const ALICE_SEED_HEX: &str = "15949421ee8241acde219c4cff93cc346a0488e049deff61da312798b758d28f";
const ROOT_SEED_HEX: &str = "b25e7cd6e4b7528df098bd668a1c765f37f8c28f407d13f18dbb84aea6dcaff1";

const SVC_KID: &str = "wltl591LbtvQV2vee3U5IpVRhqVxpnEeuh1NZh_mL88";
const AUD: &str = "https://svc.example.test";
/// The open header and every frame of the tests are signed at this second.
const OPEN_TS: i64 = 1_767_225_600;
const SID: &str = "q9nUNYuH-Xf_cgJBVu4_Dg";
const REQUEST_SIG: &str =
    "OsOug0yCJZPIkJ5Huk2UcIxlstzaz4b22EBRHfQHO0YgoHkDflI7kNPpSGO4HzueDASfxlEQRL1Kt45PN0pfBw";

const MSG_A: &str = r#"{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"t1","progress":1}}"#;
const MSG_B: &str = r#"{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"t1","progress":2}}"#;

fn hex_seed(seed_hex: &str) -> [u8; 32] {
    let mut seed = [0u8; 32];
    for (index, pair) in seed_hex.as_bytes().chunks(2).enumerate() {
        let text = std::str::from_utf8(pair).expect("ASCII hex");
        seed[index] = u8::from_str_radix(text, 16).expect("hex byte");
    }
    seed
}

/// The fixture `svc` stream key (TEST ONLY).
fn svc_signer() -> StaticStreamSigner {
    StaticStreamSigner::new(ServerSigningKey::from_bytes(&hex_seed(SVC_SEED_HEX)), None)
}

/// The signed open header of a stream bound to `request_sig`.
fn open_builder(request_sig: &str, ts: i64) -> (StreamBuilder, SignedOpen) {
    StreamBuilder::open(200, request_sig, SVC_KID, ts, SID, &svc_signer())
        .expect("open header signed")
}

/// One signed frame's exact wire bytes (2.6); empty `data` writes the end frame.
fn frame_bytes(builder: &mut StreamBuilder, ts: i64, data: &str) -> Vec<u8> {
    let (_, wire) = builder
        .frame(ts, data, &svc_signer())
        .expect("frame signed");
    wire.into_bytes()
}

/// Seconds clock with one sample per call; the last sample repeats.
fn seconds_clock(samples: &[i64]) -> Clock {
    let samples = samples.to_vec();
    let index = Arc::new(Mutex::new(0usize));
    Arc::new(move || {
        let mut index = index.lock().expect("clock lock");
        let sample = samples
            .get(*index)
            .copied()
            .unwrap_or_else(|| *samples.last().unwrap_or(&0));
        if *index + 1 < samples.len() {
            *index += 1;
        }
        sample
    })
}

/// The verifier config of the pinned fixture key with `REQUEST_SIG`.
fn config(samples: &[i64]) -> StreamVerifierConfig {
    let mut config =
        StreamVerifierConfig::pinned(SVC_KID, svc_signer().verifying_key(), REQUEST_SIG);
    config.now = seconds_clock(samples);
    config
}
