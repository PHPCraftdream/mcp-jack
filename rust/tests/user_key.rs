//! User-key conformance tests for the role-specific Ed25519 key API.
//! Standalone: all oracle constants are embedded (pinned from the repo
//! fixtures) so the pins cannot drift with fixture edits; no runtime fixture
//! reads, no common test module.

use mcp_jack::client::signer::Signer;
use mcp_jack::encoding::{decode_b64url, decode_b64url_fixed, encode_b64url};
use mcp_jack::user_key::{ClientSigningKey, IssuedClientKey, ServerPublicKey, UserKeyPublic};

/// Hex-decodes into an exact 32-byte array (panics on anything else; the
/// constants below are compile-time-pinned).
fn seed32(hex: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, pair) in hex.as_bytes().chunks(2).enumerate() {
        out[i] =
            u8::from_str_radix(std::str::from_utf8(pair).expect("valid"), 16).expect("hex digit");
    }
    out
}

/// Hex-decodes into a byte vector (for pinned signatures of any length).
fn hex_bytes(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks(2)
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("valid"), 16).expect("hex digit")
        })
        .collect()
}

// Pinned from spec/fixtures/keys.json, identity "alice".
const ALICE_SEED_HEX: &str = "15949421ee8241acde219c4cff93cc346a0488e049deff61da312798b758d28f";
const ALICE_PUBLIC_B64U: &str = "kelVoYoxb3XSb-kFkOMEZNQ_x6GUFJNgdI2RjrsdgJE";
const ALICE_KID: &str = "TXF9TkhWm8UNPD-pk0NiJtux3ecJ69fMW8J9_YBDGNs";

// Pinned from spec/fixtures/keys.json, identity "bob".
const BOB_SEED_HEX: &str = "7eb4f89033dfe79db5a8fdaa667361b768722d619b62f531fba0cae9714a351b";
const BOB_PUBLIC_B64U: &str = "27O5sjd6_PRkCVbNLwEbIwxpfh0DZCURwFI9lWF-UHE";
const BOB_KID: &str = "g1T9GIZg0cumv7-IsIzIcKz9DRzv_zxZQLOnHSI4Rns";

// Pinned from interop/sign-cases.json, case id "empty-body" (identity
// "alice"): nonce, timestamp and signature; body is empty.
const CASE_EMPTY_BODY_NONCE: &str = "9t3KTc6TGArpVjaFOCLCPw";
const CASE_EMPTY_BODY_TS: i64 = 1767225600;
const CASE_EMPTY_BODY_BODY_B64U: &str = "";
const CASE_EMPTY_BODY_SIG_B64U: &str =
    "uv3TRnyiFMmayplmLBffskNhB8-aVOgkKcZiQu0kuTtB1Ib1dxA22lebCDGPQT1Gjtavn5t6loShVCXcdweBDg";

// Pinned from interop/sign-cases.json, case id "utf8-body" (identity "bob").
const CASE_UTF8_BODY_NONCE: &str = "2Z4dHoSvsynyjs0jOd5pCQ";
const CASE_UTF8_BODY_TS: i64 = 1767225600;
const CASE_UTF8_BODY_BODY_B64U: &str = "eyJxIjoibmHDr3ZlIGNhZsOpIOKAkyDml6XmnKzoqp4g8J-agCJ9";
const CASE_UTF8_BODY_SIG_B64U: &str =
    "GzVEqb8_TEtTW84FDhZYStMTQWUyS58ec1nbaVsVfeom_RFV0U8WmU1F0lAGPIU8UmrUNAPRlyBQEHEYEWLbDw";

// RFC 8032 test 1 (also pinned in rust/src/ed25519.rs tests): empty message.
const RFC_SEED_HEX: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const RFC_PUBLIC_HEX: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const RFC_SIG_HEX: &str = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

// Pinned from spec/fixtures/key-vectors.json, case "reject-identity"
// (reason: identity element).
const REJECT_IDENTITY_HEX: &str =
    "0100000000000000000000000000000000000000000000000000000000000000";

// Pinned from spec/fixtures/key-vectors.json, case "reject-noncanonical-identity"
// (reason: y = p + 1).
const REJECT_NONCANONICAL_HEX: &str =
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f";

// Pinned from spec/fixtures/key-vectors.json, case "reject-mixed-order"
// (reason: base point plus an order-8 point).
const REJECT_MIXED_ORDER_HEX: &str =
    "98519eadf35b995233b51b5cd23e9cc5a28b639b5a4af0ec903cb960d81b7819";

// Pinned from spec/fixtures/key-vectors.json, case "reject-off-curve"
// (reason: not on the curve).
const REJECT_OFF_CURVE_HEX: &str =
    "0200000000000000000000000000000000000000000000000000000000000000";

// Pinned from spec/fixtures/key-vectors.json, case "reject-y-above-p"
// (reason: y >= field prime p).
const REJECT_Y_ABOVE_P_HEX: &str =
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

/// Reconstructs the pinned request-signing string for an interop case.
fn signing_string(kid: &str, ts: i64, nonce: &str, body_b64u: &str) -> Vec<u8> {
    let body = decode_b64url(body_b64u).expect("fixture body decodes");
    mcp_jack::signing::request_signing_string(
        "POST",
        "/mcp",
        "https://svc.example.test",
        kid,
        ts,
        nonce,
        &body,
    )
    .into_bytes()
}

fn assert_sign_case(
    seed_hex: &str,
    pub_b64u: &str,
    kid: &str,
    ts: i64,
    nonce: &str,
    body_b64u: &str,
    sig_b64u: &str,
) {
    let key = ClientSigningKey::from_seed(&seed32(seed_hex)).expect("32-byte seed");
    let msg = signing_string(kid, ts, nonce, body_b64u);
    let sig = key.sign(&msg);
    let expected = decode_b64url_fixed(sig_b64u, 64).expect("fixture sig decodes");
    assert_eq!(
        sig.to_vec(),
        expected,
        "signature bytes must match the interop oracle"
    );
    assert!(mcp_jack::ed25519::verify(
        key.public_key().as_slice(),
        &msg,
        &sig
    ));
    // Server role: the pinned public key imports strictly and verifies the
    // same signature.
    let server = ServerPublicKey::from_public_key(&decode_b64url_fixed(pub_b64u, 32).expect("pub"))
        .expect("fixture public key is valid");
    assert_eq!(server.kid(), kid);
    assert!(server.verify(&msg, &sig));
}

#[test]
fn fixture_identities_round_trip() {
    for (seed_hex, public_b64u, kid) in [
        (ALICE_SEED_HEX, ALICE_PUBLIC_B64U, ALICE_KID),
        (BOB_SEED_HEX, BOB_PUBLIC_B64U, BOB_KID),
    ] {
        let key = ClientSigningKey::from_seed(&seed32(seed_hex)).expect("32-byte seed");
        let fixture_pub = decode_b64url_fixed(public_b64u, 32).expect("fixture pub decodes");
        assert_eq!(key.public_key().as_slice(), fixture_pub.as_slice());
        assert_eq!(key.kid(), kid);
        assert_eq!(key.kid(), mcp_jack::encoding::key_id(&key.public_key()));
        let public = key.public_part();
        assert_eq!(public.public_key, public_b64u);
        assert_eq!(public.kid, kid);

        // Server role accepts the same identity through both import paths.
        let server_raw = ServerPublicKey::from_public_key(&fixture_pub).expect("valid pub");
        assert_eq!(server_raw.kid(), kid);
        let server_part = ServerPublicKey::from_public_part(&public).expect("valid part");
        assert_eq!(server_part, server_raw);
    }
}

#[test]
fn from_public_part_identity_consistency() {
    // Positive control: a consistent part imports and keeps the pinned kid.
    let part = UserKeyPublic {
        public_key: ALICE_PUBLIC_B64U.to_string(),
        kid: ALICE_KID.to_string(),
    };
    let imported = ServerPublicKey::from_public_part(&part).expect("consistent part imports");
    assert_eq!(imported.kid(), ALICE_KID);

    // Mismatch: alice's public key paired with bob's kid must be rejected,
    // never silently relabeled to the recomputed alice kid.
    let mismatch = UserKeyPublic {
        public_key: ALICE_PUBLIC_B64U.to_string(),
        kid: BOB_KID.to_string(),
    };
    let err = ServerPublicKey::from_public_part(&mismatch)
        .expect_err("inconsistent kid must be rejected");
    assert!(err.to_string().contains("does not match"), "{err}");

    // Malformed kids can never equal the canonical 43-char computed kid.
    for bad in ["not-a-kid", "", "TXF9"] {
        let part = UserKeyPublic {
            public_key: ALICE_PUBLIC_B64U.to_string(),
            kid: bad.to_string(),
        };
        assert!(
            ServerPublicKey::from_public_part(&part).is_err(),
            "malformed kid {bad:?} must be rejected"
        );
    }
}

#[test]
fn server_public_verifies_pinned_interop_signature() {
    // interop/sign-cases.json "empty-body" (alice): server-side verify of
    // the pinned signature over the reconstructed signing string.
    let server = ServerPublicKey::from_public_part(&UserKeyPublic {
        public_key: ALICE_PUBLIC_B64U.to_string(),
        kid: ALICE_KID.to_string(),
    })
    .expect("alice public key is valid");
    let msg = signing_string(
        ALICE_KID,
        CASE_EMPTY_BODY_TS,
        CASE_EMPTY_BODY_NONCE,
        CASE_EMPTY_BODY_BODY_B64U,
    );
    let sig = decode_b64url_fixed(CASE_EMPTY_BODY_SIG_B64U, 64).expect("sig decodes");
    assert!(server.verify(&msg, &sig), "positive control must verify");

    // Changed message: the same pinned signature over a different signing
    // string must be rejected.
    let changed_msg = signing_string(
        ALICE_KID,
        CASE_EMPTY_BODY_TS,
        CASE_UTF8_BODY_NONCE,
        CASE_EMPTY_BODY_BODY_B64U,
    );
    assert!(
        !server.verify(&changed_msg, &sig),
        "changed message must fail"
    );

    // Wrong key: bob's public key must not verify alice's signature.
    let bob = ServerPublicKey::from_public_key(
        &decode_b64url_fixed(BOB_PUBLIC_B64U, 32).expect("bob pub"),
    )
    .expect("bob public key is valid");
    assert!(!bob.verify(&msg, &sig), "wrong key must fail");

    // Corrupted correct-length signatures must be rejected: flipping one
    // bit in the R half, then in the S half, of the pinned 64-byte
    // signature (non-mutating copies). A verifier that ignored signature
    // CONTENTS could not pass these controls.
    let mut r_tampered = sig.clone();
    r_tampered[0] ^= 0x01;
    assert!(
        !server.verify(&msg, &r_tampered),
        "corrupted R half must fail"
    );
    let mut s_tampered = sig.clone();
    s_tampered[32] ^= 0x01;
    assert!(
        !server.verify(&msg, &s_tampered),
        "corrupted S half must fail"
    );

    // Empty signature must be rejected without panicking.
    assert!(!server.verify(&msg, &[]), "empty signature must fail");

    // Truncated signature must be rejected without panicking.
    assert!(!server.verify(&msg, &sig[..63]));

    // Overlong (65-byte) signature must be rejected without panicking.
    let mut overlong = sig.clone();
    overlong.push(0);
    assert!(!server.verify(&msg, &overlong));
}

#[test]
fn interop_sign_cases_reproduced() {
    // interop/sign-cases.json: "empty-body" (alice) and "utf8-body" (bob).
    assert_sign_case(
        ALICE_SEED_HEX,
        ALICE_PUBLIC_B64U,
        ALICE_KID,
        CASE_EMPTY_BODY_TS,
        CASE_EMPTY_BODY_NONCE,
        CASE_EMPTY_BODY_BODY_B64U,
        CASE_EMPTY_BODY_SIG_B64U,
    );
    assert_sign_case(
        BOB_SEED_HEX,
        BOB_PUBLIC_B64U,
        BOB_KID,
        CASE_UTF8_BODY_TS,
        CASE_UTF8_BODY_NONCE,
        CASE_UTF8_BODY_BODY_B64U,
        CASE_UTF8_BODY_SIG_B64U,
    );
}

#[test]
fn rfc8032_test1_vector() {
    let key = ClientSigningKey::from_seed(&seed32(RFC_SEED_HEX)).expect("32-byte seed");
    assert_eq!(
        key.public_key().as_slice(),
        hex_bytes(RFC_PUBLIC_HEX).as_slice()
    );
    let sig = key.sign(b"");
    assert_eq!(sig.to_vec(), hex_bytes(RFC_SIG_HEX));
    assert!(mcp_jack::ed25519::verify(&key.public_key(), b"", &sig));
}

#[test]
fn generate_distinct_and_valid() {
    let a = ClientSigningKey::generate().expect("os randomness");
    let b = ClientSigningKey::generate().expect("os randomness");
    assert_ne!(a.kid(), b.kid());
    assert!(mcp_jack::ed25519::validate_public_key(&a.public_key()).is_ok());
    assert!(mcp_jack::ed25519::validate_public_key(&b.public_key()).is_ok());
}

#[test]
fn deterministic_seed_import_same_signature() {
    // Determinism without any export: two imports of the same pinned seed
    // sign byte-identically.
    let a = ClientSigningKey::from_seed(&seed32(ALICE_SEED_HEX)).expect("32-byte seed");
    let b = ClientSigningKey::from_seed(&seed32(ALICE_SEED_HEX)).expect("32-byte seed");
    let msg = b"mcp-jack deterministic import";
    assert_eq!(a.sign(msg), b.sign(msg));
    assert_eq!(a.public_part(), b.public_part());
}

#[test]
fn issuance_handoff_to_client() {
    // Server-local issuance: the issuer generates a new pair, retains the
    // public identity (as a ServerPublicKey record), and hands the exported
    // seed to the client, who imports it with from_seed. Purely local: NO
    // network issuance in this crate; the seed travels only over an
    // already-authenticated channel.
    let issued = IssuedClientKey::generate().expect("os randomness");
    let retained_public = issued.public_part();
    let retained_record =
        ServerPublicKey::from_public_part(&retained_public).expect("retained part is valid");

    let handoff_seed = issued.export_seed();
    let client_key = ClientSigningKey::from_seed(&handoff_seed).expect("32-byte seed");
    assert_eq!(client_key.public_part(), retained_public);
    assert_eq!(client_key.kid(), retained_public.kid);
    assert_eq!(retained_record.public_key(), client_key.public_key());

    // Deterministic signing: re-import of the same handoff seed reproduces
    // byte-identical signatures.
    let msg = b"mcp-jack issuance handoff";
    let reimported = ClientSigningKey::from_seed(&handoff_seed).expect("32-byte seed");
    assert_eq!(client_key.sign(msg), reimported.sign(msg));
}

#[test]
fn issued_key_debug_is_redacted() {
    let issued = IssuedClientKey::generate().expect("os randomness");
    let seed = issued.export_seed();
    let seed_hex: String = seed.iter().map(|b| format!("{b:02x}")).collect();
    let rendered = format!("{issued:?}");
    // Plain assert! prints only the condition text on failure, never the
    // compared values — the handoff seed cannot leak through diagnostics.
    assert!(rendered.contains(issued.kid()));
    assert!(rendered.contains(&encode_b64url(&issued.public_key())));
    assert!(!rendered.contains(&seed_hex));
    assert!(!rendered.contains(&encode_b64url(&seed)));
    assert!(!rendered.contains("seed"));
}

#[test]
fn from_seed_rejects_wrong_lengths() {
    let err = ClientSigningKey::from_seed(&[]).expect_err("empty");
    let text = err.to_string();
    assert!(text.contains("32") && text.contains("got 0"), "{text}");
    let err = ClientSigningKey::from_seed(&[0u8; 31]).expect_err("31 bytes");
    let text = err.to_string();
    assert!(text.contains("32") && text.contains("got 31"), "{text}");
    let err = ClientSigningKey::from_seed(&[0u8; 33]).expect_err("33 bytes");
    let text = err.to_string();
    assert!(text.contains("32") && text.contains("got 33"), "{text}");
    assert!(ClientSigningKey::from_seed(&[7u8; 32]).is_ok());
    // Server role: wrong lengths are rejected by the strict import too.
    assert!(ServerPublicKey::from_public_key(&[0u8; 31]).is_err());
    assert!(ServerPublicKey::from_public_key(&[0u8; 33]).is_err());
}

#[test]
fn server_public_import_rejects_invalid_keys() {
    // Pinned from spec/fixtures/key-vectors.json (case ids in the const
    // comments above): identity, non-canonical identity, mixed order,
    // off-curve, y above p, and wrong lengths all reject.
    assert!(ServerPublicKey::from_public_key(&hex_bytes(REJECT_IDENTITY_HEX)).is_err());
    assert!(ServerPublicKey::from_public_key(&hex_bytes(REJECT_NONCANONICAL_HEX)).is_err());
    assert!(ServerPublicKey::from_public_key(&hex_bytes(REJECT_MIXED_ORDER_HEX)).is_err());
    assert!(ServerPublicKey::from_public_key(&hex_bytes(REJECT_OFF_CURVE_HEX)).is_err());
    assert!(ServerPublicKey::from_public_key(&hex_bytes(REJECT_Y_ABOVE_P_HEX)).is_err());
    assert!(ServerPublicKey::from_public_key(&[0u8; 31]).is_err());
    assert!(ServerPublicKey::from_public_key(&[0u8; 33]).is_err());
    // A valid pinned public key (alice) imports fine.
    let alice =
        ServerPublicKey::from_public_key(&decode_b64url_fixed(ALICE_PUBLIC_B64U, 32).expect("pub"))
            .expect("alice is valid");
    assert_eq!(alice.kid(), ALICE_KID);
}

#[test]
fn mutation_isolation() {
    let msg = b"mcp-jack user key mutation isolation";
    // (a) mutating the ORIGINAL seed slice after construction changes nothing.
    let mut seed = seed32(ALICE_SEED_HEX);
    let key = ClientSigningKey::from_seed(&seed).expect("32-byte seed");
    let sig_before = key.sign(msg);
    let kid_before = key.kid().to_string();
    seed[0] ^= 0xff;
    seed[31] ^= 0xff;
    // Secret comparisons use boolean assertions with safe labels: a failing
    // assert_eq!/assert_ne! would print the seed bytes into diagnostics.
    let input_mutated = seed != seed32(ALICE_SEED_HEX);
    assert!(
        input_mutated,
        "input seed slice must be actually mutated (details withheld)"
    );
    assert_eq!(key.kid(), kid_before);
    assert_eq!(
        key.public_key().as_slice(),
        decode_b64url_fixed(ALICE_PUBLIC_B64U, 32)
            .expect("pub")
            .as_slice(),
    );
    assert_eq!(key.sign(msg), sig_before);
    // (b) mutating a handoff seed COPY leaves the issued key and later
    // exports intact (same safe-label rule for handoff seed bytes).
    let issued = IssuedClientKey::generate().expect("os randomness");
    let original = issued.export_seed();
    let mut copy = issued.export_seed();
    copy[0] ^= 0xff;
    let mutated_copy_differs = copy != original;
    assert!(
        mutated_copy_differs,
        "mutated handoff copy must differ from the original (details withheld)"
    );
    let export_stable = issued.export_seed() == original;
    assert!(
        export_stable,
        "second handoff export must match the original (details withheld)"
    );
    // (c) mutating the returned public key leaves the key intact (public
    // data may stay in failure diagnostics).
    let mut pub_copy = key.public_key();
    pub_copy[0] ^= 0xff;
    assert_ne!(pub_copy, key.public_key());
    assert_eq!(key.kid(), kid_before);
    assert_eq!(key.sign(msg), sig_before);
}

#[test]
fn representations_do_not_leak_secrets() {
    let distinctive = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    let seed = seed32(distinctive);
    let seed_b64u = encode_b64url(&seed);
    let key = ClientSigningKey::from_seed(&seed).expect("32-byte seed");

    // Debug of the key: kid and public b64u only. Plain assert! prints only
    // the condition text on failure, never the compared values.
    let rendered = format!("{key:?}");
    assert!(rendered.contains(key.kid()));
    assert!(rendered.contains(&encode_b64url(&key.public_key())));
    assert!(!rendered.contains(distinctive));
    assert!(!rendered.contains(&seed_b64u));
    assert!(!rendered.contains("seed"));

    // Wrong-length error leaks no seed material in Display or Debug.
    let mut wrong = seed.to_vec();
    wrong.push(0);
    let err = ClientSigningKey::from_seed(&wrong).expect_err("33 bytes");
    let display = err.to_string();
    let debug = format!("{err:?}");
    for surface in [&display, &debug] {
        assert!(!surface.contains(distinctive));
        assert!(!surface.contains(&seed_b64u));
    }
    assert!(display.starts_with("jack: user key: "));

    // public_part JSON: exactly the two public fields, no seed material,
    // and a faithful round-trip OF THIS KEY's own values.
    let json = serde_json::to_string(&key.public_part()).expect("serializable");
    let expected = format!(
        r#"{{"public_key":"{}","kid":"{}"}}"#,
        encode_b64url(&key.public_key()),
        key.kid()
    );
    assert_eq!(json, expected);
    assert!(!json.contains(distinctive));
    assert!(!json.contains(&seed_b64u));
    let round: UserKeyPublic = serde_json::from_str(&json).expect("deserializable");
    assert_eq!(round, key.public_part());

    // Pinned-value round-trip uses ALICE's constants independently of the
    // distinctive-seed key above.
    let alice_part = UserKeyPublic {
        public_key: ALICE_PUBLIC_B64U.to_string(),
        kid: ALICE_KID.to_string(),
    };
    let alice_json = serde_json::to_string(&alice_part).expect("serializable");
    let alice_round: UserKeyPublic = serde_json::from_str(&alice_json).expect("deserializable");
    assert_eq!(alice_round.public_key, ALICE_PUBLIC_B64U);
    assert_eq!(alice_round.kid, ALICE_KID);
}

#[test]
fn server_public_type_exposes_no_private_capability() {
    // Runtime property of the server role: verification works while no
    // private material exists behind the handle. Method absence itself is
    // guarded by the compile_fail doc tests on ServerPublicKey (forbidden
    // private export and signing), mirroring the ClientSigningKey guard.
    let server = ServerPublicKey::from_public_part(&UserKeyPublic {
        public_key: ALICE_PUBLIC_B64U.to_string(),
        kid: ALICE_KID.to_string(),
    })
    .expect("valid");
    let msg = signing_string(
        ALICE_KID,
        CASE_EMPTY_BODY_TS,
        CASE_EMPTY_BODY_NONCE,
        CASE_EMPTY_BODY_BODY_B64U,
    );
    let sig = decode_b64url_fixed(CASE_EMPTY_BODY_SIG_B64U, 64).expect("sig decodes");
    assert!(server.verify(&msg, &sig));
}

#[test]
fn signer_trait_bridge_matches_inherent_sign() {
    // The trait itself stays non-extractable: it exposes only sign,
    // public_key and kid — there is no seed accessor on the trait, so the
    // seed cannot leave through a &dyn Signer handle. (Prose, not a faked
    // negative compile test.)
    let key = ClientSigningKey::generate().expect("os randomness");
    let signer: &dyn Signer = &key;
    let msg = b"mcp-jack user key trait bridge";
    assert_eq!(
        signer.sign(msg).expect("infallible for a software key"),
        key.sign(msg).to_vec()
    );
    assert_eq!(signer.public_key(), key.public_key());
    assert_eq!(signer.kid(), key.kid());
}
