//! Strict Ed25519 signature verification and public-key validation (Go: ed25519.go).

use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::Scalar;
use ed25519_dalek::{Signature, VerifyingKey};

use crate::error::{codes, JackError};

// Constant time is NOT required here: public data, admission-time only
// (spec 01 section 2, spec 03 section 2).

/// Canonical encoding of the identity: y = 1, x = 0, clear sign bit.
const IDENTITY_ENCODING: [u8; 32] = {
    let mut b = [0u8; 32];
    b[0] = 1;
    b
};

/// Reports whether `signature` is a valid Ed25519 signature of `message`
/// under `public_key`, with the strict rule that the scalar S (little-endian
/// signature[32..64]) is below the group order L (spec 01 section 2).
/// Returns false for wrong lengths; it must not panic.
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let Ok(pk) = <[u8; 32]>::try_from(public_key) else {
        return false;
    };
    let Ok(sig64) = <[u8; 64]>::try_from(signature) else {
        return false;
    };

    // Spec 01 section 2: S >= L is invalid even when the verification equation
    // holds; a canonical scalar is exactly S < L. Dalek enforces this
    // internally today, but the check stays explicit so the guarantee does not
    // depend on dalek's feature flags.
    let mut s_le = [0u8; 32];
    s_le.copy_from_slice(&sig64[32..64]);
    if Scalar::from_canonical_bytes(s_le).is_none().into() {
        return false;
    }

    let Ok(vk) = VerifyingKey::from_bytes(&pk) else {
        return false;
    };
    let sig = Signature::from_bytes(&sig64);
    // verify_strict additionally rejects non-canonical R and small-order R/A,
    // which Go's crypto/ed25519.Verify does not; nothing in the fixtures
    // requires accepting those, and public-key validity is enforced at
    // enrollment/registry load by validate_public_key (spec 03 section 2).
    vk.verify_strict(message, &sig).is_ok()
}

/// Checks spec 03 section 2: exactly 32 bytes, a canonical encoding (the y
/// coordinate below 2^255-19), a point on the curve, not the identity, and in
/// the prime-order subgroup. Any failure is 400 key_rejected.
pub fn validate_public_key(public_key: &[u8]) -> Result<(), JackError> {
    let bytes = <[u8; 32]>::try_from(public_key)
        .map_err(|_| key_rejected("public key must be 32 bytes"))?;

    let compressed = CompressedEdwardsY(bytes);
    let Some(point) = compressed.decompress() else {
        return Err(key_rejected("non-canonical or off-curve public key"));
    };
    // Re-compressing reproduces the input exactly iff the encoding is
    // canonical; this also rejects a set sign bit on a point with x = 0
    // (Go's "non-canonical sign" rejection), because compress() always
    // renders x = 0 with a clear sign bit.
    if point.compress().to_bytes() != bytes {
        return Err(key_rejected("non-canonical or off-curve public key"));
    }
    // The identity check must precede the torsion check (mirrors Go; the
    // identity IS torsion-free, so the order is observable only in messages).
    if bytes == IDENTITY_ENCODING {
        return Err(key_rejected("identity point"));
    }
    // is_torsion_free computes [L]P == identity.
    if !point.is_torsion_free() {
        return Err(key_rejected("not in the prime-order subgroup"));
    }
    Ok(())
}

fn key_rejected(message: &'static str) -> JackError {
    JackError::new(400, codes::KEY_REJECTED, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn hex_bytes(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks(2)
            .map(|pair| {
                u8::from_str_radix(std::str::from_utf8(pair).expect("valid"), 16).expect("hex")
            })
            .collect()
    }

    /// Adds `b` (little-endian) to `a` (little-endian) in place with carry.
    fn le_add(a: &mut [u8], b: &[u8]) {
        let mut carry = 0u16;
        for i in 0..a.len() {
            let sum = a[i] as u16 + b[i] as u16 + carry;
            a[i] = sum as u8;
            carry = sum >> 8;
        }
        assert_eq!(carry, 0, "addition overflowed");
    }

    const RFC_SEED_HEX: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const RFC_PUBLIC_HEX: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const RFC_SIG_HEX: &str =
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

    #[test]
    fn rfc8032_test1_accepted() {
        let seed: [u8; 32] = hex_bytes(RFC_SEED_HEX).try_into().expect("32 bytes");
        let rfc_public: [u8; 32] = hex_bytes(RFC_PUBLIC_HEX).try_into().expect("32 bytes");
        let rfc_sig = hex_bytes(RFC_SIG_HEX);

        assert_eq!(128, RFC_SIG_HEX.len()); // the hex constant is complete
        assert_eq!(64, rfc_sig.len()); // an Ed25519 signature is 64 bytes
                                       // Consistency oracle: a typo in either constant fails here.
        let signing = SigningKey::from_bytes(&seed);
        assert_eq!(signing.verifying_key().as_bytes(), &rfc_public);

        assert!(validate_public_key(&rfc_public).is_ok());
        assert!(verify(&rfc_public, b"", &rfc_sig));
        assert!(!verify(&rfc_public, b"x", &rfc_sig));

        let mut bad_sig = rfc_sig.clone();
        bad_sig[0] ^= 1;
        assert!(!verify(&rfc_public, b"", &bad_sig));
    }

    #[test]
    fn dalek_round_trip_and_strict_s() {
        let seed: [u8; 32] = hex_bytes(RFC_SEED_HEX).try_into().expect("32 bytes");
        let pub_bytes: [u8; 32] = hex_bytes(RFC_PUBLIC_HEX).try_into().expect("32 bytes");
        let signing = SigningKey::from_bytes(&seed);
        let msg = b"mcp-jack test message";
        let sig = signing.sign(msg);
        let sig_bytes = sig.to_bytes();

        assert!(verify(&pub_bytes, msg, &sig_bytes));
        assert!(!verify(&pub_bytes, b"other message", &sig_bytes));

        // Port of Go TestVerifyRejectsMalleatedSPlusL: S + L must be rejected.
        // RFC 8032: L = 2^252 + 27742317777372353535851937790883648493, little-endian.
        let l_bytes: [u8; 32] =
            hex_bytes("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")
                .try_into()
                .expect("32 bytes");
        let mut below_order = l_bytes;
        below_order[0] -= 1;
        assert!(bool::from(
            Scalar::from_canonical_bytes(below_order).is_some()
        ));
        // Oracle: L itself is not a canonical scalar (it is not < L).
        assert!(bool::from(Scalar::from_canonical_bytes(l_bytes).is_none()));
        let mut at_order = sig_bytes;
        at_order[32..64].copy_from_slice(&l_bytes);
        assert!(!verify(&pub_bytes, msg, &at_order));

        let mut malleated = sig_bytes;
        let mut s_plus_l = <[u8; 32]>::try_from(&malleated[32..64]).expect("32 bytes");
        le_add(&mut s_plus_l, &l_bytes);
        assert!(bool::from(Scalar::from_canonical_bytes(s_plus_l).is_none()));
        malleated[32..64].copy_from_slice(&s_plus_l);
        assert!(!verify(&pub_bytes, msg, &malleated));
    }

    #[test]
    fn rejects_wrong_lengths() {
        let seed: [u8; 32] = hex_bytes(RFC_SEED_HEX).try_into().expect("32 bytes");
        let signing = SigningKey::from_bytes(&seed);
        let pub_bytes = *signing.verifying_key().as_bytes();
        let msg = b"mcp-jack test message";
        let sig = signing.sign(msg).to_bytes();

        assert!(!verify(&pub_bytes[..31], msg, &sig));
        assert!(!verify(&pub_bytes, msg, &sig[..63]));
        let mut long = sig.to_vec();
        long.push(0);
        assert!(!verify(&pub_bytes, msg, &long));

        for len in [31usize, 33] {
            let err = validate_public_key(&vec![0u8; len]).expect_err("must reject");
            assert_eq!(err.http_status, 400);
            assert_eq!(err.code, codes::KEY_REJECTED);
        }
    }

    #[test]
    fn validate_rejects_identity_and_sign_bit() {
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let err = validate_public_key(&identity).expect_err("identity");
        assert_eq!(err.http_status, 400);
        assert_eq!(err.code, codes::KEY_REJECTED);

        // x = 0 forces a clear sign bit, so re-compression cannot reproduce
        // this encoding: Go rejects it as a non-canonical sign; here it fails
        // the re-compress-and-compare check.
        let mut sign_bit = [0u8; 32];
        sign_bit[0] = 1; // y = 1, the identity
        sign_bit[31] = 0x80; // sign bit is bit 255: a point with x = 0 must encode it clear
        let err = validate_public_key(&sign_bit).expect_err("non-canonical sign");
        assert_eq!(err.http_status, 400);
        assert_eq!(err.code, codes::KEY_REJECTED);
    }
}
