//! Helpers shared by both modern-matrix roles (interop/modern/contract.md
//! section 2): the fixed clock file, the deterministic nonce source and the
//! tiny encoding and header lookups both executables need.

/// Reads `path` as one decimal integer. Anything but an optional leading `-`
/// followed by ASCII digits is an error; surrounding ASCII whitespace is
/// trimmed, a leading `+` is not accepted.
pub fn read_clock(path: &str) -> Result<i64, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
    let text = text.trim_matches(|c: char| c.is_ascii_whitespace());
    let digits = text.strip_prefix('-').unwrap_or(text);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err("clock file does not hold a decimal integer".to_owned());
    }
    text.parse::<i64>()
        .map_err(|e| format!("clock file value is not an i64: {e}"))
}

/// Reads `path` for "now" and fails the process when it is unreadable or
/// malformed (interop/modern/contract.md section 2): one stderr line and exit
/// 1, never a stale timestamp. `who` prefixes the diagnostic with the role.
pub fn clock_or_exit(path: &str, who: &str) -> i64 {
    match read_clock(path) {
        Ok(now) => now,
        Err(error) => {
            eprintln!("{who}: --clock-file: {error}");
            std::process::exit(1)
        }
    }
}

/// The nonce of request `index` of `scenario`: the first 16 bytes of
/// sha256(utf8("mcp-jack-interop-modern/nonce/<scenario>/<index>")). Never
/// random, so two runs of one scenario sign identical bytes.
pub fn derive_nonce(scenario: &str, index: usize) -> [u8; 16] {
    let input = format!("mcp-jack-interop-modern/nonce/{scenario}/{index}");
    // body_hash is base64url(SHA-256(..)), the only public SHA-256 door the
    // SDK offers; decoding it back yields the 32 digest bytes.
    let digest = mcp_jack::encoding::body_hash(input.as_bytes());
    let bytes = mcp_jack::encoding::decode_b64url(&digest)
        .expect("body_hash always emits canonical base64url");
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&bytes[..16]);
    nonce
}

/// Canonical unpadded base64url of `bytes`.
pub fn b64u(bytes: &[u8]) -> String {
    mcp_jack::encoding::encode_b64url(bytes)
}

/// Every value of the header `name` in received order. Names compare
/// case-insensitively, values case-sensitively (contract section 2).
pub fn header_values<'a>(headers: &'a [(String, String)], name: &str) -> Vec<&'a str> {
    headers
        .iter()
        .filter(|(header, _)| header.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
        .collect()
}

/// The first value of the header `name`, if it appears at all.
pub fn first_header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(header, _)| header.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}
