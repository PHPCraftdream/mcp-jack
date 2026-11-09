//! Key id and name syntax checks (Go: syntax.go).

/// Reports whether `s` is 1-64 characters of [A-Za-z0-9._-] (spec 03 section 1).
pub fn valid_name(s: &str) -> bool {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > 64 {
        return false;
    }
    b.iter()
        .all(|&c| c.is_ascii_alphanumeric() || c == b'.' || c == b'_' || c == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_name_accepts_and_rejects() {
        for s in ["a", "alice-laptop", "A_1.b-c"] {
            assert!(valid_name(s), "valid_name({s:?}) should be true");
        }
        assert!(
            valid_name(&"a".repeat(64)),
            "valid_name(64 a's) should be true"
        );
        for s in ["", "bad name", "bad:name", "bad/name"] {
            assert!(!valid_name(s), "valid_name({s:?}) should be false");
        }
        assert!(
            !valid_name(&"a".repeat(65)),
            "valid_name(65 a's) should be false"
        );
    }
}
