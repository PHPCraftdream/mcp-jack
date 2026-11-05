//! Key id, scope and pattern syntax checks (Go: syntax.go).

/// Reports whether `s` matches `^[a-z][a-z0-9_]*(:[a-z0-9_]+)*$`
/// (spec 02 section 2).
pub fn valid_scope(s: &str) -> bool {
    let b = s.as_bytes();
    if b.is_empty() || !b[0].is_ascii_lowercase() {
        return false;
    }
    let mut i = 1;
    // [a-z0-9_]*
    while i < b.len() && (b[i].is_ascii_lowercase() || b[i].is_ascii_digit() || b[i] == b'_') {
        i += 1;
    }
    // (:[a-z0-9_]+)*
    while i < b.len() {
        if b[i] != b':' {
            return false;
        }
        i += 1;
        let seg_start = i;
        while i < b.len() && (b[i].is_ascii_lowercase() || b[i].is_ascii_digit() || b[i] == b'_') {
            i += 1;
        }
        if i == seg_start {
            return false;
        }
    }
    true
}

/// Reports whether `s` is 1-64 characters of [A-Za-z0-9._-] (spec 03 section 1).
pub fn valid_name(s: &str) -> bool {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > 64 {
        return false;
    }
    b.iter()
        .all(|&c| c.is_ascii_alphanumeric() || c == b'.' || c == b'_' || c == b'-')
}

/// Reports whether `input` matches `pattern`. '*' matches any run of
/// characters including none and newlines; every other character is literal and
/// case-sensitive; there are no other metacharacters (spec 02 section 3).
/// Byte-wise matching is equivalent to rune-wise here because the only
/// metacharacter is ASCII '*', and UTF-8 continuation bytes never equal '*'.
pub fn match_pattern(pattern: &str, input: &str) -> bool {
    let pattern = pattern.as_bytes();
    let input = input.as_bytes();
    // Classic greedy matcher: backtrack to the most recent '*' on mismatch.
    // star_p/star_i = last '*' position, and matching input position.
    let mut p = 0usize;
    let mut i = 0usize;
    let mut star_p: isize = -1;
    let mut star_i = 0usize;
    while i < input.len() {
        if p < pattern.len() && pattern[p] == b'*' {
            star_p = p as isize;
            star_i = i;
            p += 1; // '*' can also match the empty run; try advancing first
            continue;
        }
        if p < pattern.len() && pattern[p] == input[i] {
            p += 1;
            i += 1;
            continue;
        }
        if star_p >= 0 {
            // Extend the run matched by the last '*'.
            star_i += 1;
            i = star_i;
            p = (star_p + 1) as usize;
            continue;
        }
        return false;
    }
    // Only trailing '*'s may remain to match the empty remainder.
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn match_pattern_unit() {
        // Only '*' is a metacharacter; everything else is a literal, and '*'
        // matches across newlines too (spec 02 section 3).
        let cases = [
            ("*", "", true),
            ("*", "anything\nat all", true),
            ("a*", "a\nb", true),
            ("*status", "svc.status.extra", false),
            ("a+b", "a+b", true),
            ("a+b", "aab", false),
            ("(x)", "(x)", true),
            ("?", "?", true),
            ("?", "a", false),
            ("", "", true),
            ("", "x", false),
            ("a*b*c", "abc", true),
            ("a*b*c", "acb", false),
            ("*", "héllo", true),
        ];
        for (pattern, input, want) in cases {
            assert_eq!(
                match_pattern(pattern, input),
                want,
                "match_pattern({pattern:?}, {input:?})"
            );
        }
    }

    #[test]
    fn valid_scope_accepts_and_rejects() {
        for s in ["read", "config:write", "a:b:c", "lifecycle", "a1_b"] {
            assert!(valid_scope(s), "valid_scope({s:?}) should be true");
        }
        for s in ["", "Read", "1abc", "a::b", "a:b-", "read ", "a:b c"] {
            assert!(!valid_scope(s), "valid_scope({s:?}) should be false");
        }
    }

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
