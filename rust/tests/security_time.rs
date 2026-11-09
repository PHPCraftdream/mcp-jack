//! Regression coverage for the pinned `time` RFC 2822 parser depth limit.

use time::{format_description::well_known::Rfc2822, OffsetDateTime};

fn date_with_comment_depth(depth: usize) -> String {
    format!(
        "Fri, {}x{} 21 Nov 1997 09:55:06 -0600",
        "(".repeat(depth),
        ")".repeat(depth)
    )
}

#[test]
fn rfc2822_accepts_valid_date_and_shallow_nested_comments() {
    assert!(OffsetDateTime::parse("Fri, 21 Nov 1997 09:55:06 -0600", &Rfc2822).is_ok());
    assert!(OffsetDateTime::parse(&date_with_comment_depth(2), &Rfc2822).is_ok());
}

#[test]
fn rfc2822_rejects_nesting_at_the_recursion_guard() {
    // In time 0.3.47, comment() starts at depth 1 and refuses entry at depth 32;
    // 31 nested comments are valid, while the next level must be rejected.
    assert!(OffsetDateTime::parse(&date_with_comment_depth(31), &Rfc2822).is_ok());
    assert!(OffsetDateTime::parse(&date_with_comment_depth(32), &Rfc2822).is_err());
}
