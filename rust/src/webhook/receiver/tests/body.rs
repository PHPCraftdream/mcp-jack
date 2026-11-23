//! Unit tests of the bounded body collector (spec 06 R1.2, R3.6).
//!
//! The collector is the only writer of request bytes, so these tests pin the
//! two refusals of R1.2 — a declared length above the limit and a chunk that
//! would cross it — and the acceptance of exactly the limit.

use crate::webhook::codes;
use crate::webhook::receiver::body::{BodyCollector, INVALID_PARAMS};
use crate::webhook::receiver::errors::MAX_BODY_BYTES;

/// A limit above the profile maximum is refused before any delivery is read
/// (spec 06 R1.2).
#[test]
fn a_limit_above_the_profile_maximum_is_invalid_params() {
    let error = match BodyCollector::new(MAX_BODY_BYTES + 1) {
        Ok(_) => panic!("a limit above the profile maximum was accepted"),
        Err(error) => error,
    };
    assert_eq!(error.http_status, 0);
    assert_eq!(error.code, INVALID_PARAMS);
    assert_eq!(error.message, "the body limit is above the profile maximum");
    assert!(BodyCollector::new(MAX_BODY_BYTES).is_ok());
}

/// A declared `Content-Length` above the limit is `413 body_too_large`
/// (spec 06 R1.2, R3.6).
#[test]
fn a_declared_length_above_the_limit_is_body_too_large() {
    let mut collector = BodyCollector::new(8).expect("eight bytes is below the limit");
    let error = match collector.check_declared(Some(9)) {
        Ok(()) => panic!("a declared length above the limit was accepted"),
        Err(error) => error,
    };
    assert_eq!(error.http_status, 413);
    assert_eq!(error.code, codes::BODY_TOO_LARGE);
    collector
        .check_declared(Some(8))
        .expect("the limit itself is accepted");
    assert_eq!(collector.declared(), Some(8));
    collector
        .check_declared(None)
        .expect("an absent declared length is accepted");
    assert_eq!(collector.declared(), None);
}

/// A chunk that would cross the limit is refused before the excess is
/// buffered (spec 06 R1.2, R3.6).
#[test]
fn a_chunk_that_overflows_the_limit_is_refused_before_buffering() {
    let mut collector = BodyCollector::new(4).expect("four bytes is below the limit");
    collector
        .push(b"abcd")
        .expect("exactly the limit is accepted");
    let error = match collector.push(b"e") {
        Ok(()) => panic!("a chunk above the limit was accepted"),
        Err(error) => error,
    };
    assert_eq!(error.http_status, 413);
    assert_eq!(error.code, codes::BODY_TOO_LARGE);
    assert_eq!(collector.finish(), b"abcd".to_vec());
}

/// Exactly the limit is accepted, in any number of chunks (spec 06 R1.2).
#[test]
fn exactly_the_limit_is_accepted() {
    let mut collector = BodyCollector::new(8).expect("eight bytes is below the limit");
    collector
        .check_declared(Some(8))
        .expect("the declared length equals the limit");
    collector.push(b"1234").expect("the first half fits");
    collector.push(b"5678").expect("the second half fits");
    assert_eq!(collector.limit(), 8);
    assert_eq!(collector.finish(), b"12345678".to_vec());
}

/// An empty chunk never moves the buffer (spec 06 R1.2).
#[test]
fn an_empty_chunk_is_harmless() {
    let mut collector = BodyCollector::new(0).expect("a zero limit is not above the maximum");
    collector.push(b"").expect("an empty chunk fits");
    assert_eq!(
        collector
            .push(b"x")
            .expect_err("one byte overflows")
            .http_status,
        413
    );
    assert!(collector.finish().is_empty());
}
