//! Sender-side delivery unit tests (spec 06 R1.6-R1.10).
//!
//! The schedule and the decision table are the rule itself (R1.7, R1.8), so
//! no fixture file is read: every input below is a literal, and everything
//! here is pure.

use crate::webhook::delivery::{
    freshness, last_error_of, map_internal_outcome, retry_schedule, sender_decision, LastError,
    SenderAction, SenderAttempt, ATTEMPT_OFFSETS, RETRY_CAP_SECONDS,
};

/// The schedule origin every decision test uses, in unix seconds.
const T0: i64 = 1_767_225_600;

/// Returns one attempt that got an HTTP answer at `response_time`, with no
/// transport failure and no `Retry-After` (spec 06 R1.7).
fn http_attempt(status: u16, attempt: u32, response_time: i64) -> SenderAttempt {
    SenderAttempt {
        status: Some(status),
        transport: None,
        retry_after: None,
        attempt,
        t0: T0,
        response_time,
    }
}

/// Returns one attempt that read no response at all (spec 06 R1.9).
fn transport_attempt(category: LastError, attempt: u32, response_time: i64) -> SenderAttempt {
    SenderAttempt {
        status: None,
        transport: Some(category),
        retry_after: None,
        attempt,
        t0: T0,
        response_time,
    }
}

#[test]
fn retry_schedule_is_the_pinned_four_step_ladder() {
    let schedule = retry_schedule(T0);
    assert_eq!(ATTEMPT_OFFSETS, [0, 30, 270, 870]);
    assert_eq!(schedule, [T0, T0 + 30, T0 + 270, T0 + 870]);
    assert_eq!(schedule[0], T0, "the first attempt is at t0");
    assert_eq!(schedule[3], T0 + 870, "the last attempt is at t0 + 870");
    for pair in schedule.windows(2) {
        assert!(
            pair[0] < pair[1],
            "schedule {schedule:?} is not strictly increasing"
        );
    }
    assert!(
        schedule.iter().all(|at| *at <= T0 + RETRY_CAP_SECONDS),
        "schedule {schedule:?} is past the t0 + 900 s cap"
    );
}

#[test]
fn every_2xx_is_the_only_acceptance() {
    for status in [200, 201, 204, 299] {
        let decision = sender_decision(&http_attempt(status, 1, T0));
        assert_eq!(decision.action, SenderAction::Accept, "status {status}");
        assert_eq!(decision.last_error, None, "status {status}");
    }
}

#[test]
fn gone_and_payload_too_large_are_final() {
    for status in [410, 413] {
        for attempt in 1..=4 {
            let decision = sender_decision(&http_attempt(status, attempt, T0));
            assert_eq!(
                decision.action,
                SenderAction::Final,
                "status {status} attempt {attempt} was retried"
            );
            assert_eq!(decision.last_error, Some(LastError::Http4xx));
        }
    }
}

#[test]
fn other_3xx_and_4xx_answers_are_final() {
    for status in [300, 399, 400, 404, 499] {
        let decision = sender_decision(&http_attempt(status, 1, T0));
        assert_eq!(
            decision.action,
            SenderAction::Final,
            "status {status} was retried"
        );
        assert_eq!(decision.last_error, Some(LastError::Http4xx));
    }
}

#[test]
fn server_errors_retry_on_the_pinned_slots() {
    for (attempt, offset) in [(1, 30), (2, 270), (3, 870)] {
        let response_time = T0 + ATTEMPT_OFFSETS[(attempt - 1) as usize];
        let decision = sender_decision(&http_attempt(500, attempt, response_time));
        assert_eq!(
            decision.action,
            SenderAction::Retry {
                next_at: T0 + offset
            },
            "attempt {attempt}"
        );
        assert_eq!(decision.last_error, Some(LastError::Http5xx));
    }
}

#[test]
fn too_early_and_too_many_requests_are_retryable() {
    for status in [425, 429] {
        let decision = sender_decision(&http_attempt(status, 1, T0));
        assert_eq!(
            decision.action,
            SenderAction::Retry { next_at: T0 + 30 },
            "status {status}"
        );
        assert_eq!(decision.last_error, Some(LastError::Http4xx));
    }
}

#[test]
fn the_fourth_attempt_is_always_final() {
    let fourth = sender_decision(&http_attempt(500, 4, T0 + 870));
    assert_eq!(fourth.action, SenderAction::Final);
    assert_eq!(fourth.last_error, Some(LastError::Http5xx));

    let transport = sender_decision(&transport_attempt(LastError::Timeout, 4, T0 + 870));
    assert_eq!(transport.action, SenderAction::Final);
    assert_eq!(transport.last_error, Some(LastError::Timeout));

    let fifth = sender_decision(&http_attempt(503, 5, T0 + 900));
    assert_eq!(fifth.action, SenderAction::Final);
}

#[test]
fn retry_after_postpones_the_next_attempt() {
    let mut attempt = http_attempt(503, 1, T0 + 10);
    attempt.retry_after = Some(50);
    assert_eq!(
        sender_decision(&attempt).action,
        SenderAction::Retry { next_at: T0 + 60 }
    );

    // A `Retry-After` earlier than the pinned slot changes nothing.
    attempt.retry_after = Some(5);
    assert_eq!(
        sender_decision(&attempt).action,
        SenderAction::Retry { next_at: T0 + 30 }
    );

    // A non-positive delay postpones nothing either.
    attempt.retry_after = Some(-30);
    assert_eq!(
        sender_decision(&attempt).action,
        SenderAction::Retry { next_at: T0 + 30 }
    );
}

#[test]
fn retry_after_never_goes_past_the_900_second_cap() {
    let mut attempt = http_attempt(503, 1, T0 + 800);
    attempt.retry_after = Some(1_000);
    assert_eq!(
        sender_decision(&attempt).action,
        SenderAction::Retry { next_at: T0 + 900 }
    );
}

#[test]
fn a_capped_slot_already_past_is_final() {
    for response_time in [T0 + 900, T0 + 901] {
        let mut attempt = http_attempt(503, 1, response_time);
        attempt.retry_after = Some(1_000);
        let decision = sender_decision(&attempt);
        assert_eq!(
            decision.action,
            SenderAction::Final,
            "response_time {response_time} was retried"
        );
        assert_eq!(decision.last_error, Some(LastError::Http5xx));
    }
}

#[test]
fn transport_failures_retry_with_their_category() {
    let cases = [
        LastError::ConnectionRefused,
        LastError::Timeout,
        LastError::TlsError,
        LastError::ChallengeFailed,
    ];
    for category in cases {
        let decision = sender_decision(&transport_attempt(category, 1, T0));
        assert_eq!(
            decision.action,
            SenderAction::Retry { next_at: T0 + 30 },
            "{category:?} was not retried"
        );
        assert_eq!(decision.last_error, Some(category));
    }
}

#[test]
fn internal_outcomes_map_to_the_closed_list() {
    let cases = [
        ("blocked_address", Some(LastError::ConnectionRefused)),
        ("dns_rebinding", Some(LastError::ConnectionRefused)),
        ("connection_refused", Some(LastError::ConnectionRefused)),
        ("redirect_refused", Some(LastError::Http4xx)),
        ("timeout", Some(LastError::Timeout)),
        ("tls_error", Some(LastError::TlsError)),
        ("challenge_failed", Some(LastError::ChallengeFailed)),
        ("something_else", None),
        ("", None),
    ];
    for (outcome, expected) in cases {
        assert_eq!(map_internal_outcome(outcome), expected, "outcome {outcome}");
    }
}

#[test]
fn last_error_wire_spellings_are_the_closed_list() {
    let cases = [
        (LastError::ConnectionRefused, "connection_refused"),
        (LastError::Timeout, "timeout"),
        (LastError::TlsError, "tls_error"),
        (LastError::Http4xx, "http_4xx"),
        (LastError::Http5xx, "http_5xx"),
        (LastError::ChallengeFailed, "challenge_failed"),
    ];
    for (category, spelling) in cases {
        assert_eq!(category.as_str(), spelling);
    }
}

#[test]
fn last_error_of_classifies_each_range() {
    let cases = [
        (100, None),
        (199, None),
        (200, None),
        (204, None),
        (299, None),
        (300, Some(LastError::Http4xx)),
        (399, Some(LastError::Http4xx)),
        (400, Some(LastError::Http4xx)),
        (499, Some(LastError::Http4xx)),
        (500, Some(LastError::Http5xx)),
        (599, Some(LastError::Http5xx)),
        (600, None),
    ];
    for (status, expected) in cases {
        assert_eq!(last_error_of(status), expected, "status {status}");
    }
}

#[test]
fn freshness_boundaries_are_the_pinned_300_seconds() {
    let now = T0;
    let window = 300;
    let cases: [(i64, Option<(&str, u16)>); 4] = [
        (now - 300, None),
        (now - 301, Some(("stale_timestamp", 401))),
        (now + 300, None),
        (now + 301, Some(("future_timestamp", 401))),
    ];
    for (timestamp, expected) in cases {
        match (freshness(now, timestamp, window), expected) {
            (Ok(()), None) => {}
            (Ok(()), Some((code, _))) => {
                panic!("timestamp {timestamp} was accepted, expected {code}")
            }
            (Err(error), None) => panic!("timestamp {timestamp} was rejected: {error}"),
            (Err(error), Some((code, status))) => {
                assert_eq!(error.code, code, "timestamp {timestamp}");
                assert_eq!(error.http_status, status, "timestamp {timestamp}");
            }
        }
    }
}

#[test]
fn a_negative_window_admits_only_the_same_instant() {
    assert_eq!(freshness(T0, T0, -1).map_err(|error| error.code), Ok(()));
    assert_eq!(
        freshness(T0, T0 - 1, -1).map_err(|error| error.code),
        Err("stale_timestamp")
    );
}
