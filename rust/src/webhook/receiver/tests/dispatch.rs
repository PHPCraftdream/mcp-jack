//! Unit tests of the acknowledgement state machine (spec 06 R1.10) and the
//! `webhook-id` deduplication it keys on (spec 06 R3.16).
//!
//! Every test drives one receiver through `handle` with a counting enqueue
//! callback, so the observable facts are the answer bodies, the recorded ids
//! and the number of enqueue calls.

use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::json;

use crate::webhook::receiver::tests::{
    headers, receiver, verification_body, CHALLENGE, EVENT_BODY, NOW, OTHER_WEBHOOK_ID, WEBHOOK_ID,
};
use crate::webhook::{codes, WebhookError};

/// The `enqueue_failed` rejection a failing callback returns
/// (spec 06 R1.10, R3.17).
fn failed_enqueue() -> WebhookError {
    WebhookError::new(503, codes::ENQUEUE_FAILED, "durable enqueue failed")
}

/// A successful enqueue records the id, and a second identical delivery is
/// answered `duplicate` without calling the callback again
/// (spec 06 R1.10, R3.16).
#[test]
fn success_records_the_id_and_a_retry_is_duplicate() {
    let receiver = receiver();
    let calls = AtomicUsize::new(0);

    let first = receiver.handle(
        NOW,
        &headers(WEBHOOK_ID, EVENT_BODY),
        EVENT_BODY,
        |_messages| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
    );
    assert_eq!(first.status, 200);
    assert_eq!(first.body, json!({ "status": "accepted" }));
    assert_eq!(first.code, None);
    assert_eq!(first.delivered.len(), 1);
    assert!(first.recorded);

    let second = receiver.handle(
        NOW,
        &headers(WEBHOOK_ID, EVENT_BODY),
        EVENT_BODY,
        |_messages| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
    );
    assert_eq!(second.status, 200);
    assert_eq!(second.body, json!({ "status": "duplicate" }));
    assert!(second.delivered.is_empty());
    assert_eq!(second.code, None);
    assert!(!second.recorded);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(receiver.snapshot().accepted, vec![WEBHOOK_ID.to_owned()]);
}

/// A failed enqueue answers `503 enqueue_failed` and records nothing, so the
/// next identical delivery calls the callback again
/// (spec 06 R1.10, R3.17).
#[test]
fn a_failed_enqueue_answers_503_and_records_nothing() {
    let receiver = receiver();
    let calls = AtomicUsize::new(0);

    let failure = receiver.handle(
        NOW,
        &headers(WEBHOOK_ID, EVENT_BODY),
        EVENT_BODY,
        |_messages| {
            calls.fetch_add(1, Ordering::SeqCst);
            Err(failed_enqueue())
        },
    );
    assert_eq!(failure.status, 503);
    assert_eq!(failure.code.as_deref(), Some(codes::ENQUEUE_FAILED));
    assert_eq!(
        failure.body,
        json!({ "error": { "code": codes::ENQUEUE_FAILED, "message": "durable enqueue failed" } })
    );
    assert!(failure.delivered.is_empty());
    assert!(!failure.recorded);
    assert!(receiver.snapshot().accepted.is_empty());

    let retry = receiver.handle(
        NOW,
        &headers(WEBHOOK_ID, EVENT_BODY),
        EVENT_BODY,
        |_messages| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
    );
    assert_eq!(retry.status, 200);
    assert_eq!(retry.body, json!({ "status": "accepted" }));
    assert!(retry.recorded);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(receiver.snapshot().accepted, vec![WEBHOOK_ID.to_owned()]);
}

/// A failure for a later id keeps the `duplicate` answer of an earlier one
/// (spec 06 R1.10, R3.16).
#[test]
fn a_failure_for_one_id_keeps_the_duplicate_answer_of_another() {
    let receiver = receiver();
    let calls = AtomicUsize::new(0);

    let accepted = receiver.handle(
        NOW,
        &headers(WEBHOOK_ID, EVENT_BODY),
        EVENT_BODY,
        |_messages| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
    );
    assert_eq!(accepted.body, json!({ "status": "accepted" }));

    let failure = receiver.handle(
        NOW,
        &headers(OTHER_WEBHOOK_ID, EVENT_BODY),
        EVENT_BODY,
        |_messages| {
            calls.fetch_add(1, Ordering::SeqCst);
            Err(failed_enqueue())
        },
    );
    assert_eq!(failure.status, 503);
    assert!(!failure.recorded);

    let duplicate = receiver.handle(
        NOW,
        &headers(WEBHOOK_ID, EVENT_BODY),
        EVENT_BODY,
        |_messages| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
    );
    assert_eq!(duplicate.status, 200);
    assert_eq!(duplicate.body, json!({ "status": "duplicate" }));
    assert!(!duplicate.recorded);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(receiver.snapshot().accepted, vec![WEBHOOK_ID.to_owned()]);
}

/// Two threads delivering the same `webhook-id` enqueue exactly once and both
/// answer `2xx` (spec 06 R1.10, R3.16).
#[test]
fn concurrent_deliveries_of_one_id_enqueue_once() {
    let receiver = receiver();
    let calls = AtomicUsize::new(0);

    let outcomes = std::thread::scope(|scope| {
        let deliveries: Vec<_> = (0..2)
            .map(|_| {
                scope.spawn(|| {
                    receiver.handle(
                        NOW,
                        &headers(WEBHOOK_ID, EVENT_BODY),
                        EVENT_BODY,
                        |_messages| {
                            calls.fetch_add(1, Ordering::SeqCst);
                            Ok(())
                        },
                    )
                })
            })
            .collect();
        deliveries
            .into_iter()
            .map(|delivery| delivery.join().expect("the delivery thread finished"))
            .collect::<Vec<_>>()
    });

    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(outcomes.iter().all(|outcome| outcome.status == 200));
    let accepted = outcomes
        .iter()
        .filter(|outcome| outcome.body == json!({ "status": "accepted" }))
        .count();
    let duplicate = outcomes
        .iter()
        .filter(|outcome| outcome.body == json!({ "status": "duplicate" }))
        .count();
    assert_eq!((accepted, duplicate), (1, 1));
    assert_eq!(receiver.snapshot().accepted, vec![WEBHOOK_ID.to_owned()]);
}

/// A verification envelope answers its challenge without calling the
/// callback (spec 06 R5.6, R3.18).
#[test]
fn a_verification_envelope_answers_its_challenge_without_enqueueing() {
    let receiver = receiver();
    let calls = AtomicUsize::new(0);
    let body = verification_body();

    let outcome = receiver.handle(NOW, &headers(WEBHOOK_ID, &body), &body, |_messages| {
        calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    });
    assert_eq!(outcome.status, 200);
    assert_eq!(outcome.body, json!({ "challenge": CHALLENGE }));
    assert!(outcome.delivered.is_empty());
    assert!(outcome.recorded);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(receiver.snapshot().accepted, vec![WEBHOOK_ID.to_owned()]);
}

/// A rejected delivery releases its reservation, so the same id is processed
/// again from the start instead of being answered `duplicate`
/// (spec 06 R1.10, R3.16).
#[test]
fn a_rejected_delivery_is_not_recorded_and_is_retried() {
    let receiver = receiver();
    let calls = AtomicUsize::new(0);

    let malformed: &[u8] = b"{not json";
    let rejected = receiver.handle(
        NOW,
        &headers(WEBHOOK_ID, malformed),
        malformed,
        |_messages| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
    );
    assert_eq!(rejected.status, 400);
    assert_eq!(rejected.code.as_deref(), Some(codes::MALFORMED_BODY));
    assert!(!rejected.recorded);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(receiver.snapshot().accepted.is_empty());

    let accepted = receiver.handle(
        NOW,
        &headers(WEBHOOK_ID, EVENT_BODY),
        EVENT_BODY,
        |_messages| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
    );
    assert_eq!(accepted.status, 200);
    assert_eq!(accepted.body, json!({ "status": "accepted" }));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
