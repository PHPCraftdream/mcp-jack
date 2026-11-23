//! Unit tests of the acknowledgement state machine (spec 06 R1.10) and the
//! `webhook-id` deduplication it keys on (spec 06 R3.16).
//!
//! Every test drives one receiver through `handle` with a counting enqueue
//! callback, so the observable facts are the answer bodies, the recorded ids
//! and the number of enqueue calls.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use serde_json::json;

use crate::webhook::receiver::tests::{
    headers, receiver, secret, verification_body, CHALLENGE, EVENT_BODY, NOW, OTHER_WEBHOOK_ID,
    SUBSCRIPTION_ID, WEBHOOK_ID,
};
use crate::webhook::receiver::{DeliveryOutcome, Receiver, ReceiverConfig, ReceiverSecret};
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
///
/// The overlap is forced and observed, not hoped for: the first delivery
/// signals from inside its enqueue and then blocks there, so it owns the
/// reservation for as long as the test keeps it blocked; the second delivery
/// is spawned only after that signal, and the test then checks that it has NOT
/// answered within a bound. That absence is the proof that the second delivery
/// sits inside `Dispatch::reserve` while the first owns the id, which a plain
/// race between two spawned threads never establishes (spec 06 R1.10).
#[test]
fn concurrent_deliveries_of_one_id_enqueue_once() {
    /// How long the test waits for a signal it is certain will arrive
    /// (spec 06 R1.10).
    const GENEROUS: Duration = Duration::from_secs(5);
    /// How long the second delivery must stay unfinished while the first owns
    /// the reservation (spec 06 R1.10).
    const BLOCKED: Duration = Duration::from_millis(200);

    let receiver = receiver();
    let calls = AtomicUsize::new(0);
    // The first delivery's enqueue announces that it entered, then waits for
    // the test to release it.
    let (entered_tx, entered_rx) = mpsc::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    // The second delivery posts its answer here, so the test can tell whether
    // it finished while the first owned the id.
    let (second_tx, second_rx) = mpsc::channel::<DeliveryOutcome>();

    let (first, second) = std::thread::scope(|scope| {
        let receiver = &receiver;
        let calls = &calls;
        let first = scope.spawn(move || {
            receiver.handle(
                NOW,
                &headers(WEBHOOK_ID, EVENT_BODY),
                EVENT_BODY,
                |_messages| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    entered_tx.send(()).expect("the test waits for the enqueue");
                    release_rx
                        .recv_timeout(GENEROUS)
                        .expect("the test releases the blocked enqueue");
                    Ok(())
                },
            )
        });
        entered_rx
            .recv_timeout(GENEROUS)
            .expect("the first delivery reaches its enqueue");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(receiver.snapshot().accepted.is_empty());

        // The first delivery now owns the reservation, so this delivery of the
        // same id can only wait inside `Dispatch::reserve`.
        let second = scope.spawn(move || {
            let outcome = receiver.handle(
                NOW,
                &headers(WEBHOOK_ID, EVENT_BODY),
                EVENT_BODY,
                |_messages| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                },
            );
            second_tx
                .send(outcome.clone())
                .expect("the test waits for the second answer");
            outcome
        });
        assert!(
            second_rx.recv_timeout(BLOCKED).is_err(),
            "the second delivery answered while the first owned the reservation"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        release_tx
            .send(())
            .expect("the first delivery waits for the release");
        let first = first.join().expect("the first delivery thread finished");
        let second = second.join().expect("the second delivery thread finished");
        (first, second)
    });

    assert_eq!(calls.load(Ordering::SeqCst), 1);
    // The owner enqueued and was accepted; the waiter found the recorded id
    // and answered `duplicate` without calling the callback (spec 06 R3.16).
    assert_eq!(first.status, 200);
    assert_eq!(first.body, json!({ "status": "accepted" }));
    assert!(first.recorded);
    assert_eq!(second.status, 200);
    assert_eq!(second.body, json!({ "status": "duplicate" }));
    assert!(!second.recorded);
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

/// A delivery a pending secret authenticates but that is not a verification
/// envelope is refused `503 subscription_not_routed` before the callback
/// runs, so an unrouted event is never durably enqueued
/// (spec 06 R3.8, R5.6, R1.10).
#[test]
fn a_pending_secret_refuses_a_non_verification_body_without_enqueueing() {
    let receiver = pending_receiver();
    let calls = AtomicUsize::new(0);

    let refused = receiver.handle(
        NOW,
        &headers(WEBHOOK_ID, EVENT_BODY),
        EVENT_BODY,
        |_messages| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
    );
    assert_eq!(refused.status, 503);
    assert_eq!(
        refused.code.as_deref(),
        Some(codes::SUBSCRIPTION_NOT_ROUTED)
    );
    assert_eq!(
        refused.body,
        json!({
            "error": {
                "code": codes::SUBSCRIPTION_NOT_ROUTED,
                "message": "the subscription is not routed",
            }
        })
    );
    assert!(refused.delivered.is_empty());
    assert!(!refused.recorded);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let snapshot = receiver.snapshot();
    assert!(snapshot.accepted.is_empty());
    assert!(snapshot.routed.is_empty());
    assert_eq!(snapshot.secrets.len(), 1);
    assert_eq!(snapshot.secrets[0].subscription_id, None);

    // The verification envelope is the one body the pending entry may carry:
    // it answers its challenge, binds the entry and routes the id
    // (spec 06 R5.6, R3.18).
    let body = verification_body();
    let verified = receiver.handle(NOW, &headers(OTHER_WEBHOOK_ID, &body), &body, |_messages| {
        calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    });
    assert_eq!(verified.status, 200);
    assert_eq!(verified.body, json!({ "challenge": CHALLENGE }));
    assert!(verified.recorded);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let snapshot = receiver.snapshot();
    assert_eq!(snapshot.accepted, vec![OTHER_WEBHOOK_ID.to_owned()]);
    assert_eq!(snapshot.routed, vec![SUBSCRIPTION_ID.to_owned()]);
    assert_eq!(
        snapshot.secrets[0].subscription_id.as_deref(),
        Some(SUBSCRIPTION_ID)
    );
}

/// Builds one receiver with a single pending secret and no routed id
/// (spec 06 R3.7, R5.6).
fn pending_receiver() -> Receiver {
    Receiver::new(ReceiverConfig {
        secrets: vec![ReceiverSecret {
            secret: secret(),
            subscription_id: None,
            callback_url: None,
        }],
        ..ReceiverConfig::default()
    })
    .expect("the default receiver configuration is valid")
}
