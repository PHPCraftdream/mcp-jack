//! Tests of the bounded HTTP entry point of the receiver (spec 06 R1.2,
//! R3.6, R3.18).
//!
//! Every test drives the real [`accept`] over a stub body: [`Full`] carries
//! one chunk, [`Empty`] carries none, [`Either`] is the one-of-two body type a
//! framework adapter hands over, and [`Channel`] streams the buffers of one
//! delivery as separate data frames. `Either` selects one of its two bodies
//! rather than concatenating them, so the frame-by-frame cap checks are driven
//! through `Channel`, whose `send_data` buffers one frame per call; no socket,
//! no DNS server and no server runtime is involved. `#[tokio::test]` drives
//! the body futures, because `tokio` is a dev-dependency of this crate with
//! `rt` and `macros`.
//!
//! The signed fixtures are the receiver's own, so the accepted delivery is
//! signed exactly as the R3.13 tests sign it (spec 06 R2.2, R3.13).

use std::cell::{Cell, RefCell};

use bytes::Bytes;
use http_body_util::channel::Channel;
use http_body_util::{Either, Empty, Full};
use serde_json::{json, Value};

use crate::webhook::codes;
use crate::webhook::http::entry::{accept, RECEIVER_BODY_CAP};
use crate::webhook::receiver::tests::{headers, receiver, EVENT_BODY, NOW, WEBHOOK_ID};

/// Builds one `POST` request from a header list and a stub body
/// (spec 06 R3.1).
fn request<B>(pairs: &[(String, String)], body: B) -> ::http::Request<B> {
    let mut builder = ::http::Request::builder()
        .method("POST")
        .uri("https://example.test/hooks/alice");
    for (name, value) in pairs {
        builder = builder.header(name.as_str(), value.as_str());
    }
    builder.body(body).expect("the stub request is well formed")
}

/// Splits `body` in two halves, the frame boundaries of the multi-frame tests
/// (spec 06 R3.6).
fn halves(body: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let middle = body.len() / 2;
    (body[..middle].to_vec(), body[middle..].to_vec())
}

/// Builds the stub body that yields exactly two data frames, one per half
/// (spec 06 R3.6).
///
/// The channel buffers both frames before the sender is dropped, so the entry
/// point reads two chunks and then the end of the stream, exactly as a
/// chunked request would deliver them.
async fn framed(first: Vec<u8>, second: Vec<u8>) -> Channel<Bytes> {
    let (mut sender, body) = Channel::<Bytes>::new(2);
    sender
        .send_data(Bytes::from(first))
        .await
        .expect("the channel has capacity for the first frame");
    sender
        .send_data(Bytes::from(second))
        .await
        .expect("the channel has capacity for the second frame");
    drop(sender);
    body
}

/// Returns the JSON body of one answer (spec 06 section 3).
fn body_of(response: &::http::Response<Bytes>) -> Value {
    serde_json::from_slice(response.body()).expect("the answer body is JSON")
}

/// Returns the receiver code of one rejection answer (spec 06 section 3).
fn code_of(response: &::http::Response<Bytes>) -> String {
    body_of(response)["error"]["code"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

/// An oversized declared `Content-Length` is `413 body_too_large` before any
/// frame is polled: the enqueue closure never runs (spec 06 R1.2, R3.6).
#[tokio::test]
async fn r1_2_an_oversized_declaration_is_refused_before_the_body() {
    let receiver = receiver();
    let calls = Cell::new(0usize);
    let mut pairs = headers(WEBHOOK_ID, EVENT_BODY);
    pairs.push((
        "content-length".to_owned(),
        (RECEIVER_BODY_CAP + 1).to_string(),
    ));

    let response = accept(
        &receiver,
        NOW,
        request(&pairs, Full::new(Bytes::from_static(EVENT_BODY))),
        |_messages| {
            calls.set(calls.get() + 1);
            Ok(())
        },
    )
    .await;

    assert_eq!(response.status(), ::http::StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(code_of(&response), codes::BODY_TOO_LARGE);
    assert_eq!(calls.get(), 0);
    assert!(receiver.snapshot().accepted.is_empty());
}

/// A body above the cap delivered in two frames with no declared length is
/// `413 body_too_large` on the second frame: the enqueue closure never runs
/// (spec 06 R1.2).
#[tokio::test]
async fn r1_2_an_oversized_body_is_refused_frame_by_frame() {
    let receiver = receiver();
    let calls = Cell::new(0usize);
    let half = vec![b'a'; 200_000];
    let body = framed(half.clone(), half).await;

    let response = accept(&receiver, NOW, request(&[], body), |_messages| {
        calls.set(calls.get() + 1);
        Ok(())
    })
    .await;

    assert_eq!(response.status(), ::http::StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(code_of(&response), codes::BODY_TOO_LARGE);
    assert_eq!(calls.get(), 0);
    assert!(receiver.snapshot().accepted.is_empty());
}

/// A body of exactly [`RECEIVER_BODY_CAP`] bytes in two frames, with a
/// matching declared length, reaches the receiver and is accepted
/// (spec 06 R1.2, R3.6, R3.18).
#[tokio::test]
async fn r1_2_a_body_of_exactly_the_cap_is_accepted() {
    let receiver = receiver();
    let calls = Cell::new(0usize);
    let mut body = EVENT_BODY.to_vec();
    // Trailing JSON whitespace pads the occurrence to the cap without changing
    // the parsed message (spec 06 R3.18).
    body.resize(RECEIVER_BODY_CAP, b' ');
    assert_eq!(body.len(), RECEIVER_BODY_CAP);
    let mut pairs = headers(WEBHOOK_ID, &body);
    pairs.push(("content-length".to_owned(), RECEIVER_BODY_CAP.to_string()));
    let (first, second) = halves(&body);

    let response = accept(
        &receiver,
        NOW,
        request(&pairs, framed(first, second).await),
        |messages| {
            calls.set(calls.get() + 1);
            assert_eq!(messages.len(), 1);
            Ok(())
        },
    )
    .await;

    assert_ne!(response.status(), ::http::StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(response.status(), ::http::StatusCode::OK);
    assert_eq!(body_of(&response), json!({ "status": "accepted" }));
    assert_eq!(calls.get(), 1);
    assert_eq!(receiver.snapshot().accepted, vec![WEBHOOK_ID.to_owned()]);
}

/// One valid signed delivery is `200 {"status":"accepted"}` and calls the
/// enqueue closure exactly once with the parsed message (spec 06 R3.13,
/// R3.18).
#[tokio::test]
async fn r3_18_a_valid_signed_delivery_is_enqueued_once() {
    let receiver = receiver();
    let calls = Cell::new(0usize);
    let delivered = RefCell::new(Vec::new());
    // Either is the one-of-two body type an adapter hands over; the left
    // variant is the single-chunk body of this delivery.
    let body: Either<Full<Bytes>, Full<Bytes>> =
        Either::Left(Full::new(Bytes::from_static(EVENT_BODY)));

    let response = accept(
        &receiver,
        NOW,
        request(&headers(WEBHOOK_ID, EVENT_BODY), body),
        |messages| {
            calls.set(calls.get() + 1);
            delivered.borrow_mut().extend_from_slice(messages);
            Ok(())
        },
    )
    .await;

    assert_eq!(response.status(), ::http::StatusCode::OK);
    assert_eq!(body_of(&response), json!({ "status": "accepted" }));
    assert_eq!(calls.get(), 1);
    let expected: Value =
        serde_json::from_slice(EVENT_BODY).expect("the fixture body is a JSON object");
    assert_eq!(delivered.borrow().clone(), vec![expected]);
    assert_eq!(receiver.snapshot().accepted, vec![WEBHOOK_ID.to_owned()]);
}

/// A body with no frame at all is read to its end and judged by the receiver,
/// so the entry point answers the receiver's own rejection rather than a
/// collection error (spec 06 R3.1).
#[tokio::test]
async fn an_empty_body_reaches_the_receiver() {
    let receiver = receiver();
    let calls = Cell::new(0usize);

    let response = accept(
        &receiver,
        NOW,
        request(&[], Empty::<Bytes>::new()),
        |_messages| {
            calls.set(calls.get() + 1);
            Ok(())
        },
    )
    .await;

    assert_eq!(response.status(), ::http::StatusCode::BAD_REQUEST);
    assert_eq!(code_of(&response), codes::MISSING_WEBHOOK_HEADER);
    assert_eq!(calls.get(), 0);
}
