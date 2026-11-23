//! The bounded HTTP entry point of the receiver (spec 06 R1.2, R3.6, R3.8,
//! R5.6): the one place where a live `http` request body becomes the header
//! list and raw bytes [`crate::webhook::receiver::Receiver::handle`] judges.
//!
//! [`accept`] is the receiver half of the adapters in [`super::transport`]:
//! the adapters turn one request into the receiver's inputs and one outcome
//! into a response, and this module connects them over a streaming body. It
//! enforces the R1.2 byte cap while the frames arrive, so no framework glue
//! can hand an unbounded body to the receiver, and it reuses the receiver's
//! fixed rejection for a body that cannot be read.
//!
//! Everything is pure: `now` is an argument, the wire is an
//! [`http_body_util::BodyExt`] stream and the durable enqueue is the caller's
//! closure, so the entry point is driven from a stub body with no socket.

use bytes::Buf;
use http_body_util::BodyExt;

use crate::webhook::codes;
use crate::webhook::http::transport::{adapt_request, adapt_response, declared_length};
use crate::webhook::receiver::body::BodyCollector;
use crate::webhook::receiver::{rejection, DeliveryOutcome, EnqueueResult, Receiver};

/// The largest delivery body the entry point buffers (spec 06 R1.2, R3.6).
///
/// It is the receiver's own cap, re-exported so a framework adapter and the
/// receiver judge one number: the live path can neither buffer a body the
/// receiver would refuse nor refuse one the receiver accepts.
pub const RECEIVER_BODY_CAP: usize = crate::webhook::receiver::MAX_BODY_BYTES;

/// Reads one `http` delivery under the R1.2 cap and returns the receiver's
/// answer as an `http` response (spec 06 R1.2, R3.6, R3.8, R5.6).
///
/// The order is the receiver's own:
///
/// 1. the declared `Content-Length` is checked before the body is polled, so
///    an oversized declaration is refused with `413 body_too_large` without
///    reading a single frame and without calling `enqueue`
///    (spec 06 R1.2, R3.6);
/// 2. the body streams frame by frame into a [`BodyCollector`] capped at
///    [`RECEIVER_BODY_CAP`], so a body that crosses the cap is refused with
///    the same `413` even when the declaration understated it or was absent
///    (spec 06 R1.2);
/// 3. the headers are projected with
///    [`adapt_request`](super::transport::adapt_request), so the receiver
///    sees the header list and the declared length a framework adapter would
///    pass, and the buffered bytes go to
///    [`Receiver::handle`], which keeps every section 3 decision and the
///    durable enqueue (spec 06 R3.1-R3.18);
/// 4. the outcome is rendered by
///    [`adapt_response`](super::transport::adapt_response).
///
/// A body frame error is answered with the receiver's fixed
/// `400 malformed_body` rejection. That is an adapter decision, not a wire
/// answer: a real server aborts the connection when the body cannot be read,
/// so a client never receives this response. It exists only because this
/// function must return one answer value.
pub async fn accept<B, F>(
    receiver: &Receiver,
    now: i64,
    request: ::http::Request<B>,
    enqueue: F,
) -> ::http::Response<::bytes::Bytes>
where
    B: BodyExt + Unpin,
    F: FnOnce(&[serde_json::Value]) -> EnqueueResult,
{
    let (parts, body) = request.into_parts();
    // R1.2, R3.6: the declaration is judged before a single frame is polled,
    // so a refused delivery reads no body at all.
    let declared = declared_length(&parts.headers);
    let mut collector = match BodyCollector::new(RECEIVER_BODY_CAP) {
        Ok(collector) => collector,
        Err(error) => return adapt_response(&DeliveryOutcome::from_error(&error)),
    };
    if let Err(error) = collector.check_declared(declared) {
        return adapt_response(&DeliveryOutcome::from_error(&error));
    }
    // R3.1, R3.6: the receiver reads the same header list a framework adapter
    // projects, and derives the declared length from it again.
    let headers = adapt_request(&::http::Request::from_parts(parts, ()), Vec::new()).0;
    let mut body = body;
    // R1.2: every data frame is pushed whole, so a chunk that would cross the
    // cap is refused before any of it is buffered. A trailer frame carries no
    // body byte and is skipped.
    while let Some(frame) = body.frame().await {
        let frame = match frame {
            Ok(frame) => frame,
            Err(_) => {
                return adapt_response(&DeliveryOutcome::from_error(&rejection(
                    codes::MALFORMED_BODY,
                )))
            }
        };
        let Ok(mut data) = frame.into_data() else {
            continue;
        };
        // The frame's buffer is taken whole, so a body that arrives as
        // `Bytes` is never copied on the way into the collector.
        let length = data.remaining();
        if let Err(error) = collector.push(&data.copy_to_bytes(length)) {
            return adapt_response(&DeliveryOutcome::from_error(&error));
        }
    }
    adapt_response(&receiver.handle(now, &headers, &collector.finish(), enqueue))
}
