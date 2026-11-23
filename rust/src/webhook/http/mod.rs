//! HTTP-facing webhook layer of spec 06 sections 1, 5 and 6: the sender
//! attempt loop (R1.6-R1.10), the fail-closed per-pair verification of
//! section 5 (R5.1, R5.2, R5.9, R5.12), the hardened delivery decision and
//! connect target of section 6 (R6.8-R6.10), the R1.1 header set, and the
//! adapters and the bounded entry point between `http` requests/responses and
//! the framework-neutral receiver (R1.2, R3.6).
//!
//! The folder is split by dependency need, and the features follow exactly
//! that split:
//!
//! * The spawn-free orchestration lives behind the crate's `http` feature:
//!   [`transport`] holds the traits, [`prepare`] and the request/response
//!   types, [`sender`] holds the R1.8 loop and the R5.1 gate, [`document`]
//!   holds the R5.9 fetcher over an injected transport, and [`transport`]
//!   also holds the receiver adapters. [`entry`] adds the bounded receiver
//!   entry point of R1.2 and R3.6 over those adapters. These files use only
//!   the `http`, `bytes` and `http-body-util` crates and spawn nothing.
//! * The concrete dialer — [`https::SystemResolver`] and
//!   [`https::HttpsTransport`] — needs `hyper`, `tokio`, `tokio-rustls` and
//!   `hickory-resolver`, which this crate enables only through its
//!   `client-http` feature. [`https`] is therefore `#[cfg(feature =
//!   "client-http")]` on top of this module's own `http` gate: a build with
//!   `http` alone has no dialer and must inject a [`transport::WebhookTransport`]
//!   and a [`transport::HostResolver`].
//!
//! Everything in the pure layer is deterministic: `now` and sleep come from a
//! [`sender::Clock`], DNS answers from a [`transport::HostResolver`], the wire
//! from a [`transport::WebhookTransport`] and the verification status from a
//! [`crate::webhook::verification::gate::EndpointVerifier`], so the R1.8
//! schedule and the R5.1 gate can be exercised without a socket.

pub mod document;
pub mod entry;
pub mod sender;
pub mod transport;

#[cfg(feature = "client-http")]
pub mod https;

#[cfg(all(test, feature = "http"))]
mod tests;

pub use document::WebhookDocumentFetcher;
pub use entry::{accept, RECEIVER_BODY_CAP};
#[cfg(feature = "client-http")]
pub use https::{HttpsTransport, SystemResolver};
pub use sender::{
    delivery_headers, Clock, OutgoingMessage, SendAction, SendOutcome, Sender, SenderConfig,
    JACK_WINDOW_SECONDS,
};
pub use transport::{
    adapt_request, adapt_response, prepare, FailureKind, HostResolver, PreparedRequest,
    TransportFailure, TransportRequest, TransportResponse, WebhookTransport,
    ATTEMPT_TIMEOUT_SECONDS, CONNECT_TIMEOUT_SECONDS, MAX_DOCUMENT_BYTES, RESPONSE_TIMEOUT_SECONDS,
};
