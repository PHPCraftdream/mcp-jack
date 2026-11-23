//! HTTP-facing webhook layer of spec 06 sections 1, 5 and 6: the sender
//! attempt loop (R1.6-R1.10), the hardened delivery decision and connect
//! target of section 6 (R6.8-R6.10), the R1.1 header set, and the adapters
//! between `http` requests/responses and the framework-neutral receiver.
//!
//! Two feature levels gate the folder, because the pieces have different
//! dependency needs:
//!
//! * The orchestration, the transport traits and the receiver adapters use
//!   only the `http` and `bytes` crates, so they live behind the crate's
//!   `http` feature (`transport`).
//! * The real TLS/TCP transport needs `hyper`, `tokio`, `tokio-rustls` and
//!   `hickory-resolver`, which this crate enables only through its
//!   `client-http` feature. `https` is therefore gated on `client-http` on
//!   top of the `http` gate of this module: a build with `http` alone keeps
//!   the pure layer and leaves the network implementation out.
//!
//! Everything in the pure layer is deterministic: `now` and sleep come from
//! a [`transport::Clock`], DNS answers from a [`transport::HostResolver`] and
//! the wire from a [`transport::WebhookTransport`], so the R1.8 schedule can
//! be exercised without a socket.

#[cfg(feature = "client-http")]
pub mod https;
pub mod transport;

#[cfg(all(test, feature = "http"))]
mod tests;

#[cfg(feature = "client-http")]
pub use https::{HttpsTransport, SystemResolver};
pub use transport::{
    adapt_request, adapt_response, delivery_headers, prepare, Clock, HostResolver, OutgoingMessage,
    PreparedRequest, SendAction, SendOutcome, Sender, SenderConfig, TransportFailure,
    TransportRequest, TransportResponse, WebhookTransport, JACK_WINDOW_SECONDS,
};
