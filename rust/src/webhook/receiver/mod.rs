//! The framework-neutral receiver of spec 06 section 3 (R3.1-R3.18), plus
//! R1.2, R1.10, R5.6, R7.6 and R4.5/R4.6: the receiving building block, not a
//! subscription service.
//!
//! The wrapped MCP server owns subscriptions, events and cursors: it decides
//! what to subscribe to, produces the events it publishes and keeps the cursor
//! a `gap` envelope reports. This module owns none of that. It accepts one
//! delivery, verifies it, hands the parsed message to the caller's durable
//! enqueue and renders the section 3 answer, so an embedder can put it behind
//! any HTTP framework.
//!
//! Four pieces make up the receiver: the bounded body collector of R1.2
//! ([`body`]), the closed code, status and fixed-message table ([`errors`]),
//! the configuration it is built from ([`config`]) and the state machine
//! itself ([`state`], over the one lock and condition variable of
//! [`dispatch`]). Everything is pure and deterministic: `now` is an argument,
//! the caller supplies the headers, the raw body bytes and the durable-enqueue
//! callback, and an error carries only a wire code and a fixed literal, never
//! a secret, a header value or a body byte (spec 06 section 3). The modules
//! mirror `spec/tools/modern/webhooks/ref/receiver.mjs` exactly.

pub mod body;
pub mod config;
mod dispatch;
pub mod errors;
pub mod state;

// Visible crate-wide so the HTTP entry-point tests drive the same signed
// fixtures as the receiver's own tests (spec 06 R1.1, R2.2).
#[cfg(test)]
pub(crate) mod tests;

pub use body::BodyCollector;
pub use config::{JackConfig, ReceiverConfig, ReceiverSecret};
pub use errors::{
    code_is_retryable, code_last_error, code_status, rejection, DeliveryOutcome, MAX_BODY_BYTES,
};
pub use state::{EnqueueResult, Receiver, ReceiverSecretView, ReceiverSnapshot};
