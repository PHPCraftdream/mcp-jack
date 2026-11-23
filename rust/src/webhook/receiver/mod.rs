//! The framework-neutral receiver state machine of spec 06 section 3
//! (R3.1-R3.18), plus R1.10, R5.6, R7.6 and R4.5/R4.6.
//!
//! Three pieces make up the receiver: the closed code, status and fixed-message
//! table ([`errors`]), the configuration it is built from ([`config`]) and the
//! state machine itself ([`state`]). Everything is pure and deterministic:
//! `now` is an argument, the caller supplies the headers, the raw body bytes and
//! the durable-enqueue verdict, and an error carries only a wire code and a
//! fixed literal, never a secret, a header value or a body byte
//! (spec 06 section 3). The modules mirror
//! `spec/tools/modern/webhooks/ref/receiver.mjs` exactly.

pub mod config;
pub mod errors;
pub mod state;

pub use config::{JackConfig, ReceiverConfig, ReceiverSecret};
pub use errors::{
    code_is_retryable, code_last_error, code_status, rejection, DeliveryOutcome, MAX_BODY_BYTES,
};
pub use state::{EnqueueOutcome, Receiver, ReceiverSecretView, ReceiverSnapshot};
