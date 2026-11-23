//! Client-side signed-stream opt-in (`s1`) of spec 05: the transport-facing
//! stream source, the incremental body and the verified stream the consumer
//! iterates.
//!
//! The verifier itself lives in [`crate::stream`]; this module only routes a
//! response (1.4), drives it with a body and hands out the data values that
//! passed verification (4.7). Everything here is transport-free: a concrete
//! HTTP client implements [`StreamSource`] and [`StreamBody`] behind the
//! `client-http` feature.

mod source;
mod verified;

#[cfg(test)]
mod tests;

pub use source::{ChunkRead, StreamBody, StreamResponse, StreamSource};
pub use verified::VerifiedStream;
