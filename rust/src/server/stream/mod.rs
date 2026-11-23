//! Server-side signed-stream engine of spec 05 sections 3 and 5.1: the
//! deployment options (3.2-3.5), the per-identity admission registry (3.3),
//! the frame pump that signs a handler's SSE body and the 6.3 close shapes.
//!
//! Everything here is transport-free and builds with `--no-default-features`.
//! The HTTP adapter signs the open header; [`StreamPipe`] resumes the chain
//! from that signature and writes only signed frames: ordinary handler
//! messages, the 2.18 oversize signal, the 6.3 final response and the end
//! frame. Every timestamp comes from the caller, so the bytes are
//! deterministic.

mod close;
mod options;
mod pipe;
mod registry;

#[cfg(test)]
mod tests;

pub use close::{events_stream_result, is_final_response};
pub use options::{StreamLimits, StreamOptions};
pub use pipe::{PipeStop, StreamPipe, StreamPipeConfig};
pub use registry::{StreamRegistry, StreamSlot};
