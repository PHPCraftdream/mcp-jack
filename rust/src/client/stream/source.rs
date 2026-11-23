//! The transport-facing stream surface of spec 05: one opened stream response,
//! the incremental body trait and the source trait that opens it (sections 1.1,
//! 1.4 and 3.7). No HTTP type appears here, exactly like [`crate::client::transport`].

use crate::client::transport::{HttpRequest, TransportError};

/// One opened stream response: the response head plus an incremental body.
pub struct StreamResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Box<dyn StreamBody + Send>,
}

/// One incremental body read.
#[derive(Debug)]
pub enum ChunkRead {
    Data(Vec<u8>),
    Timeout,
    End,
}

/// Incremental response body. Dropping it closes the connection, which is the client's stream
/// cancellation (spec 05 section 3.7 / 7: "on HTTP the client cancels by closing the stream").
pub trait StreamBody: Send {
    /// Returns the next chunk, or `Timeout` when `deadline` passes first. `Data`/`End` are final
    /// answers, `Timeout` means the stream is still open and silent.
    fn next_chunk(&mut self, deadline: std::time::Instant) -> Result<ChunkRead, TransportError>;
}

/// Opens one request and returns its head plus an incremental body; never follows redirects
/// (the same obligations as `Transport`).
pub trait StreamSource: Send + Sync {
    fn open_stream(&self, req: HttpRequest) -> Result<StreamResponse, TransportError>;
}
