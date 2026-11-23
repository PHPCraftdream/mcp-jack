//! Modern-profile conformance: the generated spec 04 vectors (request
//! classification, value encoding, `x-mcp-header` validation and projection,
//! era detection), the rule exemptions the spec assigns to SDK tests, and the
//! wire-level behaviour of the HTTP layer and the client in the modern era.

mod client;
mod server;
mod vectors;
