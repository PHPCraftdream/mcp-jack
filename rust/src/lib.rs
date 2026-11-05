#![forbid(unsafe_code)]

//! Server-side Rust SDK for mcp-jack, the secure transport protocol wrapping
//! MCP: authentication, authorization and audit. The JSON fixtures under
//! ../spec/fixtures are the conformance source of truth; this crate mirrors
//! the Go jack + server packages.

pub mod auth_header;
pub mod client;
pub mod ed25519;
pub mod encoding;
pub mod error;
pub mod server;
pub mod signing;
pub mod syntax;
