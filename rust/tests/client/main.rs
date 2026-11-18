//! Client integration tests: signing transport, tools, URL policy, the HTTP
//! adapter and rotation over HTTP.

#[path = "../common/mod.rs"]
mod common;

mod http_transport;
mod rotation_http;
mod sign;
mod signer;
mod tools;
mod transport;
mod url_policy;
