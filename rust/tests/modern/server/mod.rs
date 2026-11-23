//! Wire-level tests of the modern profile: the HTTP adapter (`C7`, `S1`-`S12`)
//! and the client-side rules that need a socket-free exchange.

#[path = "../../common/mod.rs"]
mod common;

mod native_result;
