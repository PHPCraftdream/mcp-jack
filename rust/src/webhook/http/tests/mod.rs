//! In-crate unit tests of the hardened HTTP delivery path (spec 06
//! R6.8-R6.10, R1.7, R1.9).
//!
//! Every test here is pure: a scripted resolver, a recording transport and a
//! recording clock stand in for DNS, the wire and time, so no socket is
//! opened, no Tokio runtime is built and no wall clock is read. The module is
//! compiled by `cargo check --all-targets` and is never executed by the check
//! commands.

mod rebinding;
mod verification;
