//! In-crate unit tests of the hardened HTTP delivery path (spec 06
//! R6.8-R6.10, R1.7, R1.9) and of the bounded receiver entry point
//! (spec 06 R1.2, R3.6, R3.18).
//!
//! Every test here is pure: a scripted resolver, a recording transport and a
//! recording clock stand in for DNS, the wire and time, and the entry-point
//! tests drive a stub body stream, so no socket is opened, no DNS server is
//! asked and no wall clock is read. The module is compiled by `cargo check
//! --all-targets` and is never executed by the check commands; the entry-point
//! tests build a Tokio runtime only to poll the body futures of `accept`.

mod deadline;
mod entry;
mod rebinding;
mod verification;
