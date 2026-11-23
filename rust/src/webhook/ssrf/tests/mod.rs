//! In-crate unit tests of the SSRF layer (spec 06 section 6, R6.1-R6.11, and
//! the R5.11 dot-segment rule).
//!
//! Everything is pure: no resolver, no socket and no file is touched, so the
//! modules are compiled by `cargo check --all-targets` and never executed.

mod classification;
mod url_and_delivery;
