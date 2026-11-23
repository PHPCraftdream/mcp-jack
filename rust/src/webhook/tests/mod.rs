//! Unit tests of the webhook profile (spec 06 section 2).
//!
//! `signing` covers the secret layer, `delivery` the sender schedule,
//! `subscription` the subscription key, TTL and envelope bodies, and `w1` the
//! Jack signature.

mod delivery;
mod signing;
mod subscription;
mod w1;
