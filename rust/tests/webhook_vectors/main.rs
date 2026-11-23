//! Conformance runner for the webhook vector corpora of `spec/06-webhooks.md`,
//! committed as `spec/fixtures/modern/webhook-*-vectors.json`.
//!
//! One module per corpus family; every case of a corpus is driven, nothing is
//! skipped, and each runner prints a `VECTOR-SUMMARY` line with `println!`.
//! A case the SDK cannot pass fails its test instead of being excluded.

mod common;
mod endpoint_family;
mod receiver_family;
mod signature_family;
