//! Runners for the four generated corpora of `spec/fixtures/modern`.

mod annotations;
mod encoding;
mod era;
mod fixtures;
mod request;
#[cfg(feature = "http")]
mod wire_request;
