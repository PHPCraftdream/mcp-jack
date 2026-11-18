//! Server-side rotation provider and ring store (Linux only).

use super::*;

pub(in crate::rotation) mod server_provider;
#[cfg(test)]
mod server_provider_tests;
pub(in crate::rotation) mod server_store;
pub(in crate::rotation) mod server_store_format;
#[cfg(test)]
mod server_store_tests;
