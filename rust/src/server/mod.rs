//! Server-side state, identity, verification, native tools and HTTP adapter.

pub mod audit;
pub mod identity;
pub mod native;
pub mod nonce;
pub mod response_keys;
#[cfg(target_os = "linux")]
pub mod server_key;
pub mod state;
pub mod state_file;
pub mod verify;

#[cfg(target_os = "linux")]
pub mod durable_admission;
#[cfg(target_os = "linux")]
pub mod durable_format;
#[cfg(target_os = "linux")]
pub mod durable_recovery;
#[cfg(target_os = "linux")]
pub mod durable_store;
#[cfg(all(test, target_os = "linux"))]
mod durable_store_tests;

#[cfg(feature = "http")]
pub mod http;
