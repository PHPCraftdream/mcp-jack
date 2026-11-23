//! Server-side state, identity, verification, native tools and HTTP adapter.

pub mod audit;
#[cfg(target_os = "linux")]
mod durable;
#[cfg(feature = "http")]
pub mod http;
pub mod identity;
pub mod modern;
pub mod native;
mod registry;
pub mod response_keys;
#[cfg(target_os = "linux")]
pub mod server_key;
pub mod verify;

#[cfg(target_os = "linux")]
pub use durable::{durable_admission, durable_format, durable_recovery, durable_store};
pub use registry::{nonce, state, state_file};
