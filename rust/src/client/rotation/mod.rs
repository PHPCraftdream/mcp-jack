//! Rotation carrier verification and the rotation HTTP client.

pub mod rotation_auth;
#[cfg(all(target_os = "linux", feature = "client-http"))]
pub mod rotation_http;
