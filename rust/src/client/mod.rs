//! Client SDK for mcp-jack (Go: package client). The client signs every
//! outgoing request with an Ed25519 signer and verifies every response
//! against the pinned server public key before its body is returned (spec 01
//! sections 4 and 5). It speaks the protocol-native jack.* tools (spec 03
//! sections 3.1-3.3).

pub mod auth;
pub mod error;
#[cfg(feature = "client-http")]
pub mod http_transport;
pub mod profile;
pub mod rpc;
pub mod signer;
pub mod tools;
pub mod transport;
pub mod url;

pub use auth::{random_nonce, sign_request, SignedRequest, NONCE_SIZE};
pub use error::{ClientError, HttpError, RpcError, ToolError, UnauthenticatedResponseError};
#[cfg(feature = "client-http")]
pub use http_transport::{HttpTransport, HttpTransportBuilder};
pub use profile::{load_profile, save_profile, Profile};
pub use rpc::{Client, Config};
pub use signer::{InMemorySigner, Signer};
pub use tools::{
    EnrollResult, Entry, InviteCreateParams, InviteCreateResult, InviteListEntry,
    InviteRevokeResult, KidResult, UserCreateParams, WhoAmIResult, TOOL_ADMIN_INVITE_CREATE,
    TOOL_ADMIN_INVITE_LIST, TOOL_ADMIN_INVITE_REVOKE, TOOL_ADMIN_USER_CREATE, TOOL_ADMIN_USER_GET,
    TOOL_ADMIN_USER_LIST, TOOL_ADMIN_USER_REVOKE, TOOL_ADMIN_USER_SET_ADMIN, TOOL_ENROLL,
    TOOL_ROTATE_KEY, TOOL_WHOAMI,
};
pub use transport::{
    Clock, HttpRequest, HttpResponse, NonceSource, SigningTransport, Transport, TransportError,
};
