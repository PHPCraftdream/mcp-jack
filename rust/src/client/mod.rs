//! Client SDK for mcp-jack (Go: package client). The client signs every
//! outgoing request with an Ed25519 signer and verifies every response
//! against the pinned server public key before its body is returned (spec 01
//! sections 4 and 5). It speaks the protocol-native jack.* tools (spec 03
//! sections 3.1-3.3).

pub mod error;
pub mod modern;
mod network;
pub mod profile;
mod request_signing;
mod rotation;
pub mod rpc;
pub mod tools;
pub mod transport;

#[cfg(feature = "client-http")]
pub use network::http_transport;
pub use network::url;
pub use request_signing::{auth, signer};
pub use rotation::rotation_auth;
#[cfg(all(target_os = "linux", feature = "client-http"))]
pub use rotation::rotation_http;

pub use auth::{random_nonce, sign_request, SignedRequest, NONCE_SIZE};
pub use error::{
    ClientError, HttpError, ReplyEra, ReplyError, RpcError, ToolError, UnauthenticatedResponseError,
};
#[cfg(feature = "client-http")]
pub use http_transport::{HttpTransport, HttpTransportBuilder};
pub use modern::{
    build_mirrors, collect_annotations, detect_era, project_arguments, validate_annotations,
    AnnotationError, ClientEra, EraDetection, MirrorError, Mirrors, PrivateResultCache,
    ProjectionError,
};
pub use profile::{load_profile, save_profile, Profile};
pub use rotation_auth::{verify_rotation_carrier, RotationCarrier, RotationResponseKey};
#[cfg(all(target_os = "linux", feature = "client-http"))]
pub use rotation_http::RotationHttpClient;
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
