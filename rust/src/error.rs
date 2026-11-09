//! Protocol rejections: the spec-assigned HTTP status, code and message (Go: errors.go).

use std::fmt;

/// A protocol rejection with the HTTP status and code the spec assigns. A zero
/// `http_status` means the code never becomes an HTTP response (mirrors Go
/// int where 0 is that sentinel).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JackError {
    pub http_status: u16,
    pub code: String,
    pub message: String,
}

impl JackError {
    /// Builds a rejection with its spec-assigned HTTP status and code (Go: newError).
    pub fn new(http_status: u16, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            http_status,
            code: code.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for JackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.message.is_empty() {
            write!(f, "jack: {}", self.code)
        } else {
            write!(f, "jack: {}: {}", self.code, self.message)
        }
    }
}

impl std::error::Error for JackError {}

/// Error codes assigned by the spec tables; string values are the wire codes.
pub mod codes {
    /// Header absent (HTTP 401).
    pub const MISSING_AUTH: &str = "missing_auth";
    /// Header present more than once, or violates the section 3 grammar (HTTP 401, spec 01 section 4).
    pub const MALFORMED_AUTH: &str = "malformed_auth";
    /// Version is not v1 (HTTP 401, spec 01 section 4).
    pub const UNSUPPORTED_VERSION: &str = "unsupported_version";
    /// Kid is not in the key registry outside the enrollment exception (HTTP 401, spec 01 section 4).
    pub const UNKNOWN_KEY: &str = "unknown_key";
    /// Now outside the key's validity interval (HTTP 401, spec 01 section 4).
    pub const KEY_INACTIVE: &str = "key_inactive";
    /// abs(now - ts) exceeds the window (HTTP 401, spec 01 section 4).
    pub const TIMESTAMP_OUT_OF_WINDOW: &str = "timestamp_out_of_window";
    /// Signature does not verify over the signing string (HTTP 401, spec 01 section 4).
    pub const BAD_SIGNATURE: &str = "bad_signature";
    /// (kid, nonce) already recorded and still live (HTTP 401, spec 01 section 4).
    pub const REPLAYED_NONCE: &str = "replayed_nonce";
    /// Client-side check that kid is not the pinned server key; NO HTTP status (0), never an HTTP response.
    pub const UNKNOWN_SERVER_KEY: &str = "unknown_server_key";
    /// Body is not an acceptable JSON-RPC object, or params.name is not a string (HTTP 400).
    pub const INVALID_REQUEST: &str = "invalid_request";
    /// An undefined `jack.`-prefixed tool name (HTTP 403, spec 02 section 2).
    pub const OPERATION_DENIED: &str = "operation_denied";
    /// Caller is not an administrator (HTTP 403, spec 03 sections 3.3 and 7).
    pub const ADMIN_REQUIRED: &str = "admin_required";
    /// An argument is missing, of the wrong type, or out of range (HTTP 400, spec 03 section 7).
    pub const INVALID_PARAMS: &str = "invalid_params";
    /// Public key fails the validity rules of spec 03 section 2 (HTTP 400).
    pub const KEY_REJECTED: &str = "key_rejected";
    /// Rotate proof missing, malformed, or not a valid signature (HTTP 400, spec 03 section 3.1).
    pub const INVALID_PROOF: &str = "invalid_proof";
    /// Invite missing, expired, used or revoked, or a bad code (HTTP 403, spec 03 section 3.2).
    pub const INVALID_INVITE: &str = "invalid_invite";
    /// The addressed registry entry or invite does not exist (HTTP 404, spec 03 section 7).
    pub const UNKNOWN_TARGET: &str = "unknown_target";
    /// The name is already used in the registry (HTTP 409, spec 03 section 7).
    pub const NAME_TAKEN: &str = "name_taken";
    /// The key is already registered (HTTP 409, spec 03 section 7).
    pub const KEY_EXISTS: &str = "key_exists";
    /// The change would leave no active admin entry (HTTP 409, spec 03 section 4 rule 4).
    pub const LAST_ADMIN: &str = "last_admin";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_empty_message_is_code_only() {
        let e = JackError::new(401, codes::MISSING_AUTH, "");
        assert_eq!(e.to_string(), "jack: missing_auth");
    }

    #[test]
    fn display_with_message() {
        let e = JackError::new(400, codes::KEY_REJECTED, "bad key length");
        assert_eq!(e.to_string(), "jack: key_rejected: bad key length");
    }
}
