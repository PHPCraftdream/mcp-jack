package jack

// Error is a protocol rejection with the HTTP status and code the spec assigns.
// A zero HTTPStatus means the code never becomes an HTTP response.
type Error struct {
	HTTPStatus int
	Code       string
	Message    string
}

func (e *Error) Error() string {
	if e.Message == "" {
		return "jack: " + e.Code
	}
	return "jack: " + e.Code + ": " + e.Message
}

// Step table of spec 01 section 4 (request authentication).
// CodeMissingAuth: header absent (HTTP 401).
const CodeMissingAuth = "missing_auth"

// CodeMalformedAuth: header present more than once, or violates the section 3 grammar (HTTP 401, spec 01 section 4).
const CodeMalformedAuth = "malformed_auth"

// CodeUnsupportedVersion: version is not v1 (HTTP 401, spec 01 section 4).
const CodeUnsupportedVersion = "unsupported_version"

// CodeUnknownKey: kid is not in the key registry outside the enrollment exception (HTTP 401, spec 01 section 4).
const CodeUnknownKey = "unknown_key"

// CodeKeyInactive: now outside the key's validity interval (HTTP 401, spec 01 section 4).
const CodeKeyInactive = "key_inactive"

// CodeTimestampOutOfWindow: abs(now - ts) exceeds the window (HTTP 401, spec 01 section 4).
const CodeTimestampOutOfWindow = "timestamp_out_of_window"

// CodeBadSignature: signature does not verify over the signing string (HTTP 401, spec 01 section 4).
const CodeBadSignature = "bad_signature"

// CodeReplayedNonce: (kid, nonce) already recorded and still live (HTTP 401, spec 01 section 4).
const CodeReplayedNonce = "replayed_nonce"

// CodeUnknownServerKey: client-side check that kid is not the pinned server key.
// The table in spec 01 section 5 assigns NO HTTP status (HTTPStatus 0): it never becomes an HTTP response.
const CodeUnknownServerKey = "unknown_server_key"

// Table of spec 02 section 4.
// CodeInvalidRequest: body is not an acceptable JSON-RPC object, or params.name is not a string (HTTP 400).
const CodeInvalidRequest = "invalid_request"

// CodeOperationDenied: the tool name is an undefined "jack."-prefixed name (HTTP 403, spec 02 section 2).
const CodeOperationDenied = "operation_denied"

// Table of spec 03 section 7.
// CodeInvalidParams: an argument is missing, of the wrong type, or out of range (HTTP 400).
const CodeInvalidParams = "invalid_params"

// CodeKeyRejected: public key fails the validity rules of spec 03 section 2 (HTTP 400).
const CodeKeyRejected = "key_rejected"

// CodeInvalidProof: rotate proof missing, malformed, or not a valid signature (HTTP 400, spec 03 section 3.1).
const CodeInvalidProof = "invalid_proof"

// CodeInvalidInvite: invite missing, expired, used or revoked, or a bad code (HTTP 403, spec 03 section 3.2).
const CodeInvalidInvite = "invalid_invite"

// CodeAdminRequired: the caller is not an administrator (HTTP 403, spec 03 section 7).
const CodeAdminRequired = "admin_required"

// CodeUnknownTarget: the addressed registry entry or invite does not exist (HTTP 404, spec 03 section 7).
const CodeUnknownTarget = "unknown_target"

// CodeNameTaken: the name is already used in the registry (HTTP 409, spec 03 section 7).
const CodeNameTaken = "name_taken"

// CodeKeyExists: the key is already registered (HTTP 409, spec 03 section 7).
const CodeKeyExists = "key_exists"

// CodeLastAdmin: the change would leave no active admin entry (HTTP 409, spec 03 section 4 rule 4).
const CodeLastAdmin = "last_admin"

// newError is a small helper for constructing rejections.
func newError(status int, code, message string) *Error {
	return &Error{HTTPStatus: status, Code: code, Message: message}
}
