/**
 * Protocol rejections: JackError plus the Code table, mirroring Go's
 * errors.go. A zero httpStatus means the code never becomes an HTTP response.
 */

/** All protocol error codes; the string values match the Go constants exactly. */
export const Code = {
  MISSING_AUTH: "missing_auth",
  MALFORMED_AUTH: "malformed_auth",
  UNSUPPORTED_VERSION: "unsupported_version",
  UNKNOWN_KEY: "unknown_key",
  KEY_INACTIVE: "key_inactive",
  TIMESTAMP_OUT_OF_WINDOW: "timestamp_out_of_window",
  BAD_SIGNATURE: "bad_signature",
  REPLAYED_NONCE: "replayed_nonce",
  UNKNOWN_SERVER_KEY: "unknown_server_key",
  INVALID_REQUEST: "invalid_request",
  OPERATION_DENIED: "operation_denied",
  INSUFFICIENT_SCOPE: "insufficient_scope",
  INVALID_PARAMS: "invalid_params",
  KEY_REJECTED: "key_rejected",
  INVALID_PROOF: "invalid_proof",
  INVALID_INVITE: "invalid_invite",
  SCOPE_ESCALATION: "scope_escalation",
  AGENT_ADMIN_FORBIDDEN: "agent_admin_forbidden",
  FORBIDDEN_ADMIN_TARGET: "forbidden_admin_target",
  UNKNOWN_TARGET: "unknown_target",
  NAME_TAKEN: "name_taken",
  KEY_EXISTS: "key_exists",
  LAST_ADMIN: "last_admin",
} as const;

/** A protocol rejection carrying the HTTP status and code the spec assigns. */
export class JackError extends Error {
  /** Zero means the code never becomes an HTTP response. */
  readonly httpStatus: number;
  readonly code: string;

  constructor(httpStatus: number, code: string, message = "") {
    super(message);
    this.httpStatus = httpStatus;
    this.code = code;
    this.name = "JackError";
  }
}
