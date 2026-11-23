// Package dsig implements the webhook signature bytes of the mcp-jack "modern
// profile": the Standard Webhooks v1, v1a and v2a schemes of
// spec/06-webhooks.md section 2 (R2.2, R2.4, R2.5, R2.6, R2.7, R2.8) and the
// Jack w1 signature of spec/06-webhooks.md section 4 (R4.1-R4.5).
//
// The executable definition is spec/tools/modern/webhooks/ref/signatures.mjs,
// which this package mirrors entry for entry, including the check order of the
// receiver steps and the exact error code strings of section 3
// (malformed_signature_header, unsupported_signature_scheme,
// malformed_signature, bad_server_signature) and of section 4
// (malformed_jack_auth, webhook_key_is_server_key, unknown_webhook_key,
// jack_timestamp_out_of_window, bad_jack_signature).
//
// Every function is pure and deterministic: nothing here keeps state, reads a
// clock or a configuration, or decodes a body. The caller passes the exact
// header values, the raw request body bytes and the clock reading
// (spec/06-webhooks.md R2.3).
//
// Encoding rules are the ones of the spec: signature values in the
// webhook-signature header and the decoded secrets are canonical padded
// standard base64, while w1 parameters and the w1 body hash are canonical
// unpadded base64url. Comparisons of secret-dependent values are constant
// time (R2.2, R3.13).
package dsig
