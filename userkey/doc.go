// Package userkey is the shared software Ed25519 user-key foundation used by
// both the client and the server sides of the SDK. Role access is asymmetric,
// mirroring how each side handles user key material:
//
//   - The client role generates or imports private material for signing but
//     exports only public data: GenerateClientKey creates a key from
//     crypto/rand, ImportClientKey builds one from exactly 32 seed bytes
//     (copying the input), and ClientKey exposes Sign, PublicKey, and KID —
//     never a private accessor.
//   - The server role imports public material only: ImportServerKey builds a
//     ServerKey from exactly 32 public-key bytes, validating them itself with
//     jack.ValidatePublicKey (canonical encoding, on-curve, non-identity,
//     prime-order subgroup) on an owned copy, and carries the KID with no way
//     to sign and no private export. A private key can never be recovered
//     from an imported public key, and ServerKey structurally holds none.
//   - IssueLocalPair generates a new pair locally with crypto/rand and
//     returns a server-local *IssuedKey handle plus the public identity
//     *ServerKey. The handle's Secret method is an explicit private export;
//     handing those bytes to the client out of band is the caller's decision,
//     and the client turns them into a ClientKey with ImportClientKey. It
//     performs no network I/O. The portable transfer issuance path below
//     (IssueUserKey and its credential) is the second, contract-defined
//     private-export path and carries the same redaction and
//     no-persistence obligations; this raw-handoff path is unchanged by it.
//
// Both roles share the same underlying primitives: crypto/ed25519 for
// signatures and jack.KeyID for base64url(SHA-256(public key)) identifiers
// (spec 01 section 2). *ClientKey satisfies the client SDK's signer interface
// shape (Sign, PublicKey, KID) structurally; the package declares that shape
// locally as Signer so server-side code can accept client-role signers
// without importing the client package. Non-extractable signers (OS key
// stores, agents) implement the same three methods and never involve the
// issuance handle. IssuedKey cannot sign: the server side of a pair never
// acts as the user.
//
// Scope boundary: this package is server-context-free. It does not
// authenticate connections and must not be read as ready-to-connect
// authentication. Connection credentials — an endpoint/audience plus the
// server's public key and KID, validated against an independent trusted
// expected pin (never silent pin replacement, no trust-on-first-use, no
// automatic rotation) — are defined by the protocol contract and layered on
// top in SDK integration; the role wrappers here are expected to accept that
// validated server context through the credential surfaces described below.
// An untrusted advertised key alone is not protection against a
// man-in-the-middle, and nothing in this package decides what to trust.
//
// Transfer envelopes (docs/design/user-keys.md sections 3-6): the portable
// representation of a key is a versioned canonical JSON document, exactly one
// of user-key/public, user-key/private, or user-key/credential/client. The
// canonical bytes are fixed ASCII templates — members in exact order
// {"crv","kid","kty","type","v","x"} (plus "d" for private) for envelopes and
// {"aud","client_key","server_kid","server_public_key","type","url","v"} for
// credentials — with no whitespace, BOM or newline; RFC 8785 (JCS) is the
// reference form, but because every value is a fixed literal, canonical
// base64url or the integer 1, these fixed templates are the operative norm
// and no canonicalization library is involved. Credentials additionally use
// JCS string quoting for their Unicode string members. There is deliberately
// no normalize, repair, or tolerated-spelling import path.
//
// Import is strict and total, an ordered pipeline that stops at the first
// failure: input over 4096 bytes is rejected (oversized_envelope) before
// anything else; then valid UTF-8 plus a narrow lexical check of raw JSON
// string escapes — a \uD800..DBFF escape must be paired with a following
// low-surrogate escape in the same token, and any lone surrogate is
// malformed_json — before JSON decoding. Subsequent ordered checks are: the
// root is an object; v is the number 1; type is a defined literal accepted by
// this sink; the member set is exactly as defined; kty/crv literals and
// string-typed members; credential url passes the URL policy; 43-char
// canonical base64url fields decode to 32 bytes; strict public-key validity;
// seed-to-public consistency; kid consistency; strict inner-import of
// client_key for credentials; and finally the input must equal the canonical
// bytes of the parsed object (non_canonical_bytes). Duplicate member names
// resolve by last occurrence during parsing, then the ordered checks decide
// the class — a duplicate never survives: it either fails an earlier check or
// the final canonical gate. The whole pipeline is local: no normalization
// step, no network I/O, and no repair of any kind.
//
// Errors are the closed shared class set delivered as *jack.Error Code:
// malformed_json, wrong_root_type, oversized_envelope, unknown_version,
// unknown_type, bad_member_set, wrong_field_type, bad_encoding, bad_url,
// invalid_public_key, seed_pub_mismatch, kid_mismatch, non_canonical_bytes,
// wrong_envelope_type, private_material_rejected, not_private,
// server_identity_mismatch. Messages carry the class, the member name and
// observed lengths only — never decoded values.
//
// Role surfaces for the transfer API: ImportClientPublicEnvelope returns a
// verify-only *PublicIdentity exposing PublicKey, KID, and Verify; its Sign
// refuses with not_private, and no private export exists anywhere on the
// client surface. ImportClientPrivateEnvelope returns the existing software
// *ClientKey signer. ImportServerPublicEnvelope returns the existing
// *ServerKey and answers any private or credential document with
// private_material_rejected — the security class takes precedence at the
// type step. ExportPublicEnvelope accepts any value exposing
// PublicKey() []byte and emits the canonical public envelope: it works for
// non-extractable signers without a new general Signer requirement, and
// nothing asks hardware or OS-key-store signers to reveal keys.
//
// Credentials: a credential binds an issued client private envelope to a
// server identity — aud, client_key, server_kid, server_public_key, url, v.
// ImportCredential REQUIRES an independently trusted ExpectedIdentity tuple
// {URL, Aud, ServerPublicKey, ServerKID} supplied out of band; the embedded
// server identity is data, not trust — an attacker in the path can substitute
// it, so it never self-authenticates. The tuple itself must be valid, and a
// missing, incomplete, invalid, or conflicting tuple fails
// server_identity_mismatch only AFTER the full structural pipeline accepts
// the document (structurally invalid credentials keep their pipeline class).
// Comparison is exact UTF-8 bytes on all four decoded fields, with no
// normalization or case folding. There is no trust-on-first-use, no pin
// overwrite, no rotation, no caller-state mutation, and no persistence: every
// refusal leaves caller-owned state unchanged and success returns plain data.
// ConnectionConfig is the validated four-field identity (BaseURL, Aud,
// ServerKey, ServerKID) for use with the SDK's connection layer;
// ValidateCredential is the server-side check that compares a credential
// against the server's own configured identity with the same pipeline and
// class.
//
// Issuance: IssueUserKey(expected, random io.Reader) is pure and local,
// deterministic under an injected random source (the SDK's injected-random
// pattern), with no network calls, no registry mutation, and no persistence.
// It returns a *UserKeyIssuance whose CredentialBytes method is the explicit
// reusable credential export — a fresh, independently owned copy on every
// call, with no one-shot semantics — and whose PublicIdentity field is a
// normal public-only *ServerKey for ordinary registration. The issuance
// handle is NOT a client key and NOT a server record: it cannot Sign and has
// no seed accessor; its fmt and JSON representations redact everything except
// the public kid. Ordinary ClientKey, IssuedKey, and ServerKey values have no
// credential accessor; the existing IssueLocalPair/Secret raw-handoff path
// remains unchanged alongside this portable issuance path.
//
// Plaintext honesty: private envelopes and credentials are UNENCRYPTED secret
// copies. There is no guaranteed zeroization; the credential secret lives
// inside the issuance handle for its lifetime, and Secret or CredentialBytes
// hand out plaintext copies. Safe delivery, backup, and storage are the
// caller's responsibility, outside this package's contract. Nothing is
// written to disk, logged, or displayed, and no server registry, profile, or
// state-file field gains secret material. A private key can never be
// recovered from a public document, and server private material is forbidden
// in every document kind — the exact member sets make it structurally
// impossible.
//
// URLs: the credential url member and the trusted tuple's URL are checked
// against the client URL policy (docs/design/interop.md section 9) — https
// for any syntactically plain host, http only for canonical dotted-decimal
// 127.x.y.z or the bracketed literal [::1] — via a faithful internal port of
// the client package's pure check. The client package is unchanged and this
// package takes no dependency on the client SDK.
//
// The raw-key foundation remains serialization-free: key structs still have
// only unexported fields and encoding/json emits an empty object for each.
// Serialization enters the package only through the transfer API above, and
// it is exactly the canonical envelope and credential serialization defined
// by the contract — no other format, no generic canonicalizer, and no
// extension of v1.
//
// Secret bytes live only inside unexported closure (func) fields. fmt renders
// func values as addresses under every verb — including nested
// unexported-field walks that skip formatting methods, unsupported-verb
// fallbacks that restart rendering at depth zero, and container traversal —
// and reflection cannot enumerate closure captures, so no standard-format
// traversal can recover the bytes; direct verbs hit the redacted
// String/GoString/Format forms. This covers fmt and encoding/json
// representations only. It is not, and is not claimed to be, protection
// against arbitrary unsafe process-memory introspection (cgo, heap dumps, or
// same-process reflection), and Go cannot guarantee zeroization: the seed
// exists in plaintext memory for the lifetime of the key and Secret hands
// out plaintext copies, so callers should zero their own copies after use.
//
// ClientKey and IssuedKey are deliberately nonconvertible: their underlying
// struct types differ in private field names and closure signatures, so
// ordinary Go conversions between the two roles — directly, through pointers,
// or through slices — are compile-time errors. Unexported field names from other packages never
// match this package's fields, so no type outside this package can construct
// or reinterpret either role either. Only unsafe casts, which this package
// does not claim to defend against, could reinterpret memory.
//
// Constructors never return nil on success. Nil or zero-value handles fail
// safe: Sign reports an error, Secret returns nil, PublicKey returns an
// empty result, KID returns an empty string, and Verify returns false — no
// panics from the guard paths and no secret output. Key structs hold closure
// handles and are therefore not comparable; compare PublicKey or KID outputs
// instead. Nothing in this package
// writes files or talks to the network.
package userkey
