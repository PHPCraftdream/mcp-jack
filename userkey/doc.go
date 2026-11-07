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
//   - IssueLocalPair is the only issuance path and the only source of private
//     handoff: it generates a new pair locally with crypto/rand and returns a
//     server-local *IssuedKey handle plus the public identity *ServerKey. The
//     handle's Secret method is the package's single explicit private export;
//     handing those bytes to the client out of band is the caller's decision,
//     and the client turns them into a ClientKey with ImportClientKey. It
//     performs no network I/O.
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
// forthcoming validated server context in a later change. An untrusted
// advertised key alone is not protection against a man-in-the-middle, and
// nothing in this package decides what to trust.
//
// There is intentionally no JSON or other serialization in this package, and
// none is frozen here: the portable wire format is owned by the protocol
// contract, not by this foundation. All key structs have only unexported
// fields, so encoding/json emits an empty object for each of them.
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
