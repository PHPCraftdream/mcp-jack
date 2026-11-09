# Design: local user-key management contract (role-split generation, import, export)

Status: the independent transfer-envelope contract is implemented in the Go, Rust and TypeScript SDKs. Its transfer envelope `type` member (`user-key/public`, `user-key/private`, or `user-key/credential/client`) is an envelope discriminator, not the removed registry/user `kind` field. The transfer contract remains unchanged by admin-only identity baseline `b13b972`. Legacy user/state `kind` or `scopes` records are rejected without migration or rewrite.

Normative language: MUST/SHOULD/MAY per RFC 2119. MUST applies to library behavior (strict import, role surfaces, redaction, trust policy); SHOULD applies to interactive tooling (operator-facing confirmations); test obligations of section 12 are MUST for each language lane once it starts. Fixtures: `spec/fixtures/user-key-transfer.json` (hand-maintained) and `spec/fixtures/README.md` are the shared fixture side of this contract; this document is its prose.

## 1. Goal, acceptance, asymmetric role split

Users generate Ed25519 identities locally; the server only ever sees public keys (spec 03, decision D9). This contract defines one versioned portable representation (the transfer envelope), a server-issued client transfer credential, and role-specific local utilities. THE ROLES ARE ASYMMETRIC, and this is the contract's core rule:

- **Client role**: generates its own keypair locally, imports PRIVATE envelopes (its own key material obtained from a server issuance or its own backup), imports PUBLIC envelopes (someone else's key, verify-only), exports PUBLIC envelopes only, and imports server-issued credentials. The client role has NO API that exports or serializes private key material. Exporting a private envelope is not a client capability, not an option, and not a flag.
- **Server role**: imports PUBLIC envelopes (admission-ready public identities for its registry-facing paths), and locally issues new user keypairs through a dedicated issuance helper that returns an issuance result: the client transfer credential (containing the new private material, for delivery to the client) plus the public identity for normal public-only registration. After the helper returns, the ordinary server registry record retains only public identity; the caller-owned issuance result retains its secret as long as that result remains alive. The server role has no generic private-key import or private-key storage: nothing in the registry, state file, profile or admin surface gains a seed field, and the server's own long-term signing key keeps its existing local configuration mechanism, untouched and not exportable through this contract.
- **Cryptographic limit, stated plainly**: an imported public key can never yield its private key. Ed25519 public keys are [s]B with s derived from SHA-512 of the seed (RFC 8032 sections 5.1.5, 3.2); recovering the seed from the public encoding would require inverting SHA-512 and solving the discrete logarithm, which is computationally infeasible. There is no recovery path, no escrow, and no "upgrade public to private" API; any tool claiming otherwise is wrong.

Acceptance:

1. Client generate-then-public-export and credential-import reproduce pub/kid and signatures (Ed25519 is deterministic, RFC 8032 section 8.2).
2. Server issuance with an injected random source produces byte-deterministic credentials.
3. Every malformed class of section 6 is rejected with the same class in all three languages.
4. Public envelopes and credentials never contain secret material they must not carry (client public: no seed; credential: no server private key).
5. Non-extractable signers and the general Signer interface keep working unchanged.
6. Trust rules of section 8 hold (no silent pin overwrite, no TOFU).

Non-goals: no encryption, KDFs, or secret-storage subsystem; no new network protocol or issuance-over-the-network feature (issuance is a local, pure function); no algorithm changes; no JWK/PKCS#8 conversion API; no automatic server-key rotation.

## 2. Background: existing primitives (normative references)

- Ed25519 per RFC 8032: private key = 32-byte seed (section 5.1.5); public key = 32-byte encoding of [s]B; signatures 64 bytes; deterministic signing (section 8.2).
- base64url per spec 01 section 2: RFC 4648 section 5, unpadded and canonical; padding, foreign characters, non-zero trailing bits rejected; decode-then-encode reproduces the input; 32 bytes = 43 chars.
- kid = base64url(SHA-256(raw public key bytes)) (spec 01 section 2). Explicitly NOT the RFC 7638 JWK thumbprint (RFC 8037 appendix A.3 is a different construction). Implemented as `jack.KeyID`, `mcp_jack::encoding::key_id`, `mcp-jack keyId`.
- Strict public-key validity (spec 03 section 2, decision D12): exactly 32 bytes, canonical (y < 2^255-19), on the curve, prime-order subgroup, not the identity; `jack.ValidatePublicKey` / `mcp_jack::ed25519::validate_public_key` / TS equivalent; `spec/fixtures/key-vectors.json` reject-* is the normative rejection oracle ("a library that accepts a vector the spec rejects is wrapped, not trusted").
- Existing software signers: Go `client.NewInMemorySigner(seed)`/`client.GenerateSigner()`; Rust `client::signer::InMemorySigner::from_seed`/`::generate`; TS `new InMemorySigner(seed)`/`generateSigner()`. The general Signer interface (Go `client.Signer`, Rust `client::signer::Signer` trait, TS `Signer` interface) MUST NOT change; hardware/OS/agent signers keep plugging in, and nothing in this contract asks them to reveal keys.

## 3. Transfer envelope schema (version 1)

Two kinds, discriminated by the `type` member.

| member | kind | type | meaning |
|---|---|---|---|
| crv | both | string, exactly `"Ed25519"` | JWK-compatible subtype (RFC 8037 section 2) |
| kty | both | string, exactly `"OKP"` | JWK-compatible key type (RFC 8037 section 2) |
| type | both | string, exactly `"user-key/public"` or `"user-key/private"` | envelope discriminator |
| v | both | number, exactly 1 | version; only 1 exists |
| x | both | string, 43-char canonical base64url of the 32-byte public key | JWK "x" |
| d | private only | string, 43-char canonical base64url of the 32-byte seed | JWK "d" (RFC 8037: the private key; MUST NOT appear in public keys) |
| kid | both | string, 43-char canonical base64url of SHA-256(x bytes) | repository kid (section 2) |

The seed is the exported private material (RFC 8032 section 5.1.5; RFC 8410 section 7 CurvePrivateKey wraps exactly these bytes — the TS SDK already feeds them to its PKCS#8 prefix).

Canonical form: RFC 8785 (JCS) canonical JSON. Because every value is a fixed ASCII string or the integer 1, the canonical bytes are exactly:

```
{"crv":"Ed25519","kid":"<KID43>","kty":"OKP","type":"user-key/public","v":1,"x":"<PUB43>"}
{"crv":"Ed25519","d":"<SEED43>","kid":"<KID43>","kty":"OKP","type":"user-key/private","v":1,"x":"<PUB43>"}
```

Members in exactly this lexicographic order (RFC 8785 section 3.2.3 sorts by UTF-16 code units), no whitespace. State honestly: RFC 8785 is Informational; these byte templates are the operative norm, and a generic canonicalizer reproduces them. NO canonicalization library is needed: parse + serialize per the fixed template suffices. A conforming document is exactly these UTF-8 bytes, no BOM. Maximum accepted input size 4096 bytes (both envelopes are under 260 bytes). Versioning: v=1 only; anything else rejected; v1 is never extended with optional members; new revisions define new v values.

## 4. Client transfer credential schema (version 1, server-issued)

A third document kind carrying the server public identity so the client knows which server the key material is for:

```
{"aud":"<AUD>","client_key":"<PRIVATE_ENVELOPE_STRING>","server_kid":"<KID43>","server_public_key":"<PUB43>","type":"user-key/credential/client","url":"<URL>","v":1}
```

| member | type | meaning |
|---|---|---|
| aud | string, non-empty | the aud the client will sign |
| client_key | string holding the exact canonical PRIVATE envelope bytes of the issued client key | the delivered secret material |
| server_kid | 43-char canonical base64url | key id of server_public_key, consistency-checked |
| server_public_key | 43-char canonical base64url of the 32-byte server public key | the server identity to pin |
| type | string, exactly `"user-key/credential/client"` | discriminator (only the client kind exists) |
| url | string | the endpoint; must pass the client URL policy (docs/design/interop.md section 9) |
| v | number, exactly 1 | version |

Hard rules: the credential NEVER contains server private material — the member set is exact, so any `server_private_key`-like member is structurally invalid (`bad_member_set`), with a dedicated fixture (`neg-cred-extra-server-private-key`). Private envelopes and this credential both carry client secret material (the envelope is the credential's inner member); the credential is the only document that additionally binds that material to a server identity, and it is produced only by the server issuance helper. Server private material is forbidden in every document.
Canonical strings (normative): envelope templates are fixed ASCII, but credential strings are Unicode scalar sequences, not ASCII-only (`aud` may contain any non-empty Unicode scalar string). JCS string encoding is normative: quote delimiters; escape quote and backslash; encode U+0008/U+0009/U+000A/U+000C/U+000D as `\b`, `\t`, `\n`, `\f`, `\r`; encode other U+0000..U+001F as lowercase `\u00xx`; emit all other scalar values literally as UTF-8, including <>&, U+2028/U+2029 and U+FFFD. Each short escape is exactly two ASCII bytes, backslash plus the letter; each other control escape is six ASCII bytes. Do not escape solidus or Unicode-normalize. Use fixed template member order, with no whitespace, BOM or newline. First strictly validate `client_key` as an inner document, then quote it as a STRING by the same rules. URL remains subject to the existing URL policy; after decoding, `aud` preserves its exact UTF-8 bytes. Compare tuples by decoded value UTF-8, not raw JSON escape spelling; alternate escape spellings fail the canonical gate.

JSON.stringify and serde_json can provide string quoting after Unicode-scalar validation, with fixed field order explicit. Go `encoding/json` defaults to HTML escaping <>&; `Encoder.SetEscapeHTML(false)` disables those escapes but still escapes U+2028/U+2029 and appends LF, so default Go output is NOT canonical and that setting alone is insufficient. Go must use a narrow internal JSON-string quoting adapter that iterates validated Unicode scalars according to the exact rules above, while the existing serializer supplies JSON grammar/structure. This is only string emission, not a broad JSON parser, generic canonicalizer, dependency or public mode. Do not globally replace `\\u` escape substrings, which corrupt literal backslashes. All languages validate scalars before serialization and never silently replace a lone surrogate.

Pinned `aud` fixtures: `cred-aud-html-sensitive`, `cred-aud-codepoints` (é + U+1F600), `cred-aud-control` (U+0001), `cred-aud-separators` (U+2028/U+2029), and `cred-aud-replacement-char` (U+FFFD). Existing fixture composition arrays may contain integers or single-character literal strings; their exact deterministic meaning is specified in section 11.

## 5. Import pipeline (all three document kinds)

Import is strict and total: a document is accepted only when it is exactly the canonical bytes of its kind and every semantic check passes. There is no normalize, repair, or tolerated-spelling path anywhere in this contract (section 15): unknown members are never dropped, values are never repaired, and no SDK function re-displays private material for confirmation.

Ordered checks, stop at the first failure; class names are normative and shared; diagnostics carry the class, the member name and observed lengths — never decoded values:

| # | check | class |
|---|---|---|
| 1 | input larger than 4096 bytes | oversized_envelope |
| 2 | valid UTF-8; narrow raw-JSON string-escape scalar validation below; valid JSON | malformed_json |
| 3 | parsed value is an object | wrong_root_type |
| 4 | v present, a JSON number, numerically equal to 1 (a spelling like 1.0 passes here — Go and TS cannot distinguish it after parsing; the final canonical gate rejects the spelling identically everywhere) | unknown_version |
| 5 | type is a defined literal AND is the kind this sink accepts. A defined literal of the wrong kind is `wrong_envelope_type` (client public sink with a private envelope; private sink with a public envelope; envelope sinks with a credential; credential sink with an envelope). One precedence exception: the server public-import sink answers any document of kind `user-key/private` or `user-key/credential/client` with `private_material_rejected` — the specific security class wins at this step | unknown_type / wrong_envelope_type / private_material_rejected |
| 6 | member set exactly as defined (envelope public/private or credential) — unknown members are rejected, never stripped | bad_member_set |
| 7 | kty=="OKP", crv=="Ed25519" (envelopes); wrong literals are unknown_type, non-strings wrong_field_type | unknown_type / wrong_field_type |
| 8 | every string member is a string; for credentials `aud` is additionally non-empty | wrong_field_type |
| 9 | credential only: url passes the client URL policy | bad_url |
| 10 | 43-char canonical base64url decoding to exactly 32 bytes for d/x/kid (envelopes) or server_kid/server_public_key (credential) | bad_encoding |
| 11 | strict public-key validity (spec 03 section 2: canonical, on the curve, prime-order subgroup, not the identity) for x (envelopes) AND for server_public_key (credential) — the same existing validator for both | invalid_public_key |
| 12 | private envelope: public key derived from d equals x | seed_pub_mismatch |
| 13 | kid equals base64url(SHA-256(x bytes)); credential: server_kid equals the key id of server_public_key (same rule, same class) | kid_mismatch |
| 14 | credential only: client_key is a string whose strict import AS A PRIVATE envelope succeeds; its failure class propagates (a public envelope embedded here is wrong_envelope_type) | inner class |
| 15 | input bytes equal the canonical serialization of the parsed object | non_canonical_bytes |

Step 2 first validates raw UTF-8, then performs a narrow lexical scalar check on JSON string tokens before platform decoding. It honors escaped backslashes and quotes. A real `\uHHHH` high surrogate (D800..DBFF) MUST be followed immediately in the same token by `\uHHHH` low surrogate (DC00..DFFF), and the pair is consumed together; a lone low surrogate, unpaired high surrogate, or malformed escape is `malformed_json`. Hex digits are case-insensitive; `u` is lowercase per JSON grammar. An escaped backslash followed by text `uD800` is not a Unicode escape. Literal U+FFFD is allowed and is never a rejection heuristic. Remaining syntax belongs to the platform parser. Go replaces invalid surrogates, JavaScript preserves code units, and Rust rejects them, so this precheck equalizes the class before semantic steps. It is not a duplicate-name scanner, broad JSON parser, or new dependency. At the outer level only outer escapes are checked; when decoded `client_key` becomes inner JSON, recursive import repeats the check at step 14, and inner failure propagates.

**Duplicate-member precedence.** Parsing resolves duplicate member names by last occurrence — the one behavior Go `json.Unmarshal`, `serde_json::Map` and `JSON.parse` share — and the resulting document then runs the normal ordered checks. "Duplicates are always rejected" therefore means never accepted, with the class decided by where the document first fails: a duplicate whose last value is semantically consistent passes checks 6-13 and fails only the canonical-bytes gate (`non_canonical_bytes`); a duplicate whose last value is inconsistent (bob's kid on alice's key) fails earlier (`kid_mismatch`). Fixtures pin both (`neg-dup-member`, `neg-dup-member-last-mismatched`). No bespoke duplicate scanner is needed: canonical comparison rejects the first form, ordinary ordered checks reject the second.

Sink rules (normative): a public-only identity used for a secret operation is `not_private`; on the server public-import sink, private material is `private_material_rejected` (step 5 precedence above); any other cross-kind import is `wrong_envelope_type`.

**Trust ordering (credential sink only).** Trust checks run only after the whole pipeline accepts the document: a structurally invalid credential fails its pipeline class, never `server_identity_mismatch`. After acceptance, `importCredential` applies the section 8 policy and returns either the validated connection configuration or `server_identity_mismatch`.

## 6. Error classes (closed set, shared)

`malformed_json`, `wrong_root_type`, `oversized_envelope`, `unknown_version`, `unknown_type`, `bad_member_set`, `wrong_field_type`, `bad_encoding`, `bad_url`, `invalid_public_key`, `seed_pub_mismatch`, `kid_mismatch`, `non_canonical_bytes`, `wrong_envelope_type`, `private_material_rejected`, `not_private`, `server_identity_mismatch`.

Lowercase snake_case like wire codes, delivered through each language's existing error type; no new error framework.

## 7. Role APIs (illustrative names; obligations normative)

Namespace default (resolved, not an open question): preserve the existing raw-key entry points — Go package `userkey` of the existing module, Rust `mcp_jack::user_key`, and named exports from the TypeScript package root `mcp-jack` — with role-specific types and functions inside. No new package subpath, feature flag, namespace split, or public trait hierarchy is introduced for issuance; only the existing Signer trait/interface remains.

- **Client surface**: `generateIdentity()` (existing signer constructors); `exportPublic(...)` -> canonical public envelope bytes; `importPublicEnvelope(bytes)` -> public-only identity `{pub32, kid}` (secret operations refuse with `not_private`); `importPrivateEnvelope(bytes)` -> software signer (wraps the existing from-seed constructors); `importCredential(bytes, expected)` where `expected` is the REQUIRED independently trusted identity tuple `{url, aud, server_public_key, server_kid}` (section 8) -> `{signer, connection}`. NO private export or serialization exists on the client surface in any language.
- **Server surface**: `importPublicEnvelope(bytes)` -> public identity for admission paths (private material is `private_material_rejected`); `issueUserKey(config, random_source)` -> an issuance result with exactly two parts: the credential bytes accessor and `public_identity` for normal public-only registration. The helper is pure and local: no network calls, no registry mutation, no persistence; `random_source` follows the SDK's existing injected-random pattern (as for invite codes), so tests can fix it.

Issuance result obligations: a dedicated type — NOT a client key, NOT a server record; no Sign method, no seed accessor; its Debug/Display/String and default JSON serialization MUST redact the credential bytes (mirror the manual Debug precedent in `rust/src/client/signer.rs`, test `debug_hides_seed`). The credential export accessor is explicit, clearly named, and returns a FRESH copy of the credential bytes on every call: the handoff is an explicit reusable export, not a consumption state machine — there are no one-shot semantics and no new error class for it. Repeated calls to the same issuer accessor return equal, independently owned copies: mutating the first copy completely leaves the second unchanged and a third equal to the original; public_identity and any client signer imported from the original remain unchanged. There is no consumption state. Ordinary client/server records have no private handoff accessor. Plaintext warning: private envelopes and credentials are UNENCRYPTED secret copies; there is no guaranteed zeroization, and the secret lives with the issuer handle for its lifetime. The SDK/server registry/profile must not persist them; no implicit disk/log/display occurs. Safe delivery, backup and storage are the caller's responsibility outside this contract, not a server registry function.

Shared internals are allowed: envelope serialize/parse, seed-to-public derivation, key-id computation may be one internal core shared by both facades; the requirement is that the PUBLIC role APIs match the asymmetric flow, not that the code be duplicated.

## 8. Trust, pinning and bootstrap (normative; MITM honesty)

- The server identity embedded in a credential is data, not trust. A server key learned only from the same untrusted exchange as everything else proves nothing: an attacker in the path can substitute their own server key and the client would sign to the attacker. The contract therefore refuses to bless self-signed or untrusted bundles: no claim that carrying a server key prevents MITM.
- `importCredential` REQUIRES an expected identity tuple `{url, aud, server_public_key, server_kid}` supplied independently of the credential: the client's existing pinned profile identity, or an operator-supplied value obtained out-of-band (trusted channel, fingerprint check of the actual server key). A boolean "confirm whatever arrived" is explicitly rejected — the trusted input is the actual expected identity, never same-exchange self-authentication. The tuple itself must satisfy endpoint/aud/public-key/kid validity. After document validation, a missing, null, incomplete, invalid, or conflicting expected tuple fails `server_identity_mismatch` before any signer or configuration is returned. The existing pinned identity is authoritative: a separate expected value conflicting with it MUST NOT overwrite the pin; callers supply the tuple from that authoritative pin, and conflicts refuse. No new persistence/configuration subsystem or argument hierarchy is introduced.
- Comparison uses exact UTF-8 bytes of all four decoded fields, without normalization or case folding; mismatch is `server_identity_mismatch`. A successful import returns the validated signer and connection configuration to the caller. The SDK performs no persistence or profile mutation, and every refusal leaves caller-owned state unchanged.
- HTTPS certificate validation and pinned response-signature verification are unchanged (docs/design/interop.md sections 9.2/9.3); the credential adds no transport behavior, no insecure mode, no automatic rotation.
- Server side: a validation helper for issued credentials checks the embedded url/aud/server_public_key/server_kid against the server's own configured identity and fails `server_identity_mismatch` on any difference (tooling and tests; not a network feature).

## 9. Identity objects, copying and aliasing

Import returns plain data for public identity (fields fresh per call) or a software signer. Returned byte slices/arrays are owned by the caller: mutating them MUST NOT change importer/signer state, and later signer operations MUST be unaffected; re-export after mutation reproduces the original bytes. Strings are immutable in all three languages. No interior mutability, no shared caches of returned byte values.

## 10. Secret redaction

The Debug/Display/String form of every type that holds or once held a seed, private envelope or credential MUST NOT contain that material; the software signer's Debug shows kid and public key only (precedent: `rust/src/client/signer.rs` `debug_hides_seed`); error values carry class, member name, lengths only; SDK code MUST NOT log envelopes, credentials or seeds at any level. No SDK surface prints or logs private envelopes, credentials or seeds; the issuance export accessor returns bytes programmatically for the caller's delivery channel and performs no display. Interactive display of secret material is a caller concern outside the SDK.

Per-language obligations:

- Go: redaction via Stringer/`%v`/`%#v` behavior for signer, public identity and issuance result; no `fmt` logging of credential bytes anywhere in `client/` or server code.
- Rust: manual `fmt::Debug`/`Display` impls for the issuance result and imported signer (existing precedent); `#[derive(Debug)]` MUST NOT be applied to any type holding seed material.
- TypeScript: `toString`/`inspect`/serialization of these types shows kid and public key only; no `console.log` of envelopes or credentials in SDK source.

## 11. Shared fixtures and oracles

`spec/fixtures/user-key-transfer.json` (hand-maintained; provenance in the file and `spec/fixtures/README.md`) is the shared test table:

- Positives (14): `pub-alice`/`priv-alice`, `pub-bob`/`priv-bob`, `pub-carol`/`priv-carol` (canonical byte-exact envelopes; `d` strings are checked against pinned `keys.json` `seed_hex`), `priv-rfc8032-test1`, `cred-alice`/`cred-bob`, plus aud controls: `cred-aud-html-sensitive`, `cred-aud-codepoints`, `cred-aud-control`, `cred-aud-separators`, `cred-aud-replacement-char`.
- Context case (1): `cred-wrong-server` — composed; `structural_outcome` `accepted_by_import_pipeline`, `trust_outcome` `server_identity_mismatch`; used with an independently trusted svc tuple. Structural-valid and trust outcomes are separate schema fields with deterministic runner semantics.
- Negatives: unknown version/type, bad kty/crv, unknown/missing member, wrong member type, null, empty `d`, padding, foreign character, non-zero padding bits (`neg-b64-trailing-bits`), short/long, seed-pub mismatch, kid mismatch, duplicated member with consistent last value (`neg-dup-member` -> `non_canonical_bytes`) and with mismatched last value (`neg-dup-member-last-mismatched` -> `kid_mismatch`), whitespace, reordering, truncated, oversized, escaped member name and escaped url solidus (`neg-escaped-member-name`, `neg-escaped-url-slash`), size boundaries 4096/4097 (`neg-size-boundary-4096/4097`), invalid UTF-8 (`neg-invalid-utf8`), array/string/empty/null root, float `v`, four invalid public keys composed from `key-vectors.json` reject-*, and credential negatives: unknown version/type, missing server_kid, server-private-key smuggle, server_kid mismatch, bad url, empty aud (`neg-cred-empty-aud`), invalid server public key with consistently computed kid (`neg-cred-invalid-server-pub`), `neg-cred-client-key-noncanonical` and `neg-cred-client-key-public`, including duplicate-member and credential duplicate-inner-member cases (`neg-dup-member-escaped`, `neg-cred-dup-inner-member`), `neg-cred-aud-lone-surrogate-escape` and `neg-cred-aud-lone-low-surrogate-escape` -> `malformed_json`; `neg-cred-aud-escaped-surrogate-pair` -> `non_canonical_bytes`.

Oracle rules (hard requirements): `keys.json` is the independent pinned oracle for seed/public/kid triples; RFC 8032 section 7.1 TEST 1 (with RFC 8037 A.1) is the independent standards oracle; `key-vectors.json` reject-* are the generated normative invalid-key oracle. No lane may fabricate crypto outputs or assert a self-derived oracle: seed-to-public equality, kid recomputation, signature verification and URL-policy verdicts always re-derive from pinned inputs. The fixture `d` strings were hand-encoded from `keys.json` `seed_hex` by pure base64url conversion; the first import of any lane proves that conversion (a wrong `d` fails `seed_pub_mismatch` loudly). Byte-exactness where promised: exported envelopes and issued credentials equal the fixture strings exactly, in all three languages.

Fixture self-consistency obligations. Positives and structurally-valid context documents MUST parse; canonical bytes MUST match; seed/public/kid consistency and strict validity apply to fields present; embedded `client_key` MUST equal its referenced positive; context trust result is evaluated separately against the trusted tuple. CI MUST compare decoded `d` raw bytes with `keys.json` `seed_hex` (not only d-to-x), and independently pin x/kid. Test-only composition may compute missing kid using the documented formula, but that result is never an independent oracle.

Negatives do NOT require parseability, canonicality, seed/public/kid equality or referenced-inner equality when that is the declared mutation. Each literal case's envelope and `expect_why` specify the mutation; `expect_class` is the expected FIRST failure in the ordered pipeline on the intended sink. Runners verify prerequisites before the intended failing step, all nonmutated baseline fields, and the exact intended mutation. Malformed/truncated cases are exempt from later checks; noncanonical/mismatch cases deliberately violate the named check. Earlier or later failure than intended is a test failure. Canonical and inner gates remain ordered as section 5; no blanket requirement that all negatives be canonical or consistent.

Fixture composition is read-only: at CI, start from the named base or fixed template, resolve references as exact bytes, encode source hex as raw bytes then canonical base64url, and apply ONLY the named mutation. In `aud_codepoints`, each integer denotes a Unicode scalar and each single-character string denotes exactly that character; concatenate in listed order. URLs/server identity/default private key come from compose or the named base. Replacing aud with an escape sequence replaces JSON string content between quotes with those literal characters, not platform parsing or surrogate repair. `client_key_replacement` quotes the referenced negative-document string with the canonical string emitter in the outer document. The size-boundary recipe appends ASCII 0x20 until total byte length equals the specified value; UTF-8 recipe replaces the final byte of the raw canonical envelope (closing brace 0x7D) with 0xFF, preserving byte length.

## 12. Per-language, per-role acceptance checklist

The rows below describe shared obligations. The Go, Rust, and TypeScript SDKs implement this transfer contract; those source-level obligations are not in themselves CI results for the migrated baseline. The fixture file remains the oracle for exact bytes and classes.

### 12.1 Go

| # | Obligation |
|---|---|
| 1 | Client generate + exportPublic: canonical bytes match the template; kid == `jack.KeyID(pub)`. |
| 2 | Client importPrivateEnvelope of priv-alice/priv-bob/priv-carol/priv-rfc8032-test1: pub/kid match the oracles; sign a fixed message with the imported signer; signature equals the original signer's bytes (RFC 8032 determinism) and verifies. |
| 3 | Server issueUserKey with fixed config and injected random: credential bytes equal the composed template for the same inputs; public_identity matches; calling twice with the same random gives identical bytes; the result type exposes no Sign/seed accessor and its Debug/JSON output contains no credential bytes. Repeated calls to the same issuer accessor return equal independently owned copies; completely mutating the first leaves the second unchanged, a third equals original, and public_identity and a client signer imported from original are unchanged; no consumption state; ordinary client/server record has no private handoff accessor. |
| 4 | Server issuance handoff: the credential from (3) imports on the client role and yields a working signer; the public identity admits through the existing public-only paths (existing admin/enroll conformance unchanged). |
| 5 | Client importPublicEnvelope of pub-*: kid/pub match; secret operations refuse not_private. |
| 6 | Every neg-* case: strict import fails with exactly expect_class. |
| 7 | Secret absence: public export contains no d member and no occurrence of the seed string; credentials contain no server private-key member (neg-cred-extra-server-private-key byte test) and issuance results redact by default (Debug/String/JSON). |
| 8 | Mutability isolation (section 9) for exports, imports and issuance outputs. |
| 9 | Redaction (section 10) incl. a debug_hides_seed-style test per language and one for the issuance result. |
| 10 | Non-extractable compatibility: a test-only signer implementing only the general `client.Signer` interface keeps signing and satisfies public export; general Signer conformance tests pass unchanged; nothing requires hardware signers to reveal keys. |
| 11 | Wrong sink: client public sink with private material is `wrong_envelope_type`; server public sink with private or credential material is `private_material_rejected`; credential sink with public inner envelope is `wrong_envelope_type` (neg-cred-client-key-public). |
| 12 | Trust policy: a valid credential succeeds only with a valid independently trusted matching tuple; for each aud-positive fixture the expected tuple uses that exact independently supplied aud. `cred-wrong-server`, decoded url/aud mismatch, differing expected identity, and existing-pin/expected conflict refuse with `server_identity_mismatch`. Missing/null/incomplete/invalid expected tuple also refuses with `server_identity_mismatch` AFTER document validation, returning no signer/configuration and leaving caller state unchanged. Invalid documents retain earlier pipeline classes: server_kid mismatch `kid_mismatch`, bad url `bad_url`, empty aud `wrong_field_type`, invalid server public key `invalid_public_key`; server-side validation uses the same pipeline before comparing its own identity. |
| 13 | Representation and boundary controls: non-zero base64url padding bits (neg-b64-trailing-bits); escaped-equivalent member name and url spellings (neg-escaped-member-name, neg-escaped-url-slash); input size boundaries 4096 -> non_canonical_bytes and 4097 -> oversized_envelope (neg-size-boundary-4096/4097); invalid UTF-8 composition (neg-invalid-utf8); exact public import->export round trips for pub-alice/pub-bob/pub-carol byte-identical to the fixture strings. |
| 14 | Credential aud/JCS: all `cred-aud-html-sensitive`, `cred-aud-codepoints`, `cred-aud-control`, `cred-aud-separators`, and `cred-aud-replacement-char` cases; lone high/low surrogate raw escapes are `malformed_json`, valid escaped surrogate pair is `non_canonical_bytes`; escaped-equivalent duplicate and nested duplicate errors follow section 5; repeated export freshness as row 3. |

### 12.2 Rust

The identical fourteen rows, realized with `mcp_jack::` equivalents: `mcp_jack::encoding::key_id` for row 1's kid check, `client::signer::Signer` trait conformance for row 10, and the manual `fmt::Debug` precedent of `rust/src/client/signer.rs` for rows 7 and 9 (`debug_hides_seed` style plus an issuance-result variant). serde_json's 1-vs-1.0 distinction (section 16) means row 6 additionally asserts that a float `v` spelling reaches `non_canonical_bytes` at the final gate, not an early rejection.

### 12.3 TypeScript

The identical fourteen rows, realized with `mcp-jack` equivalents: `mcp-jack keyId` for row 1's kid check, the TS `Signer` interface for row 10, and redaction tests against `toString`/inspect output for rows 7 and 9. Row 6 additionally asserts that JSON.parse's last-occurrence duplicate behavior only shifts the failure class (kid_mismatch for a mismatched last value) and never lets a duplicated document through strict import.

## 13. JSON duplicate members and D13

D13 scopes last-occurrence-wins to JSON-RPC request bodies (spec 02 section 2); local documents parse strictly, resolving duplicates by decoded name AFTER unescaping, last occurrence wins. Ordinary ordered semantic checks may fail before final gate. Escaped-equivalent duplicate (`neg-dup-member-escaped`) and inner duplicate (`neg-cred-dup-inner-member`) fixtures pin behavior; inner first failure propagates at step 14 before outer gate 15. No bespoke duplicate scanner.

## 14. Examples (illustrative intent, not final APIs)

Go (client role — credential import, then sign):

```go
// Illustrative intent only; names are not final.
conn, signer, err := userkey.ImportCredential(credBytes,
    userkey.ExpectedIdentity{URL: profileUrl, Aud: profileAud, ServerPublicKey: svcPub, ServerKID: svcKID}) // independently trusted tuple
if err != nil {
    log.Fatalf("import: %v", err) // err carries class only, no material
}
msg := []byte("hello mcp")
sig, err := signer.Sign(msg)
_ = conn.Url // {"url","aud","server_public_key","server_kid"} from the credential
_ = sig      // 64-byte Ed25519 signature, deterministic
```

Rust (server role — issuance with injected random, hand off, register):

```rust
// Illustrative intent only; names are not final.
let mut rng = ChaCha20Rng::from_seed(FIXED_TEST_SEED); // injected random source
let issued = mcp_jack::userkey::issue_user_key(&config, &mut rng)?;
deliver_to_client(issued.credential_bytes())?; // reusable fresh-copy accessor
admin_enroll(issued.public_identity())?;       // existing public-only path
// Issued still retains its handoff secret while alive; delivery/export does not erase it or consume the accessor
```

TypeScript (client role — verify-only use of an imported public identity):

```typescript
// Illustrative intent only; names are not final.
const alice = mcpJack.userkey.importPublicEnvelope(pubAliceBytes);
const ok = mcpJack.userkey.verify(alice, message, signature64);
if (!ok) throw new Error("bad signature");
// alice carries {pub32, kid} only: no sign method exists on it, and a
// secret call against it is refused with not_private
```

## 15. Decisions and rejected alternatives

- Role-asymmetric APIs over symmetric export: client private export removed entirely; server issuance is a dedicated pure helper with an explicit reusable fresh-copy credential export, not a signer method — matches the reviewed direction that a client key never exports private material and a server record never stores it.
- Canonical-only strict import over tolerant parsing: kills duplicate/whitespace/spelling ambiguity with parse+serialize only; there is deliberately no normalize or confirm display in this contract (rejected: it stripped forbidden members and re-displayed private material).
- JWK-profile member names (kty/crv/x/d, RFC 8037 section 2) over generic JWK: standards-aligned semantics, but a standard JWK is NOT accepted (missing type/v/kid, arbitrary order); conversions out of scope. kid kept (not renamed), documented as not the RFC 7638 thumbprint.
- RFC 8785 (JCS) as canonical-form reference instead of a bespoke canonicalization: the byte templates are normative regardless of JCS's Informational status; no library dependency.
- Credential carries server identity as data + explicit trust policy over silent pin adoption: prevents MITM-friendly defaults; rejected alternatives: TOFU on first contact, automatic pin overwrite, automatic rotation, bundling a server private key "for completeness" (structurally impossible here).
- Rejected: PKCS#8/PEM as transfer format (DER wrapping hurts byte-exact testing; TS's internal PKCS#8 use stays internal); bespoke duplicate-detecting scanners (parser-dependent in TS); last-wins acceptance for strict import (silent; D13 is scoped to request bodies); seed rejection policies beyond RFC 8032; requiring zeroization libraries (Rust would need a new dependency; best-effort language instead, no manifest changes).
- Duplicate precedence over one fixed class: parsing resolves duplicates by last occurrence, then the ordered checks decide the class; duplicates are never accepted.
- Namespace default: one shared `userkey` root per language with role-specific functions; no new flags, namespaces or trait hierarchy.
- Credential canonicalization: the JCS string-escaping profile over existing serializers; aud/url compared byte-for-byte; escaped-equivalent spellings fail the canonical gate.
- Error classes are shared strings through each language's existing error type; no new framework.

## 16. Risks and open questions

- JCS is Informational; the section 3 templates are the operative norm.
- Rust serde_json distinguishes 1 from 1.0 where Go/TS cannot; pipeline ordering (numeric v check first, canonical gate last) keeps classes identical; Rust lanes must not reject 1.0 early.
- The fixture `d` strings are hand-encoded; first import proves them via `seed_pub_mismatch` detection (documented provenance); if one is wrong, fix the fixture, not the derivation.
- The shared fixture corpus is hand-authored and byte-exact; imported material is checked against independent seed/public/kid and RFC 8032 oracles.
- Resolved: the namespace default is fixed (section 7); issuance needs no separate feature or namespace.

The transfer contract is implemented in the Go, Rust, and TypeScript SDKs. The fixture obligations are separate from execution evidence; CI passed on integrated `444c69b`; shared harness, consumer, coverage, and fuzz evidence was verified in GitHub CI on `444c69b`.
