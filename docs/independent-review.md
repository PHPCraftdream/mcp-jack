# Independent review of v0.1.0 (AI reviewer)

**Reviewer:** the `fm` review agent (Claude Fable 5.2, medium effort), working in a separate context from the
implementers and from the earlier internal pre-review. **This is an AI reviewer that read source without
building, running or fetching anything. It is not a human audit and not a paid third-party audit.** Third-party
library behaviour (encoding/json, serde_json, node:crypto, bbolt, hyper, undici) is inferred where it is relied on.

**Commit reviewed:** `993b5397c75197008d3ceab975b3c49a75b12b4f` (`main`). The reviewer formed its own picture from
the specification and the source first and read `docs/security-review-package.md` and `docs/threat-model.md` only
afterwards. **Outcome:** no authentication bypass, response forgery or replay in the Go durable profile was found at
the depth reached; that is not evidence of absence, because large areas were not reached (see Coverage).

The findings below are the reviewer's claims. Items marked "re-verified" were re-read by the maintainers; the
others have not been re-verified yet. The disposition column states what was done or decided.

## Coverage

| Area | Read fully | Read partly | Not reached |
|---|---|---|---|
| Specification | `spec/01`, `02`, `03`, `spec/candidate/server-key-rotation.md`, `spec/candidate/durable-nonces.md` | request vector ids | other fixtures, `spec/tests/**`, `spec/tools/**` |
| Go root and `server/` | authentication, signing, base64url, Ed25519, verifier, middleware, nonce, identity, response keys, admission, native tools, state file, rotation provider | `state.go` | `audit.go` |
| Go `client/`, `rotation/` | transport, auth, signer, rotation auth, profile, rpc, URL policy, controller, refresh, http; record, chain, sign, trust, page, server state, arguments, strict JSON | | `tools.go`, `errors.go`, `result.go`, `trust_json.go` |
| Go `durable/` | admission, transaction, store, private files, server operations | | records, metadata, layout, trust stores, recovery, snapshot, inspect |
| Go `internal/cli` | gateway, native policy, nonces, signing profile, storage, JSON, keys, connection, bridge, run | | admin and nonce and server-key commands, process I/O |
| `userkey/` | outline of `transfer.go` | | `key.go`, `transfer.go` bodies |
| Rust | header grammar, verifier, HTTP layer, nonce store, Ed25519, server key | native tools (partly), greps of rotation controller and state file | client bodies, rotation stores and formats, state, user key |
| TypeScript | header grammar, encoding, signing, Ed25519, raw JSON, verifier, fetch and node adapters, nonce store, server-key tool, rotation controller | native tools (partly), greps of client and state file | client bodies, other rotation files, state, user key |
| CI and supply chain | `release-candidate.yml` (most), manifests, dependabot config | other workflows (triggers, permissions) | `tools/**`, `interop/**`, lock files |
| Tests | none | vector id list | all test bodies |

Credential transfer and key management (`userkey/`) and test quality are essentially uncovered, as are the Rust and
TypeScript rotation store formats. The external-review gap for those areas remains open.

## Findings

No Critical or High finding.

| Id | Severity | Finding | Disposition |
|---|---|---|---|
| M-1 | Medium (wire/design) | The 48 h activation delay does not bind whoever holds the authorizing key. A client only requires `P >= previous P`, `P <= response time` and local time `< A = P + 172800`, so a holder of the current response key can publish a successor with a backdated `P` whose activation is seconds away, cutting off the legitimate key; a retired key can do the same against a client that has not yet learned the successor. The threat model concedes that a compromised key can authorize a successor but did not say that the 48 h is a liveness parameter for honest operation, not a notice period. | The limitation is now stated in the threat model. A minimum-notice rule (`A - t >= N`) would break honest late refreshes, so adding it is a protocol decision before the freeze; open for the owner. |
| M-2 | Medium (conformance) | The shipped gateway records no audit events: `server.Config` is built without an `Audit` sink and the HTTP error log is discarded, while spec 03 section 8 says a server MUST record admin, enrollment and key-rotation calls and the README says protocol operations are audited. Re-verified. | Documentation corrected to say what is true now. Fix tracked: the gateway gets a JSON-lines audit sink. |
| L-1 | Low | Rust parses the whole `arguments` object of an unknown-key `jack.enroll` into a JSON value tree, Go and TypeScript use raw members. An unrelated argument such as `"x":1e999` continues in Go and TypeScript but is `401 unknown_key` in Rust (inferred for serde_json). No shared vector. | Tracked with the cross-language fixes: use the raw-member map in Rust, add a shared vector, add a spec sentence on number ranges. |
| L-2 | Low | The TypeScript verifier and nonce store do not validate the injected clock or window: a `NaN` clock turns freshness and replay protection off. | Tracked with the cross-language fixes (validate, answer 500). |
| L-3 | Low | The volatile nonce store of all three SDKs purges against the caller's current clock: a forward clock step past `ts + W` followed by a step back forgets live entries and a captured request is accepted again. The durable profile latches on this. | Documented in the threat model; a high-water mark for the volatile store is a post-0.1.0 item. |
| L-4 | Low (documentation) | "Rotations are at least 48 hours apart" is not enforced and contradicts the spec: up to 128 pending announcements with no spacing rule are allowed, so 1024 retired keys can be reached in about 16 days of announcing, after which signing is refused and there is no compaction. Re-verified; the sentence was our own error in the operations guide and the threat model. | Corrected everywhere. A spacing rule is a protocol decision; open for the owner. |
| L-5 | Low (inferred) | The gateway filters on the exact-case member `method` but forwards the original bytes; an upstream that decodes into Go structs matches member names case-insensitively, so a case-variant duplicate such as `Method` could smuggle `notifications/cancelled` past the filter. The gateway also rejects duplicate members after consuming the nonce while the SDKs accept them (last wins, spec 02). | Tracked: the gateway rejects case-variant duplicates of the reserved members. The duplicate-member rule itself is open for the owner. |
| L-6 | Low (supply chain) | Only the attestation action is pinned by commit; `dtolnay/rust-toolchain@1.88.0` is a branch ref and builds the attested `.crate`, other actions are tags. The attestation verifier accepts a signer ref of any branch the workflow was dispatched from; credentials are persisted by the checkouts. No script injection was seen. | Tracked: pin the release-candidate actions by commit, require `refs/heads/main`, `persist-credentials: false`. |
| L-7 | Low | Rust writes the requested enrollment name into the audit target before validating it; Go and TypeScript do it after. | Tracked with the cross-language fixes. |
| L-8 | Low | The Go state loader accepts case-variant member names (`ADMIN` loads as an administrator, inferred from encoding/json); Rust and TypeScript are exact. Answers F-17. | Tracked: exact-name matching in the Go loader. |
| I-1 | Info | The release candidate mixes versions: `mcp-jack-0.0.0.tgz` and `mcp-jack-0.1.0.crate`. | Known; resolved by the release PR that sets versions. |
| I-2 | Info | The gateway denies `jack.whoami` and `jack.key.rotate` and the CLI has no key-rotate command, so users behind the gateway cannot rotate their own key in-band (spec 03 section 3.1). | Documented in the operations guide. |
| I-3 | Info | The TypeScript fetch adapter sends 204/205/304 answers with a null body while the signature covers the upstream bytes; fails closed at the client. | Recorded. |
| I-4 | Info | TypeScript `acceptRefresh` throws on a late final-gate failure and loses `committed: true`; Go returns the result with the error. | Tracked with the cross-language fixes. |
| I-5 | Info | If the only administrator key expires there is no in-band path and `jack bootstrap` needs a state file that does not exist yet. | Documented in the operations guide. |
| I-6 | Info | A stale `<state>.owner` marker after a crash blocks the gateway until removed by hand. | Same family as the documented missing recovery command. |

## Cross-language differences found

| Input | Go | Rust | TypeScript | Shared vector |
|---|---|---|---|---|
| Unknown-key `jack.enroll` with an extra argument `1e999` | continues | `401 unknown_key` (inferred) | continues | none |
| Enroll with an invalid name | audit target empty | audit target is the raw string | audit target empty | none |
| Non-numeric clock | not representable | not representable | freshness and replay off | none |
| Two `Jack-Auth` headers, the first `v2 ...`, fetch adapter used without node | `malformed_auth` | `malformed_auth` | `unsupported_version` (headers are merged) | the raw case only |
| Target with dot segments or an empty query, fetch adapter without node | raw | raw | WHATWG-normalised | none |
| Absolute-form target | full URI | path and query | raw `req.url` | none |
| State-file member `ADMIN` | accepted (inferred) | rejected | rejected | none |
| BOM before the JSON body | 400 (inferred) | 400 (inferred) | 400 | TypeScript unit test only |

Found identical in all three: header grammar, check order, enrollment key checks, body classification, argument
rules, nonce store polarity and expiry, `jack.server.key` arguments, signing strings, Ed25519 strictness.

## Recommendations of the reviewer

**Before the wire format is frozen:** decide on a minimum-notice rule for rotation (M-1); decide whether an
unknown key's invite is checked read-only before the nonce is reserved (the open question F-01 of the review
package; it changes the error order and makes `invalid_invite` unsigned); settle the duplicate-member policy
consistently for the SDKs and the gateway; define target bytes as taken before decoding and reject absolute-form
and fragment before verification; state that numbers outside read members are not range-checked; constrain `aud`
to exclude control characters.

**Before a release:** M-2, L-1, L-2, L-3, L-4 (text or enforcement), L-6, L-7, L-8, I-1.

**What the reviewer would test by running code:** a differential run of the three verifiers over one generated
corpus (including the L-1 input, a BOM, case-variant members and duplicate headers); the M-1 scenario in all three
clients; the TypeScript `NaN` clock; a forward and backward clock step against the volatile stores; `kill -9`
between the intent and final transactions and during the client compare-and-swap; bbolt file growth under
sustained churn; the gateway in front of a Go-struct-decoding upstream; a state file with `ADMIN`; the
release-candidate workflow dispatched from a branch.

## Corrections to our own documentation that the review caused

- "Rotations are at least 48 hours apart" (operations guide, threat model, review package) was wrong; see L-4.
- "Protocol operations are audited" overstated the gateway; see M-2.
- The CHANGELOG sentence that the three server SDKs give one verdict for the same signed request was too strong;
  the differences listed above remain until the cross-language fixes are merged.
- The review package listed a shared small-order-R vector as still missing; it exists in the shared corpus.
