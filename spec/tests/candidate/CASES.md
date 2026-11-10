# Candidate source cases

Generated from the hand-stated source expectations; this index is not a verifier or reference-model result.

## Rotation record negative cases (19)

| Case | Source note | Hand-stated expectation |
|---|---|---|
| `bad-domain` | wrong exact domain | `{"expected":"domain"}` |
| `binding-endpoint` | endpoint differs by one trailing slash | `{"expected":"binding"}` |
| `binding-audience` | audience differs by one trailing slash | `{"expected":"binding"}` |
| `ordinal-gap` | ordinal starts at 2 with valid proof; verify as chain | `{"expected":"ordinal_sequence"}` |
| `ordinal-leading-zero` | ordinal has a leading zero | `{"expected":"ordinal"}` |
| `previous-full-hash` | wrong previous complete record digest; verify as chain | `{"expected":"previous_hash"}` |
| `adjacent-authorizer` | R2 is validly signed by known K0 but violates the sequential K0>K1 authorization edge | `{"expected":"adjacency"}` |
| `new-key-id` | new kid does not hash the new admitted key | `{"expected":"new_key_id"}` |
| `activation-arithmetic` | activation differs from checked P+172800 | `{"expected":"activation"}` |
| `timestamp-overflow` | checked P+172800 exceeds 12-digit domain | `{"expected":"timestamp"}` |
| `new-possession-proof` | new proof signature byte changed while encoding remains canonical | `{"expected":"new_proof"}` |
| `old-authorization-proof` | old authorization signature byte changed while encoding remains canonical | `{"expected":"old_authorization"}` |
| `base64url-padding` | public key has padding | `{"expected":"base64url"}` |
| `key-id-unused-bits` | kid has nonzero unused base64url bits | `{"expected":"key_id"}` |
| `trailing-lf` | record has terminal line feed | `{"expected":"trailing_lf"}` |
| `invalid-utf8` | invalid non-ASCII byte | `{"expected":"non_ascii"}` |
| `record-size-cap` | decoded record exceeds 8192 bytes | `{"expected":"record_size"}` |
| `retained-key-reuse` | R1 has valid proof and predecessor authorization but repeats K0 | `{"expected":"key_reuse"}` |
| `decreasing-publication-time` | P2<P1 with valid adjacent proofs; verify as chain | `{"expected":"publication_order"}` |

## Durable nonce events (24)

| Case | Source note | Hand-stated expectation |
|---|---|---|
| `same-second-restart-replay` | The same authenticated request is denied after restart; clock high-water is equal, so no write. | `{"status":401,"code":"replayed_nonce","callbacks":0,"writes":0,"dispatches":0,"highWater":100,"liveCount":1,"intentCount":0,"tombstoneCount":0,"fenced":false,"effects":{"authorization":0,"handler":0,"stateMutation":0}}` |
| `future-ts-restart-replay` | A future-but-fresh timestamp remains replayed after restart. | `{"status":401,"code":"replayed_nonce","callbacks":0,"writes":0,"dispatches":0,"highWater":101,"liveCount":1,"intentCount":0,"tombstoneCount":0,"fenced":false,"effects":{"authorization":0,"handler":0,"stateMutation":0}}` |
| `concurrent-same-pair` | The serialized model processes two arrivals in order; one final commit and one dispatch result. | `{"statuses":[[200,"committed"],[401,"replayed_nonce"]],"confirmedCommits":1,"callbacks":[2,0],"writes":[2,0],"dispatches":[1,0],"highWater":100,"liveCount":1,"intentCount":0,"tombstoneCount":0,"effects":{"authorization":1,"handler":1,"stateMutation":0}}` |
| `concurrent-different-request-identity` | A different signed request identity cannot reuse a committed pair; serialized model yields one final commit. | `{"statuses":[[200,"committed"],[401,"replayed_nonce"]],"confirmedCommits":1,"callbacks":[2,0],"writes":[2,0],"dispatches":[1,0],"highWater":100,"liveCount":1,"intentCount":0,"tombstoneCount":0,"effects":{"authorization":1,"handler":1,"stateMutation":0}}` |
| `expiry-equality` | retainUntil=130 remains live at now=130. | `{"status":401,"code":"replayed_nonce","callbacks":0,"writes":0,"dispatches":0,"highWater":129,"liveCount":1,"intentCount":0,"tombstoneCount":0,"fenced":false,"effects":{"authorization":0,"handler":0,"stateMutation":0}}` |
| `expiry-plus-one-fresh-timestamp` | At 131, after H advances, same pair with fresh ts=131 is reusable. | `{"status":200,"code":"committed","callbacks":2,"writes":2,"dispatches":1,"highWater":131,"liveCount":1,"intentCount":0,"tombstoneCount":0,"fenced":false,"effects":{"authorization":1,"handler":1,"stateMutation":0}}` |
| `delayed-crypto-final-freshness` | The fresh sample before intent is 131; no intent commit or handler effect. | `{"status":401,"code":"timestamp_out_of_window","callbacks":0,"writes":0,"dispatches":0,"highWater":0,"liveCount":0,"intentCount":0,"tombstoneCount":0,"fenced":false,"effects":{"authorization":0,"handler":0,"stateMutation":0}}` |
| `delayed-final-after-confirmed-intent` | Intent at 100 is committed; final sample 131 yields confirmed final abort and cleanup. | `{"status":401,"code":"timestamp_out_of_window","callbacks":2,"writes":2,"dispatches":0,"highWater":100,"liveCount":0,"intentCount":0,"tombstoneCount":0,"fenced":false,"effects":{"authorization":0,"handler":0,"stateMutation":0}}` |
| `purge-highwater-rollback` | Restart raw 215 below durable H=216 latches the unsafe clock fence before absence. | `{"status":503,"code":"clock_unsafe","callbacks":1,"writes":1,"dispatches":0,"highWater":216,"liveCount":0,"intentCount":0,"tombstoneCount":0,"fenced":true,"effects":{"authorization":0,"handler":0,"stateMutation":0}}` |
| `window-decrease-refused` | W=15 cannot replace stored W=30. | `{"status":503,"code":"state_changed","callbacks":0,"writes":0,"dispatches":0,"highWater":0,"liveCount":0,"intentCount":0,"tombstoneCount":0,"fenced":false,"effects":{"authorization":0,"handler":0,"stateMutation":0}}` |
| `window-increase-refused` | W=30 cannot replace stored W=15. | `{"status":503,"code":"state_changed","callbacks":0,"writes":0,"dispatches":0,"highWater":0,"liveCount":0,"intentCount":0,"tombstoneCount":0,"fenced":false,"effects":{"authorization":0,"handler":0,"stateMutation":0}}` |
| `generation-change-zero-commit` | Owner generation mismatch is rejected before intent. | `{"status":503,"code":"state_changed","callbacks":0,"writes":0,"dispatches":0,"highWater":0,"liveCount":0,"intentCount":0,"tombstoneCount":0,"fenced":false,"effects":{"authorization":0,"handler":0,"stateMutation":0}}` |
| `key-snapshot-change-zero-commit` | Captured active-key snapshot differs after cryptography. | `{"status":503,"code":"state_changed","callbacks":0,"writes":0,"dispatches":0,"highWater":0,"liveCount":0,"intentCount":0,"tombstoneCount":0,"fenced":false,"effects":{"authorization":0,"handler":0,"stateMutation":0}}` |
| `enrollment-snapshot-change-zero-commit` | Pending enrollment state differs at the final gate. | `{"status":503,"code":"state_changed","callbacks":0,"writes":0,"dispatches":0,"highWater":0,"liveCount":0,"intentCount":0,"tombstoneCount":0,"fenced":false,"effects":{"authorization":0,"handler":0,"stateMutation":0}}` |
| `bad-signature-zero-writes` | Invalid signature exits before every durable callback/write. | `{"status":401,"code":"bad_signature","callbacks":0,"writes":0,"dispatches":0,"highWater":0,"liveCount":0,"intentCount":0,"tombstoneCount":0,"fenced":false,"effects":{"authorization":0,"handler":0,"stateMutation":0}}` |
| `commit-then-authorization-refusal` | Authorization refusal follows confirmed commit and keeps pair consumed. | `{"status":403,"code":"authorization_refused","callbacks":2,"writes":2,"dispatches":0,"highWater":100,"liveCount":1,"intentCount":0,"tombstoneCount":0,"fenced":false,"effects":{"authorization":1,"handler":0,"stateMutation":0}}` |
| `crash-after-commit-no-dispatch` | A committed reservation survives crash before handler dispatch. | `{"status":503,"code":"durability_unavailable","callbacks":2,"writes":2,"dispatches":0,"highWater":100,"liveCount":1,"intentCount":0,"tombstoneCount":0,"fenced":false,"effects":{"authorization":0,"handler":0,"stateMutation":0}}` |
| `definite-abort-confirmed-cleanup` | Confirmed abort and confirmed intent cleanup have no nonce or effects. | `{"status":503,"code":"durability_unavailable","callbacks":2,"writes":2,"dispatches":0,"highWater":100,"liveCount":0,"intentCount":0,"tombstoneCount":0,"fenced":false,"effects":{"authorization":0,"handler":0,"stateMutation":0}}` |
| `unknown-final-present` | Unknown final outcome with reservation found fences and never dispatches. | `{"status":503,"code":"durability_unavailable","callbacks":2,"writes":2,"dispatches":0,"highWater":100,"liveCount":0,"intentCount":0,"tombstoneCount":1,"fenced":true,"effects":{"authorization":0,"handler":0,"stateMutation":0},"tombstoneOutcome":"unknown_found"}` |
| `unknown-final-absent` | Unknown final outcome absent after restart still records terminal no-redelivery. | `{"status":503,"code":"durability_unavailable","callbacks":2,"writes":2,"dispatches":0,"highWater":100,"liveCount":0,"intentCount":0,"tombstoneCount":1,"fenced":true,"effects":{"authorization":0,"handler":0,"stateMutation":0},"tombstoneOutcome":"unknown_absent"}` |
| `unknown-intent-absent` | Unknown intent creation with absent row remains manually fenced, never auto-retries. | `{"status":503,"code":"durability_unavailable","callbacks":1,"writes":1,"dispatches":0,"highWater":100,"liveCount":0,"intentCount":0,"tombstoneCount":0,"fenced":true,"effects":{"authorization":0,"handler":0,"stateMutation":0},"reconciliation":"manual_fence"}` |
| `capacity-live-plus-intent` | 4096 live reservations fill capacity; authoritative replay/capacity lookup refuses without eviction. | `{"status":503,"code":"capacity_exhausted","callbacks":0,"writes":0,"dispatches":0,"highWater":0,"liveCount":4096,"intentCount":0,"tombstoneCount":0,"fenced":false,"effects":{"authorization":0,"handler":0,"stateMutation":0},"preserveLive":true}` |
| `capacity-tombstones` | 64 unresolved tombstones refuse without eviction. | `{"status":503,"code":"capacity_exhausted","callbacks":0,"writes":0,"dispatches":0,"highWater":0,"liveCount":0,"intentCount":0,"tombstoneCount":64,"fenced":false,"effects":{"authorization":0,"handler":0,"stateMutation":0},"preserveTombstones":true}` |
| `no-effects-without-final-commit` | A prepared intent is never dispatch permission when final outcome is unknown. | `{"status":503,"code":"durability_unavailable","callbacks":2,"writes":2,"dispatches":0,"highWater":100,"liveCount":0,"intentCount":0,"tombstoneCount":1,"fenced":true,"effects":{"authorization":0,"handler":0,"stateMutation":0},"tombstoneOutcome":"unknown_absent"}` |

## Rotation client cases (14)

| Case | Source note | Hand-stated expectation |
|---|---|---|
| `first-bridge-before-cutoff` | — | `{"error":null,"callbacks":1,"committed":true,"ackOrdinal":1,"carrierTrusted":true}` |
| `first-bridge-at-cutoff` | — | `{"error":"rotation_bridge_expired","callbacks":0,"committed":false,"ackOrdinal":0}` |
| `unknown-outer-before-invalid-payload` | — | `{"error":"unknown_server_key","callbacks":0,"committed":false,"ackOrdinal":0}` |
| `exact-duplicate-at-new-key-lower-bound` | — | `{"error":null,"callbacks":0,"duplicate":true,"ackOrdinal":1,"carrierTrusted":true}` |
| `new-key-lower-bound-minus-one-is-stale` | — | `{"error":"timestamp_out_of_window","callbacks":0,"committed":false,"ackOrdinal":1}` |
| `duplicate-prefix-then-extension` | — | `{"error":null,"callbacks":1,"committed":true,"ackOrdinal":2,"carrierTrusted":true}` |
| `trust-callback-definite-conflict` | — | `{"error":"rotation_state_changed","callbacks":1,"committed":false,"ackOrdinal":1}` |
| `trust-callback-unknown-fences` | — | `{"error":"rotation_state_unknown","callbacks":1,"committed":false,"ackOrdinal":1,"fenced":true}` |
| `late-callback-ack-retains-snapshot-but-rejects-carrier` | — | `{"error":"rotation_key_interval","callbacks":1,"committed":true,"ackOrdinal":1,"carrierTrusted":false}` |
| `conflicting-duplicate-prefix-is-not-adopted` | — | `{"error":"rotation_conflict","callbacks":0,"committed":false,"ackOrdinal":1}` |
| `gapped-prefix-cannot-be-claimed-by-head` | — | `{"error":"rotation_gap","callbacks":0,"committed":false,"ackOrdinal":0}` |
| `busy-writer-stops-before-trust-callback` | — | `{"error":"rotation_state_changed","callbacks":0,"committed":false,"ackOrdinal":1}` |
| `stale-whole-snapshot-stops-before-callback` | — | `{"error":"rotation_state_changed","callbacks":0,"committed":false,"ackOrdinal":1}` |
| `whole-response-body-cap-plus-one` | — | `{"error":"rotation_result_invalid","callbacks":0,"committed":false,"ackOrdinal":0}` |

## Rotation event cases (8)

| Case | Source note | Hand-stated expectation |
|---|---|---|
| `same-second-greatest-ordinal-wins` | — | `{"selectedBefore":0,"selectedAt":2,"selectedAfter":2}` |
| `clock-rollback-latches` | — | `{"error":"rotation_clock_unsafe","highWater":173800,"unsafe":true,"writes":1,"callbacks":1}` |
| `clock-equal-is-noop` | — | `{"error":null,"highWater":173800,"revision":4,"unsafe":false,"writes":0,"callbacks":0}` |
| `clock-rollback-latch-unknown-is-unavailable` | — | `{"error":"rotation_clock_unavailable","highWater":173800,"unsafe":false,"revision":4,"writes":1,"callbacks":1}` |
| `clock-advance-persists-revision` | — | `{"error":null,"highWater":173801,"revision":5,"writes":1,"callbacks":1}` |
| `server-final-eligible-single-signature` | — | `{"emit":true,"signatures":1,"resigns":0}` |
| `server-final-cutoff-no-resign` | — | `{"emit":false,"signatures":1,"resigns":0}` |
| `server-final-generation-fence-no-fallback` | — | `{"emit":false,"signatures":1,"resigns":0}` |

