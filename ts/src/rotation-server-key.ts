import { bodyHash, decodeBase64URLFixed } from "./encoding.js";
import { parseCandidateJsonRaw } from "./json-raw.js";
import { nodeField, nodeNumber, nodeObject, nodeText } from "./rotation-json-node.js";
import type { RotationCursor } from "./rotation-page.js";
import { RotationError } from "./rotation-record.js";
import { ROTATION_MAX_PAGE_RECORDS } from "./rotation-result.js";
import type { RotationServerSnapshot } from "./rotation-server-state.js";

/** Structured content of a successful `jack.server.key`; fields describe one immutable snapshot. */
export interface RotationServerKeyPage {
  readonly current: { readonly kid: string; readonly public_key: string };
  readonly records: readonly string[];
  readonly head: { readonly ordinal: number; readonly hash: string };
  readonly complete: boolean;
}

/**
 * Candidate-strict `params.arguments`: exactly after_ordinal and after_hash, no duplicate/null/float.
 * The result is only a request cursor, not checkpoint authority. Any failure -> invalid_params.
 */
export function decodeRotationServerKeyArguments(text: string | undefined): RotationCursor {
  try {
    if (text === undefined) throw new RotationError("invalid_params");
    const root = nodeObject(parseCandidateJsonRaw(text), ["after_ordinal", "after_hash"]);
    const ordinalNode = nodeField(root, "after_ordinal");
    // Literal -0 is the JSON integer zero (Go reference parity); other forms are canonical decimal.
    const ordinal = ordinalNode.text === "-0" ? 0 : nodeNumber(ordinalNode);
    const hash = nodeText(nodeField(root, "after_hash"));
    if (ordinal === 0) {
      if (hash !== "-") throw new RotationError("invalid_params");
    } else {
      decodeBase64URLFixed(hash, 32);
    }
    return Object.freeze({ ordinal, hash });
  } catch {
    throw new RotationError("invalid_params");
  }
}

/** Cursor offset into the retained ring; outside the ring or with a wrong hash -> rotation_checkpoint_unavailable. */
function cursorOffset(snapshot: RotationServerSnapshot, cursor: RotationCursor): number {
  const trust = snapshot.trust;
  const records = trust.records;
  const unavailable = (): never => { throw new RotationError("rotation_checkpoint_unavailable"); };
  if (cursor.ordinal < trust.checkpoint.ordinal || cursor.ordinal > trust.head.ordinal) unavailable();
  const offset = cursor.ordinal - trust.checkpoint.ordinal;
  if (offset > records.length) unavailable();
  const previous = offset === 0 ? undefined : records[offset - 1];
  if (offset !== 0 && previous === undefined) unavailable();
  const expected = previous === undefined ? trust.checkpoint.hash : bodyHash(Buffer.from(previous, "utf8"));
  if (cursor.hash !== expected) unavailable();
  return offset;
}

/** Checks the cursor against the retained ring only; clock and signer remain separate caller gates. */
export function validateRotationServerKeyCursor(snapshot: RotationServerSnapshot, cursor: RotationCursor): void {
  cursorOffset(snapshot, cursor);
}

/**
 * Builds a page from an already validated snapshot and the selected response-signer; no re-reads.
 * The caller must perform the authoritative clock check and signer-eligibility before the call, and the final guard after.
 * cursor outside the ring or with a wrong hash -> rotation_checkpoint_unavailable; signer outside the ring -> rotation_state_unavailable.
 */
export function rotationServerKeyPage(
  snapshot: RotationServerSnapshot,
  cursor: RotationCursor,
  signerPublicKeyB64u: string,
): RotationServerKeyPage {
  const trust = snapshot.trust;
  const records = trust.records;
  const offset = cursorOffset(snapshot, cursor);
  const signer = trust.keys.find((key) => key.publicKeyB64u === signerPublicKeyB64u);
  if (signer === undefined) throw new RotationError("rotation_state_unavailable");
  const end = Math.min(offset + ROTATION_MAX_PAGE_RECORDS, records.length);
  return Object.freeze({
    current: Object.freeze({ kid: signer.kid, public_key: signer.publicKeyB64u }),
    records: Object.freeze(records.slice(offset, end)),
    head: Object.freeze({ ordinal: trust.head.ordinal, hash: trust.head.hash }),
    complete: end === records.length,
  });
}
