import type { RawJsonNode } from "../../core/json-raw.js";
import { RotationError, ROTATION_MAX_ORDINAL } from "../wire/record.js";

// Internal strict-node helpers of the local rotation codecs; not a public API.
function fail(): never {
  throw new RotationError("rotation_state_unknown");
}

/** Exactly the listed members, nothing extra; duplicates are already rejected by the candidate parser. */
export function nodeObject(node: RawJsonNode, names: readonly string[]): ReadonlyMap<string, RawJsonNode> {
  const members = node.members;
  if (members === undefined || members.size !== names.length || names.some((name) => !members.has(name))) fail();
  return members;
}

export function nodeField(members: ReadonlyMap<string, RawJsonNode>, name: string): RawJsonNode {
  const value = members.get(name);
  if (value === undefined) fail();
  return value;
}

export function nodeText(node: RawJsonNode): string {
  if (typeof node.value !== "string") fail();
  return node.value;
}

/** Canonical non-negative integer in the safe-integer domain; exponent/fraction/sign are rejected. */
export function nodeNumber(node: RawJsonNode): number {
  if (node.text.length > 16 || !/^(0|[1-9][0-9]*)$/.test(node.text) || typeof node.value !== "number" ||
    !Number.isSafeInteger(node.value) || node.value > ROTATION_MAX_ORDINAL) fail();
  return node.value;
}

export function nodeBoolean(node: RawJsonNode): boolean {
  if (typeof node.value !== "boolean") fail();
  return node.value;
}
