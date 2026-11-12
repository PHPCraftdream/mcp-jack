import { validatePublicKey } from "./ed25519.js";
import { decodeBase64URLFixed, keyId } from "./encoding.js";
import { parseCandidateJsonRaw } from "./json-raw.js";
import type { RawJsonNode } from "./json-raw.js";
import { RotationError, ROTATION_MAX_ORDINAL } from "./rotation-record.js";

export const ROTATION_MAX_BODY_BYTES = 256 * 1024;
export const ROTATION_MAX_PAGE_RECORDS = 16;

/** Только decoded данные; это не ACKed trust snapshot и не доказательство carrier trust. */
export interface DecodedRotationResult {
  readonly current: { readonly kid: string; readonly publicKeyB64u: string };
  readonly records: readonly string[];
  readonly head: { readonly ordinal: number; readonly hash: string };
  readonly complete: boolean;
}

const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

function invalid(): never {
  throw new RotationError("rotation_result_invalid");
}

function object(node: RawJsonNode, fields: readonly string[]): ReadonlyMap<string, RawJsonNode> {
  const members = node.members;
  if (members === undefined || members.size !== fields.length || fields.some((field) => !members.has(field))) invalid();
  return members;
}

function field(members: ReadonlyMap<string, RawJsonNode>, name: string): RawJsonNode {
  const node = members.get(name);
  if (node === undefined) invalid();
  return node;
}

function string(node: RawJsonNode): string {
  if (typeof node.value !== "string") invalid();
  return node.value;
}

function structured(node: RawJsonNode): DecodedRotationResult {
  const members = object(node, ["current", "records", "head", "complete"]);
  const current = object(field(members, "current"), ["kid", "public_key"]);
  const kid = string(field(current, "kid"));
  const publicKeyB64u = string(field(current, "public_key"));
  const publicKey = decodeBase64URLFixed(publicKeyB64u, 32);
  if (validatePublicKey(publicKey) !== null || keyId(publicKey) !== kid) invalid();
  const head = object(field(members, "head"), ["ordinal", "hash"]);
  const ordinalNode = field(head, "ordinal");
  if (ordinalNode.text.length > 16 || !/^(0|[1-9][0-9]*)$/.test(ordinalNode.text) || typeof ordinalNode.value !== "number" || !Number.isSafeInteger(ordinalNode.value) || ordinalNode.value > ROTATION_MAX_ORDINAL) invalid();
  const ordinal = ordinalNode.value;
  const hash = string(field(head, "hash"));
  if (ordinal === 0) {
    if (hash !== "-") invalid();
  } else {
    decodeBase64URLFixed(hash, 32);
  }
  const records = field(members, "records").items;
  if (records === undefined || records.length > ROTATION_MAX_PAGE_RECORDS) invalid();
  const complete = field(members, "complete").value;
  if (typeof complete !== "boolean") invalid();
  return Object.freeze({
    current: Object.freeze({ kid, publicKeyB64u }),
    records: Object.freeze(records.map(string)),
    head: Object.freeze({ ordinal, hash }),
    complete,
  });
}

function same(left: RawJsonNode, right: RawJsonNode): boolean {
  if (left.members !== undefined || right.members !== undefined) {
    if (left.members === undefined || right.members === undefined || left.members.size !== right.members.size) return false;
    for (const [name, child] of left.members) {
      const other = right.members.get(name);
      if (other === undefined || !same(child, other)) return false;
    }
    return true;
  }
  if (left.items !== undefined || right.items !== undefined) {
    return left.items !== undefined && right.items !== undefined && left.items.length === right.items.length && left.items.every((child, index) => {
      const other = right.items?.[index];
      return other !== undefined && same(child, other);
    });
  }
  if (typeof left.value === "number" || typeof right.value === "number") return typeof left.value === "number" && typeof right.value === "number" && left.text === right.text;
  return left.value === right.value;
}

/**
 * Вызывать только ПОСЛЕ outer authentication, known-key interval и ClockGuard gates.
 * Проверяет только schema/parity/limits; не records/proofs/cursor/gaps/current binding,
 * не carrier trust, persistence, ACK, fetch или refresh. Signed errors обрабатывает caller.
 * Numeric request ID сопоставляется с exact JSON.stringify lexeme SDK request.
 */
export function decodeRotationResult(body: Uint8Array, expectedId: string | number): DecodedRotationResult {
  try {
    if (!(body instanceof Uint8Array) || body.length === 0 || body.length > ROTATION_MAX_BODY_BYTES || (typeof expectedId !== "string" && (typeof expectedId !== "number" || !Number.isFinite(expectedId)))) invalid();
    const root = object(parseCandidateJsonRaw(utf8.decode(body)), ["jsonrpc", "id", "result"]);
    const id = field(root, "id");
    if (field(root, "jsonrpc").value !== "2.0" || id.value !== expectedId) invalid();
    if (typeof expectedId === "number" && id.text !== JSON.stringify(expectedId)) invalid();
    const result = object(field(root, "result"), ["content", "structuredContent", "isError"]);
    if (field(result, "isError").value !== false) invalid();
    const content = field(result, "content").items;
    if (content === undefined || content.length !== 1 || content[0] === undefined) invalid();
    const item = object(content[0], ["type", "text"]);
    if (field(item, "type").value !== "text") invalid();
    const payload = field(result, "structuredContent");
    const textPayload = parseCandidateJsonRaw(string(field(item, "text")));
    const decoded = structured(payload);
    structured(textPayload);
    if (!same(payload, textPayload)) invalid();
    return decoded;
  } catch {
    return invalid();
  }
}
