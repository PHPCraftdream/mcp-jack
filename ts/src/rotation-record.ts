import { validatePublicKey, verify } from "./ed25519.js";
import { rotationBindingError } from "./rotation-binding.js";
import { bodyHash, decodeBase64URL, decodeBase64URLFixed, keyId } from "./encoding.js";

export const ROTATION_DOMAIN = "mcp-jack/server-key-rotation/min1";
export const ROTATION_GRACE_SECONDS = 172800;
export const ROTATION_MAX_TIMESTAMP = 999999999999;
export const ROTATION_MAX_ORDINAL = Number.MAX_SAFE_INTEGER;
export const ROTATION_MAX_RECORD_BYTES = 8192;

export class RotationError extends Error {
  constructor(readonly code: string) {
    super(`jack: candidate rotation ${code}`);
    this.name = "RotationError";
  }
}

export interface RotationBinding {
  readonly endpoint: string;
  readonly aud: string;
}

// Только immutable значения: вызывающий код не получает изменяемые key/proof buffers.
export interface RotationRecord {
  readonly ordinal: number;
  readonly previousHash: string;
  readonly oldKid: string;
  readonly newKid: string;
  readonly publicKeyB64u: string;
  readonly publishedAt: number;
  readonly activatesAt: number;
  readonly wire: string;
  readonly hash: string;
}

const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

function reject(code: string): never {
  throw new RotationError(code);
}

function decimal(text: string, maximum: number, code: string): number {
  if (text.length > String(maximum).length || !/^(0|[1-9][0-9]*)$/.test(text)) reject(code);
  const value = Number(text);
  if (!Number.isSafeInteger(value) || value > maximum) reject(code);
  return value;
}

function decode(text: string, size: number | undefined, code: string): Uint8Array {
  try {
    return size === undefined ? decodeBase64URL(text) : decodeBase64URLFixed(text, size);
  } catch {
    return reject(code);
  }
}

function decodeText(bytes: Uint8Array): string {
  try {
    return utf8.decode(bytes);
  } catch {
    return reject("utf8");
  }
}

/** Candidate codec: не меняет trust, не выбирает outer carrier, не выполняет fetch. */
export function parseRotationRecord(
  wire: Uint8Array,
  binding: RotationBinding,
  authorizers: ReadonlyMap<string, string>,
): RotationRecord {
  if (!(wire instanceof Uint8Array) || wire.length === 0 || wire.length > ROTATION_MAX_RECORD_BYTES) reject("record_size");
  const bytes = Buffer.from(wire);
  if (bytes.some((byte) => byte > 127)) reject("non_ascii");
  const text = bytes.toString("ascii");
  if (text.endsWith("\n")) reject("trailing_lf");
  const lines = text.split("\n");
  if (lines.length !== 12) reject("line_count");
  // Проверка length выше гарантирует существование всех двенадцати строк.
  const line = (index: number): string => lines[index] as string;
  if (line(0) !== ROTATION_DOMAIN) reject("domain");
  const ordinal = decimal(line(3), ROTATION_MAX_ORDINAL, "ordinal");
  if (ordinal === 0) reject("ordinal");
  const publishedAt = decimal(line(8), ROTATION_MAX_TIMESTAMP, "timestamp");
  const activatesAt = decimal(line(9), ROTATION_MAX_TIMESTAMP, "timestamp");
  const bindingError = rotationBindingError(binding);
  if (bindingError !== undefined) reject(bindingError);
  const endpoint = decode(line(1), undefined, "binding_encoding");
  const aud = decode(line(2), undefined, "binding_encoding");
  if (endpoint.length < 1 || endpoint.length > 2048 || aud.length < 1 || aud.length > 1024) reject("binding_encoding");
  if (decodeText(endpoint) !== binding.endpoint || decodeText(aud) !== binding.aud) reject("binding");
  const oldKid = line(5);
  const newKid = line(6);
  decode(oldKid, 32, "key_id");
  decode(newKid, 32, "key_id");
  const publicKeyB64u = line(7);
  if (publicKeyB64u.length !== 43) reject("base64url");
  const publicKey = decode(publicKeyB64u, 32, "new_key");
  if (validatePublicKey(publicKey) !== null) reject("new_key");
  if (keyId(publicKey) !== newKid) reject("new_key_id");
  const nextProof = decode(line(10), 64, "proof_encoding");
  const oldProof = decode(line(11), 64, "proof_encoding");
  if (publishedAt > ROTATION_MAX_TIMESTAMP - ROTATION_GRACE_SECONDS || activatesAt !== publishedAt + ROTATION_GRACE_SECONDS) reject("activation");
  const oldPublicText = authorizers.get(oldKid);
  if (oldPublicText === undefined) reject("unknown_authorizer");
  const oldPublic = decode(oldPublicText, 32, "unknown_authorizer");
  if (keyId(oldPublic) !== oldKid || validatePublicKey(oldPublic) !== null) reject("unknown_authorizer");
  const body = lines.slice(0, 10).join("\n");
  if (!verify(publicKey, Buffer.from(`${ROTATION_DOMAIN}/next-proof\n${body}`, "ascii"), nextProof)) reject("new_proof");
  if (!verify(oldPublic, Buffer.from(`${ROTATION_DOMAIN}/authorize\n${body}\n${line(10)}`, "ascii"), oldProof)) reject("old_authorization");
  return Object.freeze({ ordinal, previousHash: line(4), oldKid, newKid, publicKeyB64u, publishedAt, activatesAt, wire: text, hash: bodyHash(bytes) });
}
