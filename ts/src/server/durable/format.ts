/**
 * On-disk format for the durable authenticated nonce store (candidate profile,
 * spec/candidate/durable-nonces.md). The byte format is implementation-local
 * (spec section 3): one sealed JSON document rewritten atomically per
 * transaction (temp + fsync + rename via the shared rotation file owner).
 * Every load is STRICT: exact key sets, typed fields, checked ranges, checksum,
 * duplicate/unsorted rows, cross-set key/operation conflicts and cap overruns
 * all reject the store outright (no repair, no truncation, no eviction).
 */
import { createHash } from "node:crypto";
import { bodyHash, decodeBase64URLFixed, encodeBase64URL } from "../../core/encoding.js";
import { JackError } from "../../core/errors.js";
import { parseCandidateJsonRaw } from "../../core/json-raw.js";
import type { RawJsonNode } from "../../core/json-raw.js";

export const DURABLE_FORMAT_VERSION = 1;
export const DURABLE_MAX_TIMESTAMP = 999999999999;
/** Combined live reservations plus outstanding intents (spec section 6). */
export const DURABLE_MAX_COMBINED = 4096;
/** Unresolved unknown-outcome intents/tombstones (spec section 6). */
export const DURABLE_MAX_TOMBSTONES = 64;
/** Expiry-index removals per purge transaction (spec section 6). */
export const DURABLE_MAX_PURGE = 128;
/** Logical database-file budget (spec section 6). */
export const DURABLE_MAX_FILE_BYTES = 16 * 1024 * 1024;
export const DURABLE_MAX_DEPLOYMENT_BYTES = 1024;

export type DurableRecordKind = "intent" | "live" | "tombstone";

/** Exact committed receipt tuple of spec section 1 (all fields byte-exact). */
export interface DurableReceipt {
  readonly version: number;
  readonly deploymentId: string;
  readonly storeGeneration: number;
  readonly ownerGeneration: number;
  readonly intentId: string;
  /** 16-byte operation id, canonical base64url. */
  readonly operationId: string;
  /** 32-byte kid, canonical base64url. */
  readonly kid: string;
  /** 16-byte nonce, canonical base64url. */
  readonly nonce: string;
  /** 64-byte authenticated signature, canonical base64url. */
  readonly signature: string;
  /** SHA-256 of the exact v1 signing bytes, canonical base64url. */
  readonly requestHash: string;
  readonly timestamp: number;
  readonly retainUntil: number;
  readonly highWater: number;
}

export interface DurableMetadata {
  readonly deployment: string;
  readonly storeId: string;
  readonly generation: number;
  readonly owner: number;
  readonly window: number;
  readonly highWater: number;
  readonly live: number;
  readonly intents: number;
  readonly tombstones: number;
  readonly dirty: boolean;
  readonly unsafe: boolean;
}

export interface DurableDocument {
  readonly meta: DurableMetadata;
  readonly live: readonly DurableReceipt[];
  readonly intents: readonly DurableReceipt[];
  readonly tombstones: readonly DurableReceipt[];
}

export function durableUnavailable(): JackError {
  return new JackError(503, "durability_unavailable", "durable nonce store unavailable");
}

export function durableAdmissionError(status: number, code: string): JackError {
  return new JackError(status, code, "durable admission refused");
}

/** Intent identity of spec section 1: SHA-256 over the domain-separated tuple. */
export function intentIdOf(deployment: string, kidRaw: Uint8Array, nonceRaw: Uint8Array,
  signatureRaw: Uint8Array, requestHashRaw: Uint8Array, operationId: Uint8Array): string {
  const hash = createHash("sha256");
  hash.update("mcp-jack/durable-nonce/intent/v1\n", "ascii");
  const length = Buffer.alloc(2);
  length.writeUInt16BE(Buffer.byteLength(deployment, "utf8"));
  hash.update(length);
  hash.update(deployment, "utf8");
  hash.update(kidRaw);
  hash.update(nonceRaw);
  hash.update(signatureRaw);
  hash.update(requestHashRaw);
  hash.update(operationId);
  return encodeBase64URL(hash.digest());
}

/** Primary key: kid_raw || nonce_raw (48 bytes). */
export function pairKeyOf(kidRaw: Uint8Array, nonceRaw: Uint8Array): Buffer {
  const key = Buffer.alloc(48);
  Buffer.from(kidRaw).copy(key, 0);
  Buffer.from(nonceRaw).copy(key, 32);
  return key;
}

function fail(): never {
  throw new Error("durable: invalid store document");
}

type JsonValue = string | number | boolean | null | JsonValue[] | { readonly [key: string]: JsonValue };

function object(value: JsonValue | undefined): Record<string, JsonValue> {
  if (value === undefined || value === null || Array.isArray(value) || typeof value !== "object") fail();
  return value as Record<string, JsonValue>;
}

function exactKeys(value: Record<string, JsonValue>, names: readonly string[]): void {
  const keys = Object.keys(value).sort();
  if (keys.length !== names.length || names.some((name, index) => keys[index] !== name)) fail();
}

function bool(value: JsonValue | undefined): boolean {
  if (typeof value !== "boolean") fail();
  return value;
}

function int(value: JsonValue | undefined, low: number, high: number): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < low || value > high) fail();
  return value;
}

function text(value: JsonValue | undefined): string {
  if (typeof value !== "string") fail();
  return value;
}

function b64u(value: JsonValue | undefined, size: number): string {
  const s = text(value);
  try {
    decodeBase64URLFixed(s, size);
  } catch {
    fail();
  }
  return s;
}

const META_KEYS = ["deployment", "dirty", "generation", "high_water", "intents", "live", "owner", "store_id",
  "tombstones", "unsafe", "window"].sort();
const DOC_KEYS = ["format_version", "meta", "records"];
const RECORD_KEYS = ["high_water", "intent_id", "kid", "nonce", "operation_id", "owner_generation",
  "request_hash", "retain_until", "signature", "store_generation", "timestamp"].sort();

/** Record validity mirroring durable/record.go validateRecord against the metadata. */
export function validateReceipt(r: DurableReceipt, meta: DurableMetadata): void {
  if (r.version !== DURABLE_FORMAT_VERSION || r.deploymentId !== meta.deployment ||
    r.storeGeneration !== meta.generation || r.ownerGeneration === 0 || r.ownerGeneration > meta.owner) fail();
  if (meta.window < 1 || meta.window > 120) fail();
  const kidRaw = decodeBase64URLFixed(r.kid, 32);
  const nonceRaw = decodeBase64URLFixed(r.nonce, 16);
  const signatureRaw = decodeBase64URLFixed(r.signature, 64);
  const requestHashRaw = decodeBase64URLFixed(r.requestHash, 32);
  const operationId = decodeBase64URLFixed(r.operationId, 16);
  if (r.intentId !== intentIdOf(meta.deployment, kidRaw, nonceRaw, signatureRaw, requestHashRaw, operationId)) fail();
  if (r.timestamp < 0 || r.timestamp > DURABLE_MAX_TIMESTAMP - meta.window) fail();
  if (r.retainUntil !== r.timestamp + meta.window) fail();
  if (r.highWater < 0 || r.highWater > meta.highWater || r.highWater > DURABLE_MAX_TIMESTAMP) fail();
  const difference = r.highWater - r.timestamp;
  if (difference > meta.window || -difference > meta.window) fail();
}

function decodeReceipt(value: JsonValue, meta: DurableMetadata): DurableReceipt {
  const obj = object(value);
  exactKeys(obj, RECORD_KEYS);
  const receipt: DurableReceipt = {
    version: DURABLE_FORMAT_VERSION,
    deploymentId: meta.deployment,
    storeGeneration: int(obj["store_generation"], 1, Number.MAX_SAFE_INTEGER),
    ownerGeneration: int(obj["owner_generation"], 1, Number.MAX_SAFE_INTEGER),
    intentId: b64u(obj["intent_id"], 32),
    operationId: b64u(obj["operation_id"], 16),
    kid: b64u(obj["kid"], 32),
    nonce: b64u(obj["nonce"], 16),
    signature: b64u(obj["signature"], 64),
    requestHash: b64u(obj["request_hash"], 32),
    timestamp: int(obj["timestamp"], 0, DURABLE_MAX_TIMESTAMP),
    retainUntil: int(obj["retain_until"], 0, DURABLE_MAX_TIMESTAMP),
    highWater: int(obj["high_water"], 0, DURABLE_MAX_TIMESTAMP),
  };
  validateReceipt(receipt, meta);
  return receipt;
}

function keyOf(row: DurableReceipt): string {
  return pairKeyOf(decodeBase64URLFixed(row.kid, 32), decodeBase64URLFixed(row.nonce, 16)).toString("latin1");
}

/** Sorted load of one row set: order by primary key, duplicates rejected. */
function decodeRecordSet(value: JsonValue | undefined, meta: DurableMetadata): DurableReceipt[] {
  if (!Array.isArray(value)) fail();
  const rows: DurableReceipt[] = [];
  let previous = "";
  for (const entry of value) {
    const row = decodeReceipt(entry, meta);
    const key = keyOf(row);
    if (key <= previous) fail();
    previous = key;
    rows.push(row);
  }
  return rows;
}

function decodeMeta(value: JsonValue | undefined): DurableMetadata {
  const obj = object(value);
  exactKeys(obj, META_KEYS);
  const deployment = text(obj["deployment"]);
  const deploymentBytes = Buffer.byteLength(deployment, "utf8");
  if (deploymentBytes === 0 || deploymentBytes > DURABLE_MAX_DEPLOYMENT_BYTES) fail();
  const meta: DurableMetadata = {
    deployment,
    storeId: b64u(obj["store_id"], 16),
    generation: int(obj["generation"], 1, Number.MAX_SAFE_INTEGER),
    owner: int(obj["owner"], 1, Number.MAX_SAFE_INTEGER),
    window: int(obj["window"], 1, 120),
    highWater: int(obj["high_water"], 0, DURABLE_MAX_TIMESTAMP),
    live: int(obj["live"], 0, DURABLE_MAX_COMBINED),
    intents: int(obj["intents"], 0, DURABLE_MAX_COMBINED),
    tombstones: int(obj["tombstones"], 0, DURABLE_MAX_TOMBSTONES),
    dirty: bool(obj["dirty"]),
    unsafe: bool(obj["unsafe"]),
  };
  if (meta.live + meta.intents > DURABLE_MAX_COMBINED) fail();
  return meta;
}

function receiptRow(r: DurableReceipt): Record<string, JsonValue> {
  return {
    kid: r.kid,
    nonce: r.nonce,
    intent_id: r.intentId,
    operation_id: r.operationId,
    signature: r.signature,
    request_hash: r.requestHash,
    timestamp: r.timestamp,
    retain_until: r.retainUntil,
    high_water: r.highWater,
    store_generation: r.storeGeneration,
    owner_generation: r.ownerGeneration,
  };
}

/** Sealed encoding: the checksum detects accidental corruption, not a MAC. */
export function encodeDocument(doc: DurableDocument): Uint8Array {
  const meta = {
    deployment: doc.meta.deployment,
    store_id: doc.meta.storeId,
    generation: doc.meta.generation,
    owner: doc.meta.owner,
    window: doc.meta.window,
    high_water: doc.meta.highWater,
    live: doc.live.length,
    intents: doc.intents.length,
    tombstones: doc.tombstones.length,
    dirty: doc.meta.dirty,
    unsafe: doc.meta.unsafe,
  };
  const records = {
    intents: doc.intents.map(receiptRow),
    live: doc.live.map(receiptRow),
    tombstones: doc.tombstones.map(receiptRow),
  };
  const payload = JSON.stringify({ format_version: DURABLE_FORMAT_VERSION, meta, records });
  const bytes = Buffer.from(JSON.stringify({ payload, checksum: bodyHash(Buffer.from(payload, "utf8")) }), "utf8");
  if (bytes.length > DURABLE_MAX_FILE_BYTES) fail();
  return bytes;
}

/** Strict load: unknown/missing fields, wrong types, checksum, caps, duplicates, cross-set conflicts.
 * Spec section 3 canonical bytes: the strict raw parser rejects duplicate members at every nesting
 * level and trailing content after the document (Go refuses trailing bytes the same way via exact
 * stream consumption, durable/metadata.go and durable/record.go); the final re-encode comparison
 * rejects whitespace and noncanonical number spellings, mirroring Go's exact-length binary layout. */
export function decodeDocument(bytes: Uint8Array): DurableDocument {
  if (bytes.length === 0 || bytes.length > DURABLE_MAX_FILE_BYTES) fail();
  const input = Buffer.from(bytes);
  let outer: JsonValue;
  try {
    const raw: RawJsonNode = parseCandidateJsonRaw(input.toString("utf8"));
    outer = raw.value;
  } catch {
    fail();
  }
  const sealed = object(outer);
  const keys = Object.keys(sealed).sort();
  if (keys.length !== 2 || keys[0] !== "checksum" || keys[1] !== "payload") fail();
  const payload = text(sealed["payload"]);
  if (bodyHash(Buffer.from(payload, "utf8")) !== text(sealed["checksum"])) fail();
  let doc: JsonValue;
  try {
    doc = parseCandidateJsonRaw(payload).value;
  } catch {
    fail();
  }
  const obj = object(doc);
  exactKeys(obj, DOC_KEYS);
  if (int(obj["format_version"], 0, 255) !== DURABLE_FORMAT_VERSION) fail();
  const meta = decodeMeta(obj["meta"]);
  const records = object(obj["records"]);
  exactKeys(records, ["intents", "live", "tombstones"]);
  const live = decodeRecordSet(records["live"], meta);
  const intents = decodeRecordSet(records["intents"], meta);
  const tombstones = decodeRecordSet(records["tombstones"], meta);
  if (live.length !== meta.live || intents.length !== meta.intents || tombstones.length !== meta.tombstones) fail();
  // Cross-set agreement: a pair and an operation id may appear exactly once overall.
  const seenKeys = new Set<string>();
  const seenOperations = new Set<string>();
  for (const rows of [live, intents, tombstones]) {
    for (const row of rows) {
      const key = keyOf(row);
      if (seenKeys.has(key) || seenOperations.has(row.operationId)) fail();
      seenKeys.add(key);
      seenOperations.add(row.operationId);
    }
  }
  const decoded: DurableDocument = { meta, live, intents, tombstones };
  // Canonical-bytes gate: only byte-identical re-encoding of the decoded document may load.
  if (Buffer.compare(input, Buffer.from(encodeDocument(decoded))) !== 0) fail();
  return decoded;
}

/** Sorted-array key used by every row mutation. */
export function sortKeyOf(row: DurableReceipt): string {
  return keyOf(row);
}

/** Insert into a key-sorted row set; a duplicate key is store corruption. */
export function insertSorted(rows: readonly DurableReceipt[], row: DurableReceipt): DurableReceipt[] {
  const key = keyOf(row);
  const before: DurableReceipt[] = [];
  let index = 0;
  while (index < rows.length) {
    const existing = rows[index] as DurableReceipt;
    const existingKey = keyOf(existing);
    if (existingKey === key) fail();
    if (existingKey > key) break;
    before.push(existing);
    index++;
  }
  return [...before, row, ...rows.slice(index)];
}

/** Remove the row with the exact key, if present. */
export function removeSorted(rows: readonly DurableReceipt[], key: string): DurableReceipt[] {
  return rows.filter((row) => keyOf(row) !== key);
}

/** Find the row with the exact key, if present. */
export function findSorted(rows: readonly DurableReceipt[], key: string): DurableReceipt | undefined {
  return rows.find((row) => keyOf(row) === key);
}