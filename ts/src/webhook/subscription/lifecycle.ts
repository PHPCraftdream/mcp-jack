import { parseWhsec } from "../crypto/primitives.js";
import type { ActiveSecret } from "../crypto/signatures.js";

/** The default subscription lifetime in milliseconds (spec 06 R8.5). */
export const DEFAULT_TTL_MS = 3600000;
/** The minimum finite subscription lifetime in milliseconds (spec 06 R8.5). */
export const MIN_TTL_MS = 60000;
/** The maximum finite subscription lifetime in milliseconds (spec 06 R8.5). */
export const MAX_TTL_MS = 86400000;
/** The maximum length of a replay cursor (spec 06 R8.9). */
export const CURSOR_MAX_LENGTH = 512;

/** A granted subscription lifetime and refresh deadline, or an invalid TTL. */
export type TtlGrantResult =
  | { readonly ok: true; readonly grantMs: number | null; readonly refreshBefore: string | null }
  | { readonly ok: false; readonly code: "invalid_arguments"; readonly reason: "ttl" };

/** Grants a TTL and computes its second-precision UTC deadline from `now` in seconds (spec 06 R8.5). */
export function ttlGrant(input: { readonly ttlMs?: number | null; readonly now: number }): TtlGrantResult {
  const { ttlMs } = input;
  if (ttlMs === null) return { ok: true, grantMs: null, refreshBefore: null };
  let grantMs = DEFAULT_TTL_MS;
  if (ttlMs !== undefined) {
    if (!Number.isSafeInteger(ttlMs) || ttlMs < 0) {
      return { ok: false, code: "invalid_arguments", reason: "ttl" };
    }
    grantMs = Math.min(Math.max(ttlMs, MIN_TTL_MS), MAX_TTL_MS);
  }
  const refreshBefore = new Date((input.now + Math.floor(grantMs / 1000)) * 1000).toISOString().slice(0, 19) + "Z";
  return { ok: true, grantMs, refreshBefore };
}

function secretBytes(value: Uint8Array | string): Uint8Array {
  if (typeof value !== "string") return value;
  const parsed = parseWhsec(value);
  if (!parsed.ok) throw new Error(parsed.reason);
  return parsed.key;
}

/** Lists the current secret first and the previous secret only before the grace deadline (spec 06 R8.6). */
export function activeSecrets(input: {
  readonly current: Uint8Array | string;
  readonly previous?: Uint8Array | string | null;
  readonly graceEndsAt?: number | null;
  readonly now: number;
}): ActiveSecret[] {
  const { current, previous, graceEndsAt, now } = input;
  const secrets: ActiveSecret[] = [{ secret: secretBytes(current), current: true }];
  if (previous !== undefined && previous !== null && graceEndsAt !== undefined && graceEndsAt !== null && now < graceEndsAt) {
    secrets.push({ secret: secretBytes(previous), current: false });
  }
  return secrets;
}

/** Serializes the gap envelope with its replay cursor (spec 06 R8.7). */
export function gapEnvelope(cursor: string | null): string {
  return JSON.stringify({ type: "gap", cursor });
}

/** The JSON-RPC error fields of a terminated envelope (spec 06 R8.8). */
export interface TerminatedEnvelopeInput {
  readonly code: number;
  readonly message: string;
  readonly data?: Record<string, unknown>;
}

/** Validates and serializes the terminated envelope (spec 06 R8.8). */
export function terminatedEnvelope(input: TerminatedEnvelopeInput): string {
  const { code, message, data } = input;
  if (!Number.isInteger(code)) throw new Error("terminatedEnvelope requires an integer code");
  if (typeof message !== "string") throw new Error("terminatedEnvelope requires a string message");
  if (data !== undefined && (data === null || Array.isArray(data) || typeof data !== "object")) {
    throw new Error("terminatedEnvelope data must be a non-null, non-array object");
  }
  return JSON.stringify({ type: "terminated", error: { code, message, ...(data === undefined ? {} : { data }) } });
}

/** Checks for null or a non-empty cursor of at most 512 printable ASCII characters (spec 06 R8.9). */
export function cursorOk(value: unknown): boolean {
  if (value === null) return true;
  if (typeof value !== "string" || value.length < 1 || value.length > CURSOR_MAX_LENGTH) return false;
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code < 0x21 || code > 0x7e) return false;
  }
  return true;
}
