import { randomBytes as defaultRandomBytes } from "node:crypto";
import { encodeBase64URL } from "../../core/encoding.js";
import { constTimeEqual, decodeBase64UrlStrict } from "../crypto/primitives.js";

const NONCE_RE = /^[A-Za-z0-9_-]{22}$/;

/** The maximum age of a challenge nonce, in seconds (R5.3). */
export const NONCE_MAX_AGE_SECONDS = 600;

/** Whether the value consists of exactly 22 base64url characters (R5.3). */
export function nonceOk(value: unknown): boolean {
  return typeof value === "string" && value.length === 22 && NONCE_RE.test(value);
}

function nonceBytes(value: unknown): Uint8Array | null {
  if (typeof value !== "string" || !nonceOk(value)) return null;
  const bytes = decodeBase64UrlStrict(value);
  return bytes?.length === 16 ? bytes : null;
}

/** Generates an unpadded base64url nonce from 16 CSPRNG bytes (R5.3). */
export function randomNonce(randomBytes: (n: number) => Uint8Array = defaultRandomBytes): string {
  return encodeBase64URL(randomBytes(16));
}

/** The outcome of inspecting a challenge response (R5.4). */
export type ChallengeEcho =
  | { readonly ok: true }
  | { readonly ok: false; readonly code: "challenge_failed"; readonly reason: string };

/** Checks the HTTP status, UTF-8 body size, JSON shape and echoed challenge, in that order (R5.4). */
export function challengeEcho(input: {
  readonly status?: number;
  readonly bodyText?: string;
  readonly nonce?: string;
  readonly maxBodyBytes?: number;
}): ChallengeEcho {
  const { status, bodyText, nonce, maxBodyBytes = 4096 } = input;
  if (typeof status !== "number" || !Number.isInteger(status) || status < 200 || status > 299) {
    return failure("status");
  }
  if (typeof bodyText !== "string") return failure("body");
  if (Buffer.byteLength(bodyText, "utf8") > maxBodyBytes) return failure("too_large");
  let parsed: unknown;
  try {
    parsed = JSON.parse(bodyText);
  } catch {
    return failure("json");
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return failure("body");
  const echo = (parsed as { readonly challenge?: unknown }).challenge;
  if (typeof echo !== "string") return failure("missing");
  const echoed = nonceBytes(echo);
  const expected = nonceBytes(nonce);
  if (echoed === null || expected === null || !constTimeEqual(echoed, expected)) {
    return failure("mismatch");
  }
  return { ok: true };
}

/** Encodes a valid attempt pair as a comparable key; invalid pairs have no key (R5.3). */
export function pairKey(pair: unknown): string | null {
  let principal: unknown;
  let url: unknown;
  if (Array.isArray(pair)) {
    if (pair.length !== 2) return null;
    [principal, url] = pair;
  } else if (pair !== null && typeof pair === "object") {
    ({ principal, url } = pair as { readonly principal?: unknown; readonly url?: unknown });
  } else {
    return null;
  }
  if (typeof principal !== "string" || typeof url !== "string" || principal === "" || url === "") {
    return null;
  }
  return JSON.stringify([principal, url]);
}

/** The outcome of validating an echo against an issued attempt (R5.3). */
export type EchoAcceptance = ChallengeEcho;

/** Checks echo equality, age in seconds, single use and attempt pairing, in that order (R5.3). */
export function acceptEcho(input: {
  readonly nonce?: string;
  readonly expected?: string;
  readonly issuedAt?: number;
  readonly now?: number;
  readonly ttlSeconds?: number;
  readonly consumed?: boolean;
  readonly pair?: unknown;
  readonly expectedPair?: unknown;
}): EchoAcceptance {
  const { nonce, expected, issuedAt, now, ttlSeconds = NONCE_MAX_AGE_SECONDS, consumed, pair, expectedPair } = input;
  const echoed = nonceBytes(nonce);
  const issued = nonceBytes(expected);
  if (echoed === null || issued === null || !constTimeEqual(echoed, issued)) {
    return failure("mismatch");
  }
  if (now === undefined || issuedAt === undefined || !(now - issuedAt <= ttlSeconds)) return failure("expired");
  if (consumed === true) return failure("reused");
  const key = pairKey(pair);
  if (key === null || key !== pairKey(expectedPair)) return failure("pair");
  return { ok: true };
}

function failure(reason: string): ChallengeEcho {
  return { ok: false, code: "challenge_failed", reason };
}
