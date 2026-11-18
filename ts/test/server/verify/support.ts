import assert from "node:assert/strict";
import { createPrivateKey, createPublicKey, randomBytes, sign as nodeSign } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { test } from "node:test";
import { formatRequestAuth, parseRequestAuth } from "../../../src/core/auth-header.js";
import { encodeBase64URL, keyId } from "../../../src/core/encoding.js";
import { Code } from "../../../src/core/errors.js";
import { requestSigningString } from "../../../src/core/signing.js";
import { MemoryAuditSink } from "../../../src/server/audit.js";
import { Native } from "../../../src/server/native.js";
import { NonceStore } from "../../../src/server/registry/nonce.js";
import { MemoryState, inviteIdOf } from "../../../src/server/registry/state.js";
import type { RegistryEntry } from "../../../src/server/registry/state.js";
import { Verifier, classifyBody, TOOL_ENROLL } from "../../../src/server/verify.js";
import type { NativeCall, NativeResult, NativeTools, VerifyRequest } from "../../../src/server/verify.js";
import { loadKeys, loadRegistry } from "../../support/fixtures/index.js";
import type { TestKey } from "../../support/fixtures/index.js";


export const NOW = 1767225600;
/** Fixed canonical 16-byte nonce in base64url, so every test request is deterministic. */
export const NONCE = "r9SAnpI_j3jZjJXRpWDlSg";
/** Second fixed canonical 16-byte nonce (from the fixture corpus). */
export const NONCE2 = "nWfW0dywfDj9xse_1sv69Q";

export let nonceCounter = 0;
/** Distinct canonical 16-byte nonce (22 base64url chars) per request. Reusing a live (kid, nonce) pair is a replay by definition, so only deliberate replay scenarios pass an explicit nonce. */
export function freshNonce(): string {
  const bytes = new Uint8Array(16);
  let v = BigInt(nonceCounter++);
  for (let b = 15; b >= 8; b--) {
    bytes[b] = Number(v & 0xffn);
    v >>= 8n;
  }
  bytes.set([0x6d, 0x63, 0x70, 0x6a, 0x2d, 0x74, 0x73, 0x30]); // "mcpj-ts0" prefix, counter in the low 8 bytes
  return encodeBase64URL(bytes);
}
export const PING = '{"jsonrpc":"2.0","id":1,"method":"ping"}';
export const encoder = new TextEncoder();

// ---------------------------------------------------------------------------
// Key material (ported helpers from request-vectors.test.ts, self-contained).
// ---------------------------------------------------------------------------

/** Ed25519 private key from a keys.json seed, via node:crypto PKCS8 DER. */
export function privateKeyFor(key: TestKey): KeyObject {
  const pkcs8Prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  return createPrivateKey({
    key: Buffer.concat([pkcs8Prefix, Buffer.from(key.seedHex, "hex")]),
    format: "der",
    type: "pkcs8",
  });
}

/** Raw 32-byte Ed25519 public key of priv (SPKI DER minus the 12-byte prefix). */
export function publicKeyOf(priv: KeyObject): Uint8Array {
  const spki = createPublicKey(priv).export({ format: "der", type: "spki" });
  return new Uint8Array(spki.subarray(12));
}

/** Signing material for one keys.json entry, resolved by name (never hard-coded kids). */
export interface KeyMaterial {
  readonly priv: KeyObject;
  readonly pub: Uint8Array;
  readonly kid: string;
}

export function materialFor(keyName: string): KeyMaterial {
  const key = loadKeys().keys.find((k) => k.name === keyName);
  assert.ok(key !== undefined, `key "${keyName}" missing from keys.json`);
  const priv = privateKeyFor(key);
  const pub = publicKeyOf(priv);
  assert.equal(keyId(pub), key.kid, `key "${keyName}": keyId mismatch against keys.json`);
  return { priv, pub, kid: key.kid };
}

/** A valid prime-order Ed25519 key NOT in the registry, for enrollment tests. */
export function randomKey(): KeyMaterial {
  const seed = new Uint8Array(randomBytes(32));
  const pkcs8Prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  const priv = createPrivateKey({ key: Buffer.concat([pkcs8Prefix, Buffer.from(seed)]), format: "der", type: "pkcs8" });
  const pub = publicKeyOf(priv);
  return { priv, pub, kid: keyId(pub) };
}

// ---------------------------------------------------------------------------
// Harness.
// ---------------------------------------------------------------------------

export interface Harness {
  readonly verifier: Verifier;
  readonly state: MemoryState;
  readonly nonces: NonceStore;
  readonly now: number;
  readonly aud: string;
  readonly audit: MemoryAuditSink | undefined;
}

/** One fresh harness per test: seeded registry, fresh nonces, fixed clock. */
export function harness(opts?: { native?: NativeTools; withAudit?: boolean }): Harness {
  const state = new MemoryState();
  state.update((edit) => {
    // exactOptionalPropertyTypes: assign admin/notBefore/notAfter only when defined.
    for (const f of loadRegistry().keys) {
      const entry: { -readonly [K in keyof RegistryEntry]: RegistryEntry[K] } = {
        kid: f.kid,
        publicKey: f.publicKey,
        name: f.name,
      };
      if (f.admin !== undefined) entry.admin = f.admin;
      if (f.notBefore !== undefined) entry.notBefore = f.notBefore;
      if (f.notAfter !== undefined) entry.notAfter = f.notAfter;
      edit.putKey(entry);
    }
  });
  const nonces = new NonceStore();
  const audit = opts?.withAudit === true ? new MemoryAuditSink() : undefined;
  const verifier = new Verifier({
    aud: loadRegistry().aud,
    state,
    nonces,
    now: () => NOW,
    ...(opts?.native !== undefined ? { native: opts.native } : {}),
    ...(audit !== undefined ? { audit } : {}),
  });
  return { verifier, state, nonces, now: NOW, aud: loadRegistry().aud, audit };
}

/** Builds and signs one request header + VerifyRequest over the EXACT body bytes. */
export function signed(
  mat: KeyMaterial,
  opts: {
    body?: Uint8Array;
    method?: string;
    target?: string;
    ts?: number;
    nonce?: string;
  } = {},
): { req: VerifyRequest; kid: string; pub: Uint8Array } {
  const ts = opts.ts ?? NOW;
  const nonce = opts.nonce ?? freshNonce();
  const body = opts.body ?? new Uint8Array(0);
  const method = opts.method ?? "POST";
  const target = opts.target ?? "/mcp";
  const msg = requestSigningString(method, target, loadRegistry().aud, mat.kid, ts, nonce, body);
  const sig = encodeBase64URL(new Uint8Array(nodeSign(null, Buffer.from(msg), mat.priv)));
  const header = formatRequestAuth({ kid: mat.kid, ts, nonce, sig });
  return {
    req: { method, target, authValues: [header], body },
    kid: mat.kid,
    pub: mat.pub,
  };
}

/**
 * Native-call double for plumbing tests ONLY: records the call, sets the audit
 * target output field, then delegates (the real tools live in native.ts, which
 * does its own admin gating).
 */
export class RecordingNative implements NativeTools {
  readonly calls: NativeCall[] = [];
  constructor(
    private readonly impl?: (c: NativeCall) => NativeResult,
    private readonly target = "t-1",
  ) {}
  call(c: NativeCall): NativeResult {
    this.calls.push(c);
    c.target = this.target;
    if (this.impl !== undefined) return this.impl(c);
    return { structured: { ok: true } };
  }
}

export const ALICE = "alice";
export const ROOT = "root";

/** Fixed raw invite code; the harness stores only its hash, like the real tools. */
export const ENROLL_CODE_RAW = new Uint8Array(32).fill(7);

/** Stores an invite for ENROLL_CODE_RAW and returns the code string a client would send. */
export function seedInvite(h: Harness, expiresAt: number = NOW + 60): string {
  h.state.update((edit) => {
    edit.putInvite({ inviteId: inviteIdOf(ENROLL_CODE_RAW), createdBy: ROOT, createdAt: NOW - 1, expiresAt });
  });
  return encodeBase64URL(ENROLL_CODE_RAW);
}

/** A signed jack.enroll request body for key k carrying the given code member (omitted when undefined). */
export function enrollBody(k: KeyMaterial, code: unknown): Uint8Array {
  const args: Record<string, unknown> = { public_key: encodeBase64URL(k.pub) };
  if (code !== undefined) args["code"] = code;
  return encoder.encode(
    JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: TOOL_ENROLL, arguments: args } }),
  );
}

/** Asserts the ordinary unsigned unknown_key rejection with no nonce and no audit event. */
export function assertUnknownKey(h: Harness, req: VerifyRequest, kid: string, label: string): void {
  const res = h.verifier.verify(req);
  assert.equal(res.accepted, false, `${label}: accepted`);
  assert.equal(res.httpStatus, 401, `${label}: status`);
  assert.equal(res.code, Code.UNKNOWN_KEY, `${label}: code`);
  assert.equal(res.nonceRecorded, false, `${label}: nonceRecorded`);
  assert.equal(res.kid, "", `${label}: unsigned kid`);
  assert.equal(res.requestSig, "", `${label}: unsigned requestSig`);
  assert.equal(res.audit, undefined, `${label}: audit`);
  // The request's own nonce was never recorded: recording it now is not a replay.
  const { nonce } = parseRequestAuth(req.authValues);
  assert.equal(h.nonces.checkAndRecord(kid, nonce, NOW, NOW + 30), false, `${label}: nonce untouched`);
}

// ---------------------------------------------------------------------------
// 1. Scheme before parameters.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 2. Unknown kid outside enrollment.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 3. The enrollment exception (verify.go enrollmentKey / verify.ts enrollmentKey).
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 3b. The enrollment exception requires a live invite (read-only gate).
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 4. Replay checked only after the signature.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 5. UTF-8 validity before JSON parse.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 6. Empty body: POST invalid, GET fine.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 7. Window boundaries: reject iff |now - ts| > window (Go parity).
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 8. Body hash binds the signature to the exact bytes.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 9. classifyBody table (Go TestClassifyBody).
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 10. rpcId keeps the raw JSON text.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 11. arguments keep the exact raw JSON text.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 12. NativeCall plumbing.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 13. Audit event on a failed admin call.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 14. Undefined jack.* tool and missing handler: 403, no audit.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 15. The identity snapshot of forwarded accepts.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 16. Verifier config validation and window defaults.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 17. Fail-closed on a broken injected clock (review L-2) and aud validation.
// ---------------------------------------------------------------------------

/** A verifier over a fresh seeded registry with an arbitrary clock. */
export function clockHarness(now: () => number, native?: NativeTools): { verifier: Verifier; nonces: NonceStore } {
  const state = new MemoryState();
  state.update((edit) => {
    for (const f of loadRegistry().keys) {
      const entry: { -readonly [K in keyof RegistryEntry]: RegistryEntry[K] } = {
        kid: f.kid,
        publicKey: f.publicKey,
        name: f.name,
      };
      if (f.admin !== undefined) entry.admin = f.admin;
      if (f.notBefore !== undefined) entry.notBefore = f.notBefore;
      if (f.notAfter !== undefined) entry.notAfter = f.notAfter;
      edit.putKey(entry);
    }
  });
  const nonces = new NonceStore();
  const verifier = new Verifier({
    aud: loadRegistry().aud,
    state,
    nonces,
    now,
    ...(native !== undefined ? { native } : {}),
  });
  return { verifier, nonces };
}

// ---------------------------------------------------------------------------
// Monotonic request clock (high-water mark).
// ---------------------------------------------------------------------------

/** An accepted POST needs a valid JSON-RPC body (an empty body is invalid_request). */
export const ping = encoder.encode(PING);

/** Harness whose injected clock is steered by the test through the returned setter. */
export function steppedHarness(opts?: { native?: NativeTools; withAudit?: boolean }): {
  verifier: Verifier;
  setClock: (t: number) => void;
  state: MemoryState;
  nonces: NonceStore;
  audit: MemoryAuditSink | undefined;
} {
  const base = harness(opts);
  let clock = NOW;
  const verifier = new Verifier({
    aud: base.aud,
    state: base.state,
    nonces: base.nonces,
    now: () => clock,
    ...(opts?.native !== undefined ? { native: opts.native } : {}),
    ...(base.audit !== undefined ? { audit: base.audit } : {}),
  });
  return { verifier, setClock: (t) => void (clock = t), state: base.state, nonces: base.nonces, audit: base.audit };
}
