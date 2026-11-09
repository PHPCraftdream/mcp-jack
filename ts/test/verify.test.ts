/**
 * Verifier unit tests for the order-of-checks edge cases, the body classifier
 * and the raw-JSON tokenizer — the parts the request vectors cannot express.
 * Derived from server/verify.go, Go's TestClassifyBody (server/policy_test.go)
 * and spec 01 section 4 / 02 section 4 / 03 section 3.2. Nothing is executed
 * here beyond the tests themselves; every expected value was derived by hand
 * from the code path.
 */
import assert from "node:assert/strict";
import { createPrivateKey, createPublicKey, randomBytes, sign as nodeSign } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { test } from "node:test";
import { formatRequestAuth } from "../src/auth-header.js";
import { encodeBase64URL, keyId } from "../src/encoding.js";
import { Code, JackError } from "../src/errors.js";
import { requestSigningString } from "../src/signing.js";
import { MemoryAuditSink, AUDIT_FAILURE } from "../src/server/audit.js";
import { Native } from "../src/server/native.js";
import { NonceStore } from "../src/server/nonce.js";
import { MemoryState } from "../src/server/state.js";
import type { RegistryEntry } from "../src/server/state.js";
import {
  Verifier,
  classifyBody,
  TOOL_ADMIN_USER_SET_ADMIN,
  TOOL_ADMIN_USER_GET,
  TOOL_ADMIN_USER_LIST,
  TOOL_ENROLL,
  TOOL_WHOAMI,
} from "../src/server/verify.js";
import type {
  NativeCall,
  NativeResult,
  NativeTools,
  RpcMessage,
  VerifyRequest,
  VerifierConfig,
} from "../src/server/verify.js";
import { loadKeys, loadRegistry } from "./fixtures.js";
import type { TestKey } from "./fixtures.js";

const NOW = 1767225600;
/** Fixed canonical 16-byte nonce in base64url, so every test request is deterministic. */
const NONCE = "r9SAnpI_j3jZjJXRpWDlSg";
/** Second fixed canonical 16-byte nonce (from the fixture corpus). */
const NONCE2 = "nWfW0dywfDj9xse_1sv69Q";

let nonceCounter = 0;
/** Distinct canonical 16-byte nonce (22 base64url chars) per request. Reusing a live (kid, nonce) pair is a replay by definition, so only deliberate replay scenarios pass an explicit nonce. */
function freshNonce(): string {
  const bytes = new Uint8Array(16);
  let v = BigInt(nonceCounter++);
  for (let b = 15; b >= 8; b--) {
    bytes[b] = Number(v & 0xffn);
    v >>= 8n;
  }
  bytes.set([0x6d, 0x63, 0x70, 0x6a, 0x2d, 0x74, 0x73, 0x30]); // "mcpj-ts0" prefix, counter in the low 8 bytes
  return encodeBase64URL(bytes);
}
const PING = '{"jsonrpc":"2.0","id":1,"method":"ping"}';
const encoder = new TextEncoder();

// ---------------------------------------------------------------------------
// Key material (ported helpers from request-vectors.test.ts, self-contained).
// ---------------------------------------------------------------------------

/** Ed25519 private key from a keys.json seed, via node:crypto PKCS8 DER. */
function privateKeyFor(key: TestKey): KeyObject {
  const pkcs8Prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  return createPrivateKey({
    key: Buffer.concat([pkcs8Prefix, Buffer.from(key.seedHex, "hex")]),
    format: "der",
    type: "pkcs8",
  });
}

/** Raw 32-byte Ed25519 public key of priv (SPKI DER minus the 12-byte prefix). */
function publicKeyOf(priv: KeyObject): Uint8Array {
  const spki = createPublicKey(priv).export({ format: "der", type: "spki" });
  return new Uint8Array(spki.subarray(12));
}

/** Signing material for one keys.json entry, resolved by name (never hard-coded kids). */
interface KeyMaterial {
  readonly priv: KeyObject;
  readonly pub: Uint8Array;
  readonly kid: string;
}

function materialFor(keyName: string): KeyMaterial {
  const key = loadKeys().keys.find((k) => k.name === keyName);
  assert.ok(key !== undefined, `key "${keyName}" missing from keys.json`);
  const priv = privateKeyFor(key);
  const pub = publicKeyOf(priv);
  assert.equal(keyId(pub), key.kid, `key "${keyName}": keyId mismatch against keys.json`);
  return { priv, pub, kid: key.kid };
}

/** A valid prime-order Ed25519 key NOT in the registry, for enrollment tests. */
function randomKey(): KeyMaterial {
  const seed = new Uint8Array(randomBytes(32));
  const pkcs8Prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  const priv = createPrivateKey({ key: Buffer.concat([pkcs8Prefix, Buffer.from(seed)]), format: "der", type: "pkcs8" });
  const pub = publicKeyOf(priv);
  return { priv, pub, kid: keyId(pub) };
}

// ---------------------------------------------------------------------------
// Harness.
// ---------------------------------------------------------------------------

interface Harness {
  readonly verifier: Verifier;
  readonly state: MemoryState;
  readonly nonces: NonceStore;
  readonly now: number;
  readonly aud: string;
  readonly audit: MemoryAuditSink | undefined;
}

/** One fresh harness per test: seeded registry, fresh nonces, fixed clock. */
function harness(opts?: { native?: NativeTools; withAudit?: boolean }): Harness {
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
function signed(
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
class RecordingNative implements NativeTools {
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

const ALICE = "alice";
const ROOT = "root";

// ---------------------------------------------------------------------------
// 1. Scheme before parameters.
// ---------------------------------------------------------------------------

test("scheme is examined before the parameters", () => {
  const h = harness();
  // "v2" parses as a version-like scheme, so the check fires before the
  // garbage parameters kid=SHORT / ts=notanumber are ever examined (spec 01
  // section 3: scheme first).
  const v2 = h.verifier.verify({ method: "POST", target: "/mcp", authValues: ["v2 kid=SHORT,ts=notanumber"], body: encoder.encode(PING) });
  assert.equal(v2.accepted, false, "v2: accepted");
  assert.equal(v2.httpStatus, 401, "v2: status");
  assert.equal(v2.code, Code.UNSUPPORTED_VERSION, "v2: code");
  assert.equal(v2.nonceRecorded, false, "v2: nonceRecorded");
  assert.equal(v2.requestSig, "", "v2: requestSig");
  // "w1" is not "v"+digits, so it is a malformed scheme even before parameters.
  const w1 = h.verifier.verify({ method: "POST", target: "/mcp", authValues: ["w1 kid=x"], body: encoder.encode(PING) });
  assert.equal(w1.accepted, false, "w1: accepted");
  assert.equal(w1.httpStatus, 401, "w1: status");
  assert.equal(w1.code, Code.MALFORMED_AUTH, "w1: code");
  assert.equal(w1.nonceRecorded, false, "w1: nonceRecorded");
  assert.equal(w1.requestSig, "", "w1: requestSig");
});

// ---------------------------------------------------------------------------
// 2. Unknown kid outside enrollment.
// ---------------------------------------------------------------------------

test("unknown kid is rejected outside enrollment", () => {
  const h = harness();
  const k = randomKey();
  const { req } = signed(k, { body: encoder.encode(PING) });
  const res = h.verifier.verify(req);
  assert.equal(res.accepted, false, "accepted");
  assert.equal(res.httpStatus, 401, "status");
  assert.equal(res.code, Code.UNKNOWN_KEY, "code");
  assert.equal(res.nonceRecorded, false, "nonceRecorded");
});

// ---------------------------------------------------------------------------
// 3. The enrollment exception (verify.go enrollmentKey / verify.ts enrollmentKey).
// ---------------------------------------------------------------------------

test("enrollment exception passes authentication (steps 5-8 skipped for the registry interval)", () => {
  // (a) Valid submitted key hashing to the header kid: authentication SUCCEEDS
  // even though the kid is unregistered; without a native handler the call
  // fails later, at the native-tool gate, with 403 operation_denied.
  {
    const h = harness();
    const k = randomKey();
    const body = encoder.encode(
      `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"${TOOL_ENROLL}","arguments":{"public_key":"${encodeBase64URL(k.pub)}"}}}`,
    );
    const { req } = signed(k, { body });
    const res = h.verifier.verify(req);
    assert.equal(res.accepted, false, "a: accepted");
    assert.equal(res.httpStatus, 403, "a: status (operation_denied, NOT unknown_key)");
    assert.equal(res.code, Code.OPERATION_DENIED, "a: code");
    assert.equal(res.nonceRecorded, true, "a: nonceRecorded (authentication completed)");
    assert.equal(res.native, true, "a: native");
    assert.equal(res.tool, TOOL_ENROLL, "a: tool");
    assert.equal(res.audit, undefined, "a: audit (no handler -> no audit event)");
  }
  // (b) Submitted public key whose hash differs from the header kid: unknown_key.
  {
    const h = harness();
    const k = randomKey();
    const k2 = randomKey();
    const body = encoder.encode(
      `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"${TOOL_ENROLL}","arguments":{"public_key":"${encodeBase64URL(k2.pub)}"}}}`,
    );
    const { req } = signed(k, { body });
    const res = h.verifier.verify(req);
    assert.equal(res.httpStatus, 401, "b: status");
    assert.equal(res.code, Code.UNKNOWN_KEY, "b: code (hash mismatch is unknown_key)");
  }
  // (c) The all-zero 32-byte string decodes but is not a valid curve point, so validatePublicKey rejects it: 400 key_rejected (checked BEFORE the kid hash).
  {
    const h = harness();
    const k = randomKey();
    const body = encoder.encode(
      `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"${TOOL_ENROLL}","arguments":{"public_key":"${encodeBase64URL(new Uint8Array(32))}"}}}`,
    );
    const { req } = signed(k, { body });
    const res = h.verifier.verify(req);
    assert.equal(res.httpStatus, 400, "c: status");
    assert.equal(res.code, Code.KEY_REJECTED, "c: code");
  }
  // (d) Malformed base64url encoding: decode failure is key_rejected (Go parity).
  {
    const h = harness();
    const k = randomKey();
    const body = encoder.encode(
      `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"${TOOL_ENROLL}","arguments":{"public_key":"not-base64url!!"}}}`,
    );
    const { req } = signed(k, { body });
    const res = h.verifier.verify(req);
    assert.equal(res.httpStatus, 400, "d: status");
    assert.equal(res.code, Code.KEY_REJECTED, "d: code");
  }
  // (e) Only POST: a GET enroll from an unregistered kid is unknown_key.
  {
    const h = harness();
    const k = randomKey();
    const body = encoder.encode(
      `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"${TOOL_ENROLL}","arguments":{"public_key":"${encodeBase64URL(k.pub)}"}}}`,
    );
    const { req } = signed(k, { body, method: "GET" });
    const res = h.verifier.verify(req);
    assert.equal(res.httpStatus, 401, "e: status");
    assert.equal(res.code, Code.UNKNOWN_KEY, "e: code");
  }
  // (f) jack.enroll signed by a REGISTERED key takes the normal path; whether
  // the call itself is 409 key_exists is native-tool logic (a later task).
  {
    const h = harness();
    const alice = materialFor(ALICE);
    const body = encoder.encode(
      `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"${TOOL_ENROLL}","arguments":{"public_key":"${encodeBase64URL(randomKey().pub)}"}}}`,
    );
    const { req } = signed(alice, { body });
    const res = h.verifier.verify(req);
    assert.equal(res.httpStatus, 403, "f: status");
    assert.equal(res.code, Code.OPERATION_DENIED, "f: code");
    assert.equal(res.nonceRecorded, true, "f: nonceRecorded");
  }
});

// ---------------------------------------------------------------------------
// 4. Replay checked only after the signature.
// ---------------------------------------------------------------------------

test("replay is checked only after the signature", () => {
  const h = harness();
  const alice = materialFor(ALICE);
  // Preseed the (kid, nonce) pair as already seen.
  assert.equal(h.nonces.checkAndRecord(alice.kid, NONCE, NOW, NOW + 30), false, "preseed recorded");
  const { req } = signed(alice, { body: encoder.encode(PING) });
  // Break the signature: the signature step fires BEFORE the nonce step, so
  // the outcome is bad_signature, NOT replayed_nonce, and nothing is recorded.
  const badHeader = formatRequestAuth({
    kid: alice.kid,
    ts: NOW,
    nonce: NONCE,
    sig: encodeBase64URL(new Uint8Array(64)),
  });
  const bad = h.verifier.verify({ ...req, authValues: [badHeader] });
  assert.equal(bad.accepted, false, "bad sig: accepted");
  assert.equal(bad.httpStatus, 401, "bad sig: status");
  assert.equal(bad.code, Code.BAD_SIGNATURE, "bad sig: code (NOT replayed_nonce)");
  assert.equal(bad.nonceRecorded, false, "bad sig: nonceRecorded");
  // (ii) A failed attempt never records its nonce: the same nonce is still
  // fresh for a correctly signed request at the same clock. Had the failed
  // attempt consumed it, this would be replayed_nonce.
  const { req: req2 } = signed(alice, { body: encoder.encode(PING), nonce: NONCE2 });
  const bad2Header = formatRequestAuth({ kid: alice.kid, ts: NOW, nonce: NONCE2, sig: encodeBase64URL(new Uint8Array(64)) });
  const bad2 = h.verifier.verify({ ...req2, authValues: [bad2Header] });
  assert.equal(bad2.accepted, false, "fresh nonce, bad sig: accepted");
  assert.equal(bad2.code, Code.BAD_SIGNATURE, "fresh nonce, bad sig: code");
  assert.equal(bad2.nonceRecorded, false, "fresh nonce, bad sig: nonceRecorded");
  const ok = h.verifier.verify(req2);
  assert.equal(ok.accepted, true, "ok: accepted");
  assert.equal(ok.nonceRecorded, true, "ok: nonceRecorded");
  assert.equal(ok.kid, alice.kid, "ok: kid");
});

// ---------------------------------------------------------------------------
// 5. UTF-8 validity before JSON parse.
// ---------------------------------------------------------------------------

test("invalid UTF-8 is rejected before any JSON parse", () => {
  const h = harness();
  const alice = materialFor(ALICE);
  // The 0xff byte sits INSIDE the method string of an otherwise valid ping
  // request (like the request-utf8-* vectors). A lossy decoder would produce a
  // valid "p\uFFFDng" request that is forwarded as an ordinary accept; only
  // the fatal decoder yields 400 invalid_request, so the expectation
  // discriminates. The signature covers the exact bytes, so authentication
  // succeeds first and the nonce is consumed.
  const body = Buffer.concat([
    Buffer.from('{"jsonrpc":"2.0","id":1,"method":"p', "utf8"),
    Buffer.from([0xff]),
    Buffer.from('ng"}', "utf8"),
  ]);
  const { req } = signed(alice, { body: new Uint8Array(body) });
  const res = h.verifier.verify(req);
  assert.equal(res.accepted, false, "accepted");
  assert.equal(res.httpStatus, 400, "status");
  assert.equal(res.code, Code.INVALID_REQUEST, "code");
  assert.equal(res.nonceRecorded, true, "nonceRecorded (authentication succeeded first)");
});

test("a UTF-8 BOM before the JSON text is invalid_request", () => {
  const h = harness();
  const alice = materialFor(ALICE);
  // RFC 8259 forbids a BOM at the start of JSON text. The decoder runs with
  // ignoreBOM: true, so U+FEFF survives into the decoded text; the tokenizer's
  // whitespace set (space/tab/LF/CR) does not include it, so parsing fails
  // before classification (spec 02 section 4). No fixture covers this case.
  const body = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(PING, "utf8")]);
  const { req } = signed(alice, { body: new Uint8Array(body) });
  const res = h.verifier.verify(req);
  assert.equal(res.accepted, false, "accepted");
  assert.equal(res.httpStatus, 400, "status");
  assert.equal(res.code, Code.INVALID_REQUEST, "code");
  assert.equal(res.nonceRecorded, true, "nonceRecorded (authentication succeeded first)");
});

// ---------------------------------------------------------------------------
// 6. Empty body: POST invalid, GET fine.
// ---------------------------------------------------------------------------

test("empty POST is invalid, empty GET is fine", () => {
  const h = harness();
  const alice = materialFor(ALICE);
  // POST: classifyBody rejects the empty body AFTER authentication.
  const post = signed(alice, { body: new Uint8Array(0) });
  const postRes = h.verifier.verify(post.req);
  assert.equal(postRes.accepted, false, "post: accepted");
  assert.equal(postRes.httpStatus, 400, "post: status");
  assert.equal(postRes.code, Code.INVALID_REQUEST, "post: code");
  assert.equal(postRes.nonceRecorded, true, "post: nonceRecorded");
  // GET: authorized by authentication alone, body never examined.
  const get = signed(alice, { body: new Uint8Array(0), method: "GET" });
  const getRes = h.verifier.verify(get.req);
  assert.equal(getRes.accepted, true, "get: accepted");
  assert.equal(getRes.kid, alice.kid, "get: kid");
});

// ---------------------------------------------------------------------------
// 7. Window boundaries: reject iff |now - ts| > window (Go parity).
// ---------------------------------------------------------------------------

test("window boundaries (Go: reject iff |now-ts| > window)", () => {
  const h = harness();
  const alice = materialFor(ALICE);
  for (const [delta, accepted] of [
    [-30, true],
    [-31, false],
    [30, true],
    [31, false],
  ] as const) {
    const { req } = signed(alice, { body: encoder.encode(PING), ts: NOW + delta });
    const res = h.verifier.verify(req);
    assert.equal(res.accepted, accepted, `ts=now${delta >= 0 ? "+" : ""}${delta}: accepted`);
    if (!accepted) {
      assert.equal(res.code, Code.TIMESTAMP_OUT_OF_WINDOW, `ts=now${delta}: code`);
    }
  }
});

// ---------------------------------------------------------------------------
// 8. Body hash binds the signature to the exact bytes.
// ---------------------------------------------------------------------------

test("the body hash binds the signature to the exact bytes", () => {
  const h = harness();
  const alice = materialFor(ALICE);
  // Sign body A, send body B: bad_signature before any nonce consumption.
  const bodyA = encoder.encode('{"jsonrpc":"2.0","id":1,"method":"ping"}');
  const bodyB = encoder.encode('{"jsonrpc":"2.0","id":2,"method":"ping"}');
  const signedA = signed(alice, { body: bodyA });
  const req = { ...signedA.req, body: bodyB };
  const res = h.verifier.verify(req);
  assert.equal(res.accepted, false, "accepted");
  assert.equal(res.httpStatus, 401, "status");
  assert.equal(res.code, Code.BAD_SIGNATURE, "code");
  assert.equal(res.nonceRecorded, false, "nonceRecorded");
});

// ---------------------------------------------------------------------------
// 9. classifyBody table (Go TestClassifyBody).
// ---------------------------------------------------------------------------

test("classifyBody table (Go TestClassifyBody)", () => {
  const cls = (body: string): RpcMessage | undefined => classifyBody(encoder.encode(body));
  // Requests.
  assert.deepEqual(cls(PING), { kind: "request", id: "1", method: "ping", hasTool: false, tool: "", arguments: undefined }, "ping request");
  const notif = cls('{"jsonrpc":"2.0","method":"notifications/initialized"}');
  assert.ok(notif !== undefined, "notification: defined");
  assert.equal(notif.kind, "request", "notification: kind");
  assert.equal(notif.id, undefined, "notification: id undefined (no id member)");
  // Responses.
  assert.deepEqual(cls('{"jsonrpc":"2.0","id":1,"result":{}}'), { kind: "response", id: "1", method: "", hasTool: false, tool: "", arguments: undefined }, "result response");
  assert.equal(cls('{"jsonrpc":"2.0","id":"a","error":{"code":1,"message":"x"}}')?.kind, "response", "error response");
  assert.equal(cls('{"jsonrpc":"2.0","id":null,"result":1}')?.kind, "response", "id null response");
  // Undefined rows.
  for (const body of [
    "",
    "null",
    '[{"jsonrpc":"2.0","id":1,"method":"ping"}]', // batch: root is an array
    '{"JSONRPC":"2.0","method":"ping"}', // member names are case-sensitive
    '{"jsonrpc":"1.0","method":"ping"}',
    '{"jsonrpc":2.0,"method":"ping"}', // version not a string
    '{"jsonrpc":"2.0","method":null}',
    '{"jsonrpc":"2.0","method":7}',
    '{"jsonrpc":"2.0","id":1,"result":1,"error":2}', // both result and error
    '{"jsonrpc":"2.0","result":1}', // response shape without id
    '{"jsonrpc":"2.0","id":1,"method":"tools/call"}', // no params
    '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":7}}',
    '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":null}}',
  ]) {
    assert.equal(cls(body), undefined, `undefined row: ${JSON.stringify(body)}`);
  }
  // Invalid UTF-8: checked before any JSON parse.
  assert.equal(classifyBody(new Uint8Array([0x7b, 0xff, 0x7d])), undefined, "invalid UTF-8 bytes");
});

// ---------------------------------------------------------------------------
// 10. rpcId keeps the raw JSON text.
// ---------------------------------------------------------------------------

test("rpcId keeps the raw JSON text", () => {
  const idOf = (body: string): string | undefined => classifyBody(encoder.encode(body))?.id;
  assert.equal(idOf('{"jsonrpc":"2.0","id":1,"method":"ping"}'), "1", "numeric id");
  assert.equal(idOf('{"jsonrpc":"2.0","id":"abc","method":"ping"}'), '"abc"', "string id keeps the quotes");
  assert.equal(idOf('{"jsonrpc":"2.0","id":null,"result":1}'), "null", "null id");
  assert.equal(idOf('{"jsonrpc":"2.0","id":1.5,"method":"ping"}'), "1.5", "fractional id");
  assert.equal(idOf('{"jsonrpc":"2.0","method":"notifications/initialized"}'), undefined, "notification: no id");
  // Through the pipeline: a signed response carries the quoted raw id.
  const h = harness();
  const alice = materialFor(ALICE);
  const body = encoder.encode('{"jsonrpc":"2.0","id":"str-1","result":{}}');
  const { req } = signed(alice, { body });
  const res = h.verifier.verify(req);
  assert.equal(res.accepted, true, "pipeline: accepted (responses are auth-only)");
  assert.equal(res.rpcId, '"str-1"', "pipeline: rpcId is the raw quoted text");
});

// ---------------------------------------------------------------------------
// 11. arguments keep the exact raw JSON text.
// ---------------------------------------------------------------------------

test("arguments keep the exact raw JSON text (spec 03 section 3)", () => {
  // JSON.parse would lose 1.0 and -0; the raw slice must be verbatim.
  const rawArgs = '{ "ttl": 30, "n": 1.0, "neg": -0 }';
  const msg = classifyBody(
    encoder.encode(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"jack.x","arguments":${rawArgs}}}`),
  );
  assert.ok(msg !== undefined, "defined");
  assert.equal(msg.arguments, rawArgs, "arguments verbatim");
  assert.equal(
    classifyBody(encoder.encode('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"jack.x"}}'))?.arguments,
    undefined,
    "params without arguments",
  );
  assert.equal(
    classifyBody(encoder.encode('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"jack.x","arguments":null}}'))
      ?.arguments,
    "null",
    "arguments null is the raw text",
  );
});

// ---------------------------------------------------------------------------
// 12. NativeCall plumbing.
// ---------------------------------------------------------------------------

test("NativeCall carries what native tools need", () => {
  const native = new RecordingNative();
  const h = harness({ native });
  const alice = materialFor(ALICE);
  const body = encoder.encode(`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"${TOOL_WHOAMI}","arguments":{"a":1}}}`);
  const { req } = signed(alice, { body });
  const res = h.verifier.verify(req);
  // The captured call.
  assert.equal(native.calls.length, 1, "one captured call");
  const call = native.calls[0];
  assert.ok(call !== undefined, "captured call expected");
  assert.equal(call.tool, TOOL_WHOAMI, "call.tool");
  assert.equal(call.arguments, '{"a":1}', "call.arguments raw text");
  assert.ok(call.caller !== undefined, "call.caller defined");
  assert.equal(call.caller.name, "alice", "caller.name");
  assert.equal(call.caller.admin === true, false, "caller.admin (alice does not have admin true)");
  assert.equal(call.caller.admin, undefined, "caller.admin remains absent for alice");
  assert.equal(call.caller.notBefore, undefined, "caller.notBefore absent (unbounded)");
  assert.equal(call.kid, alice.kid, "call.kid");
  assert.equal(call.ts, NOW, "call.ts");
  assert.equal(call.now, NOW, "call.now");
  assert.equal(call.aud, h.aud, "call.aud");
  assert.equal(call.state, h.state, "call.state is the harness state instance");
  // The result.
  assert.equal(res.accepted, true, "result: accepted");
  assert.equal(res.native, true, "result: native");
  assert.equal(res.tool, TOOL_WHOAMI, "result: tool");
  assert.deepEqual(res.structured, { ok: true }, "result: structured");
  assert.equal(res.rpcId, "9", "result: rpcId");
  assert.equal(res.audit, undefined, "result: audit undefined (whoami is not audited)");
});

// ---------------------------------------------------------------------------
// 13. Audit event on a failed admin call.
// ---------------------------------------------------------------------------

test("audit event on a failed admin call carries target, code and actor name", () => {
  const native = new RecordingNative(() => {
    throw new JackError(404, Code.UNKNOWN_TARGET, "no such key");
  }, "target-kid");
  const h = harness({ native, withAudit: true });
  const root = materialFor(ROOT);
  const body = encoder.encode(
    `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"${TOOL_ADMIN_USER_GET}","arguments":{"kid":"x"}}}`,
  );
  const { req } = signed(root, { body });
  const res = h.verifier.verify(req);
  assert.equal(res.accepted, false, "accepted");
  assert.equal(res.httpStatus, 404, "status (from the JackError)");
  assert.equal(res.code, Code.UNKNOWN_TARGET, "code");
  assert.equal(res.nonceRecorded, true, "nonceRecorded");
  // The handler set target BEFORE throwing, so the failure event still names it.
  assert.deepEqual(
    res.audit,
    {
      time: NOW,
      tool: TOOL_ADMIN_USER_GET,
      outcome: AUDIT_FAILURE,
      code: "unknown_target",
      actorKid: root.kid,
      actorName: "root",
      target: "target-kid",
    },
    "res.audit",
  );
  const events = h.audit?.events() ?? [];
  assert.equal(events.length, 1, "sink recorded exactly one event");
  assert.deepEqual(events[0], res.audit, "sink event deep-equals res.audit");
});

// ---------------------------------------------------------------------------
// 14. Undefined jack.* tool and missing handler: 403, no audit.
// ---------------------------------------------------------------------------

test("undefined jack.* tool and missing handler are 403 without audit", () => {
  // Unknown jack.* tool WITH a native configured: still 403 (IsNativeTool gate).
  {
    const h = harness({ native: new RecordingNative() });
    const alice = materialFor(ALICE);
    const body = encoder.encode('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"jack.nope"}}');
    const { req } = signed(alice, { body });
    const res = h.verifier.verify(req);
    assert.equal(res.accepted, false, "nope: accepted");
    assert.equal(res.httpStatus, 403, "nope: status");
    assert.equal(res.code, Code.OPERATION_DENIED, "nope: code");
    assert.equal(res.native, true, "nope: native");
    assert.equal(res.audit, undefined, "nope: audit undefined");
    assert.equal(res.nonceRecorded, true, "nope: nonceRecorded");
  }
  // Real admin tool with native undefined: the call never reached a tool, so
  // no audit event (spec 03 section 8).
  {
    const h = harness({ withAudit: true });
    const alice = materialFor(ALICE);
    const body = encoder.encode(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"${TOOL_ADMIN_USER_LIST}"}}`);
    const { req } = signed(alice, { body });
    const res = h.verifier.verify(req);
    assert.equal(res.accepted, false, "no native: accepted");
    assert.equal(res.httpStatus, 403, "no native: status");
    assert.equal(res.code, Code.OPERATION_DENIED, "no native: code");
    assert.equal(res.native, true, "no native: native");
    assert.equal(res.audit, undefined, "no native: audit undefined");
    assert.equal(res.nonceRecorded, true, "no native: nonceRecorded");
    assert.equal((h.audit?.events() ?? []).length, 0, "no native: sink stayed empty");
  }
});

// ---------------------------------------------------------------------------
// 15. The identity snapshot of forwarded accepts.
// ---------------------------------------------------------------------------

test("the identity snapshot is frozen, per-request, and survives registry changes (in-flight snapshot retained)", () => {
  const native = new Native();
  const h = harness({ native });
  const root = materialFor(ROOT);
  const lowadmin = materialFor("lowadmin");
  // An ORDINARY tool (not jack.*): the request is forwarded with identity set.
  const body = encoder.encode(PING);

  // (1) The first forwarded accept carries the signer's frozen snapshot.
  const first = h.verifier.verify(signed(root, { body }).req);
  assert.equal(first.accepted, true, "first: accepted");
  assert.deepEqual(first.identity, { kid: root.kid, name: ROOT, admin: true }, "first: identity");
  assert.ok(first.identity !== undefined, "first: identity defined");
  assert.ok(Object.isFrozen(first.identity), "first: identity frozen");

  // (2) A second, independent verify() call demotes the same caller through
  // the real native tools. A second admin is added first so the demote does
  // not trip last_admin.
  h.state.update((edit) => {
    edit.putKey({
      kid: lowadmin.kid,
      publicKey: encodeBase64URL(lowadmin.pub),
      name: "lowadmin",
      admin: true,
    });
  });
  const demoteBody = encoder.encode(
    `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"${TOOL_ADMIN_USER_SET_ADMIN}","arguments":{"kid":"${root.kid}","admin":false}}}`,
  );
  const demote = h.verifier.verify(signed(root, { body: demoteBody }).req);
  assert.equal(demote.accepted, true, "demote: accepted (native tools run their own gating)");
  assert.equal(demote.identity, undefined, "demote: native accepts carry no identity");
  const demoted = h.state.lookup(root.kid);
  assert.ok(demoted, "demoted entry expected");
  assert.equal(demoted.admin, undefined, "demote: registry entry is now non-admin");

  // (3) The SAME forwarded request again, fresh nonce: the NEW result reflects
  // the demotion, while the FIRST result's identity snapshot is unchanged.
  const second = h.verifier.verify(signed(root, { body }).req);
  assert.equal(second.accepted, true, "second: accepted");
  assert.deepEqual(second.identity, { kid: root.kid, name: ROOT, admin: false }, "second: identity is the new snapshot");
  assert.deepEqual(first.identity, { kid: root.kid, name: ROOT, admin: true }, "first: snapshot retained");
  assert.ok(Object.isFrozen(first.identity), "first: snapshot still frozen");
});

test("request properties cannot influence the identity: it is always the signer's own registry entry", () => {
  const h = harness();
  const alice = materialFor(ALICE);
  const root = materialFor(ROOT);

  // An ordinary tools/call whose ARGUMENTS claim the root kid: identity must
  // be alice's snapshot, never root's.
  const body = encoder.encode(
    `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"some.other.tool","arguments":{"kid":"${root.kid}","admin":true}}}`,
  );
  const res = h.verifier.verify(signed(alice, { body }).req);
  assert.equal(res.accepted, true, "args spoof: accepted (ordinary tools are forwarded)");
  assert.deepEqual(res.identity, { kid: alice.kid, name: ALICE, admin: false }, "args spoof: identity is the signer's");

  // A notification (no id) carries identity too.
  const notifBody = encoder.encode('{"jsonrpc":"2.0","method":"notifications/initialized"}');
  const notif = h.verifier.verify(signed(alice, { body: notifBody }).req);
  assert.equal(notif.accepted, true, "notification: accepted");
  assert.deepEqual(notif.identity, { kid: alice.kid, name: ALICE, admin: false }, "notification: identity");

  // A response object (id + result) carries identity too.
  const respBody = encoder.encode('{"jsonrpc":"2.0","id":1,"result":{}}');
  const resp = h.verifier.verify(signed(alice, { body: respBody }).req);
  assert.equal(resp.accepted, true, "response: accepted");
  assert.deepEqual(resp.identity, { kid: alice.kid, name: ALICE, admin: false }, "response: identity");
});

// ---------------------------------------------------------------------------
// 16. Verifier config validation and window defaults.
// ---------------------------------------------------------------------------

test("verifier config", () => {
  const base = (): VerifierConfig => ({
    aud: loadRegistry().aud,
    state: new MemoryState(),
    nonces: new NonceStore(),
    now: () => NOW,
  });
  // Empty aud throws (Go NewVerifier parity).
  assert.throws(() => new Verifier({ ...base(), aud: "" }), "aud empty throws");
  // window undefined behaves as DEFAULT_WINDOW: |now-ts| = 31 rejected...
  const alice = materialFor(ALICE);
  const h31 = harness();
  const { req: req31 } = signed(alice, { body: encoder.encode(PING), ts: NOW - 31 });
  assert.equal(h31.verifier.verify(req31).code, Code.TIMESTAMP_OUT_OF_WINDOW, "window undefined: 31 rejected");
  // ...and the same request with window: 60 accepted.
  const h60 = harness();
  const verifier60 = new Verifier({
    aud: h60.aud,
    state: h60.state,
    nonces: h60.nonces,
    now: () => NOW,
    window: 60,
  });
  assert.equal(verifier60.verify(req31).accepted, true, "window 60: 31 accepted");
  // window: 0 behaves as DEFAULT_WINDOW too.
  const h0 = harness();
  const verifier0 = new Verifier({
    aud: h0.aud,
    state: h0.state,
    nonces: h0.nonces,
    now: () => NOW,
    window: 0,
  });
  const { req: req30 } = signed(alice, { body: encoder.encode(PING), ts: NOW - 30 });
  assert.equal(verifier0.verify(req30).accepted, true, "window 0: 30 accepted (DEFAULT_WINDOW)");
  assert.equal(verifier0.verify(req31).code, Code.TIMESTAMP_OUT_OF_WINDOW, "window 0: 31 rejected (DEFAULT_WINDOW)");
});
