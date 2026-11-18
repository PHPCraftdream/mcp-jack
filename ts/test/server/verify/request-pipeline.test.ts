import assert from "node:assert/strict";
import { test } from "node:test";
import { formatRequestAuth } from "../../../src/core/auth-header.js";
import { encodeBase64URL } from "../../../src/core/encoding.js";
import { Code } from "../../../src/core/errors.js";
import { inviteIdOf } from "../../../src/server/registry/state.js";
import { classifyBody, TOOL_ENROLL } from "../../../src/server/verify.js";
import type { RpcMessage } from "../../../src/server/verify.js";
import { NOW, NONCE, NONCE2, PING, encoder, materialFor, randomKey, harness, signed, ALICE, ENROLL_CODE_RAW, seedInvite, enrollBody, assertUnknownKey, ping } from "./support.js";

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

test("enrollment exception passes authentication (steps 5-8 skipped for the registry interval)", () => {
  // (a) Valid submitted key hashing to the header kid: authentication SUCCEEDS
  // even though the kid is unregistered; without a native handler the call
  // fails later, at the native-tool gate, with 403 operation_denied.
  {
    const h = harness();
    const k = randomKey();
    const body = encoder.encode(
      `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"${TOOL_ENROLL}","arguments":{"code":"${seedInvite(h)}","public_key":"${encodeBase64URL(k.pub)}"}}}`,
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
      `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"${TOOL_ENROLL}","arguments":{"code":"${seedInvite(h)}","public_key":"${encodeBase64URL(k2.pub)}"}}}`,
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
      `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"${TOOL_ENROLL}","arguments":{"code":"${seedInvite(h)}","public_key":"${encodeBase64URL(new Uint8Array(32))}"}}}`,
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
      `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"${TOOL_ENROLL}","arguments":{"code":"${seedInvite(h)}","public_key":"not-base64url!!"}}}`,
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

test("enrollment exception: unknown kid without any invite is unknown_key, nothing recorded", () => {
  const h = harness({ withAudit: true });
  const k = randomKey();
  const { req } = signed(k, { body: enrollBody(k, encodeBase64URL(ENROLL_CODE_RAW)), nonce: NONCE });
  assertUnknownKey(h, req, k.kid, "no invite");
  assert.equal(h.audit?.events().length, 0, "no audit event");
});

test("enrollment exception: an invite expiring exactly now is not live", () => {
  const h = harness({ withAudit: true });
  const k = randomKey();
  const code = seedInvite(h, NOW);
  const { req } = signed(k, { body: enrollBody(k, code) });
  assertUnknownKey(h, req, k.kid, "now == expiresAt");
  assert.equal(h.audit?.events().length, 0, "no audit event");
});

test("enrollment exception: code must be a canonical 32-byte base64url string", () => {
  const h = harness();
  seedInvite(h);
  const k = randomKey();
  const canonical = encodeBase64URL(ENROLL_CODE_RAW);
  const cases: [string, unknown][] = [
    ["padded", `${canonical}=`],
    ["short", canonical.slice(0, 40)],
    ["standard alphabet", `${canonical.slice(0, 10)}+${canonical.slice(11)}`],
    ["non-canonical trailing bits", `${canonical.slice(0, 42)}d`],
    ["not a string", 7],
    ["absent", undefined],
  ];
  for (const [label, code] of cases) {
    const { req } = signed(k, { body: enrollBody(k, code) });
    assertUnknownKey(h, req, k.kid, label);
  }
});

test("enrollment exception: the invite gate runs before public key validation", () => {
  const h = harness();
  const k = randomKey();
  const body = encoder.encode(
    `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"${TOOL_ENROLL}","arguments":{"code":"${encodeBase64URL(ENROLL_CODE_RAW)}","public_key":"not-base64url!!"}}}`,
  );
  const { req } = signed(k, { body });
  assertUnknownKey(h, req, k.kid, "bad key without invite is unknown_key, not key_rejected");
});

test("enrollment exception: a live invite is accepted and the verifier does not consume it", () => {
  const h = harness();
  const k = randomKey();
  const code = seedInvite(h, NOW + 1);
  const { req } = signed(k, { body: enrollBody(k, code) });
  const res = h.verifier.verify(req);
  // No native handler configured: authentication succeeded, the tool gate says 403.
  assert.equal(res.httpStatus, 403, "status");
  assert.equal(res.code, Code.OPERATION_DENIED, "code");
  assert.equal(res.nonceRecorded, true, "nonceRecorded");
  assert.ok(h.state.lookupInvite(inviteIdOf(ENROLL_CODE_RAW)) !== undefined, "invite still stored");
});

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

test("classifyBody: surrogate escapes and the 128-level depth cap (spec 02 section 4)", () => {
  const ok = (body: string) => assert.ok(classifyBody(encoder.encode(body)) !== undefined, body);
  const bad = (body: string) => assert.equal(classifyBody(encoder.encode(body)), undefined, body);
  bad('{"jsonrpc":"2.0","id":1,"method":"pi\\ud800ng"}');
  bad('{"jsonrpc":"2.0","id":1,"m\\ud800":1,"method":"ping"}');
  bad('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"stat\\udc00us"}}');
  bad('{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":"\\ud83d\\ude00\\ud800"}}');
  ok('{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":"\\ud83d\\ude00"}}');
  ok('{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":"a\\\\ud800b"}}');
  const deep = (levels: number): string =>
    `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":${"[".repeat(levels)}${"]".repeat(levels)}}}`;
  ok(deep(126));
  bad(deep(127));
  // Brackets inside string values never count toward the depth.
  ok(
    `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":"${"[".repeat(200)}${"]".repeat(200)}"}}`,
  );
});

test("classifyBody: duplicate member names make the body unacceptable at any depth", () => {
  const ok = (body: string) => assert.ok(classifyBody(encoder.encode(body)) !== undefined, body);
  const bad = (body: string) => assert.equal(classifyBody(encoder.encode(body)), undefined, body);
  bad('{"jsonrpc":"2.0","id":1,"method":"ping","method":"pong"}'); // top level
  bad('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a","name":"b"}}'); // nested in params
  bad('{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":[1,{"k":1,"k":2}]}}'); // object inside an array
  bad('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"jack.x","arguments":{"a":{"b":1,"b":1}}}}'); // free-form arguments
  bad('{"jsonrpc":"2.0","id":1,"meth\\u006fd":"ping","method":"ping"}'); // escaped spelling of the same name
  bad('{"jsonrpc":"2.0","id":1,"method":"ping","params":{"\\u00e9":1,"\u00e9":2}}'); // escaped vs raw non-ASCII
  bad('{"jsonrpc":"2.0","id":1,"method":"ping","params":{"__proto__":1,"__proto__":2}}'); // prototype key
  // Same name in different objects, and a value equal to a name, are fine.
  ok('{"jsonrpc":"2.0","id":1,"method":"ping","params":{"a":{"x":1},"b":{"x":2},"c":[{"x":1},{"x":2}]}}');
  ok('{"jsonrpc":"2.0","id":1,"method":"ping","params":{"constructor":1,"__proto__":2,"id":"method"}}');
  // Names differing only in case are different names.
  ok('{"jsonrpc":"2.0","id":1,"method":"ping","params":{"A":1,"a":2}}');
});

test("a duplicate member is 400 invalid_request after authentication; the nonce stays consumed", () => {
  const h = harness();
  const alice = materialFor(ALICE);
  const body = encoder.encode('{"jsonrpc":"2.0","id":1,"method":"ping","method":"ping"}');
  const { req } = signed(alice, { body });
  const res = h.verifier.verify(req);
  assert.equal(res.accepted, false, "accepted");
  assert.equal(res.httpStatus, 400, "status");
  assert.equal(res.code, Code.INVALID_REQUEST, "code");
  assert.equal(res.nonceRecorded, true, "nonceRecorded");
});

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
