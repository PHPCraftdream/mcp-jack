import assert from "node:assert/strict";
import { test } from "node:test";
import { encodeBase64URL } from "../../../src/core/encoding.js";
import { Code, JackError } from "../../../src/core/errors.js";
import { AUDIT_FAILURE } from "../../../src/server/audit.js";
import { Native } from "../../../src/server/native.js";
import { NonceStore } from "../../../src/server/registry/nonce.js";
import { MemoryState, inviteIdOf } from "../../../src/server/registry/state.js";
import { Verifier, TOOL_ADMIN_USER_SET_ADMIN, TOOL_ADMIN_USER_GET, TOOL_ADMIN_USER_LIST, TOOL_WHOAMI } from "../../../src/server/verify.js";
import type { NativeCall, VerifierConfig } from "../../../src/server/verify.js";
import { loadRegistry } from "../../support/fixtures/index.js";
import { NOW, NONCE, PING, encoder, materialFor, randomKey, harness, signed, RecordingNative, ALICE, ROOT, ENROLL_CODE_RAW, enrollBody, clockHarness, ping, steppedHarness } from "./support.js";

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

test("a broken injected clock fails closed with 500 and records no nonce", () => {
  const alice = materialFor(ALICE);
  for (const bad of [Number.NaN, undefined as unknown as number, -1, Number.POSITIVE_INFINITY]) {
    const native = new RecordingNative();
    const { verifier, nonces } = clockHarness(() => bad, native);
    // A request that is otherwise perfectly valid: signed for ts=NOW.
    const { req } = signed(alice, { body: encoder.encode(PING) });
    const res = verifier.verify(req);
    assert.equal(res.accepted, false, `${bad}: accepted`);
    assert.equal(res.httpStatus, 500, `${bad}: status`);
    assert.equal(res.code, "internal_error", `${bad}: code`);
    assert.equal(res.nonceRecorded, false, `${bad}: nonceRecorded`);
    assert.equal(res.requestSig, "", `${bad}: requestSig`);
    assert.equal(nonces.len(), 0, `${bad}: no nonce recorded`);
    assert.equal(native.calls.length, 0, `${bad}: nothing dispatched`);
  }
});

test("verifier constructor validates shared window bounds and safe integers", () => {
  const base = (): VerifierConfig => ({
    aud: loadRegistry().aud,
    state: new MemoryState(),
    nonces: new NonceStore(),
    now: () => NOW,
  });
  assert.throws(
    () => new Verifier({ ...base(), window: Number.NaN }),
    /server: window must be 0 \(default 30\) or an integer between 1 and 120 seconds/,
  );
  assert.throws(
    () => new Verifier({ ...base(), window: Number.POSITIVE_INFINITY }),
    /server: window must be 0 \(default 30\) or an integer between 1 and 120 seconds/,
  );
  for (const window of [-1, 121, 1.5, 2 ** 53]) {
    assert.throws(
      () => new Verifier({ ...base(), window }),
      /server: window must be 0 \(default 30\) or an integer between 1 and 120 seconds/,
      `invalid volatile window ${window}`,
    );
  }
  const alice = materialFor(ALICE);
  const maxWindowHarness = harness();
  const verifier120 = new Verifier({
    aud: maxWindowHarness.aud,
    state: maxWindowHarness.state,
    nonces: maxWindowHarness.nonces,
    now: () => NOW,
    window: 120,
  });
  const { req: req120 } = signed(alice, { body: encoder.encode(PING), ts: NOW + 120 });
  const { req: req121 } = signed(alice, { body: encoder.encode(PING), ts: NOW + 121 });
  // spec 01 section 4/task165: inclusive window edge accepts; one second beyond rejects.
  assert.equal(verifier120.verify(req120).accepted, true, "window 120 boundary accepted");
  assert.equal(verifier120.verify(req121).code, Code.TIMESTAMP_OUT_OF_WINDOW, "window 121 boundary rejected");
});

test("verifier constructor rejects aud control characters; ordinary aud accepted", () => {
  const base = (): VerifierConfig => ({
    aud: loadRegistry().aud,
    state: new MemoryState(),
    nonces: new NonceStore(),
    now: () => NOW,
  });
  for (const bad of ["a\nb", "a\rb", "a\u0000b", "a\tb", "a\u007fb"]) {
    assert.throws(() => new Verifier({ ...base(), aud: bad }), /aud must be non-empty and contain no control characters/);
  }
  assert.doesNotThrow(() => new Verifier(base()), "ordinary aud accepted");
});

test("clock step forward then back: the replay is refused and old timestamps are out of window", () => {
  const { verifier, setClock } = steppedHarness();
  const alice = materialFor(ALICE);
  const jump = NOW + 1000;

  setClock(jump);
  const first = signed(alice, { ts: jump, nonce: NONCE, body: ping });
  assert.equal(verifier.verify(first.req).accepted, true, "request at the stepped-forward time");

  setClock(NOW);
  const replay = verifier.verify(first.req);
  assert.equal(replay.accepted, false, "replay after the step back");
  assert.equal(replay.code, Code.REPLAYED_NONCE);

  const old = verifier.verify(signed(alice, { ts: NOW, body: ping }).req);
  assert.equal(old.accepted, false, "ts=T judged against the high-water mark");
  assert.equal(old.code, Code.TIMESTAMP_OUT_OF_WINDOW);
});

test("clock high-water mark: a request ahead of the raw clock is judged against the mark", () => {
  const { verifier, setClock } = steppedHarness();
  const alice = materialFor(ALICE);
  const jump = NOW + 1000;

  // Without a prior step the same request is out of window.
  const early = verifier.verify(signed(alice, { ts: jump, body: ping }).req);
  assert.equal(early.code, Code.TIMESTAMP_OUT_OF_WINDOW, "no high-water mark yet");

  setClock(jump);
  assert.equal(verifier.verify(signed(alice, { ts: jump, body: ping }).req).accepted, true, "forward movement");
  setClock(NOW);
  assert.equal(verifier.clock(), NOW, "clock getter continues to expose the raw injected sample");
  assert.equal(verifier.verify(signed(alice, { ts: jump, body: ping }).req).accepted, true, "ts=T+1000 at raw T");
  setClock(jump + 5);
  assert.equal(verifier.verify(signed(alice, { ts: jump + 5, body: ping }).req).accepted, true, "moving on");
});

test("clock high-water mark applies to key validity even after raw clock moves back", () => {
  const { verifier, setClock, state } = steppedHarness();
  const alice = materialFor(ALICE);
  const expiring = randomKey();
  const jump = NOW + 1000;
  state.update((edit) => edit.putKey({
    kid: expiring.kid,
    publicKey: encodeBase64URL(expiring.pub),
    name: "expiring",
    notAfter: jump - 10,
  }));

  setClock(jump);
  assert.equal(verifier.verify(signed(alice, { ts: jump, body: ping }).req).accepted, true, "advance high-water mark");
  setClock(jump - 20); // Raw time is still before notAfter; effective time is not.
  const { req } = signed(expiring, { ts: jump, body: ping });
  const res = verifier.verify(req);
  // spec 01 section 4/task165: key activity uses effective, not raw, request time.
  assert.equal(res.code, Code.KEY_INACTIVE, "expired at high-water mark stays inactive");
  assert.equal(res.nonceRecorded, false, "inactive key fails before nonce recording");
});

test("clock high-water mark applies to enrollment invite expiry before nonce/audit/consumption", () => {
  const { verifier, setClock, state, nonces, audit } = steppedHarness({ native: new Native(), withAudit: true });
  const alice = materialFor(ALICE);
  const enrolling = randomKey();
  const jump = NOW + 1000;
  const code = encodeBase64URL(ENROLL_CODE_RAW);
  state.update((edit) => {
    edit.putInvite({ inviteId: inviteIdOf(ENROLL_CODE_RAW), createdBy: ROOT, createdAt: NOW - 1, expiresAt: jump - 10 });
  });

  setClock(jump);
  assert.equal(verifier.verify(signed(alice, { ts: jump, body: ping }).req).accepted, true, "advance high-water mark");
  setClock(jump - 20); // Raw time sees a live invite; effective time sees it expired.
  const { req } = signed(enrolling, { ts: jump, body: enrollBody(enrolling, code) });
  const res = verifier.verify(req);
  // spec 01 section 4/task165: a stale invite remains unknown_key with no auth side effects.
  assert.equal(res.code, Code.UNKNOWN_KEY, "expired invite stays unknown_key");
  assert.equal(res.nonceRecorded, false, "expired invite does not record nonce");
  assert.equal(nonces.len(), 1, "only the earlier valid request is in the volatile store");
  assert.equal(audit?.events().length, 0, "expired invite does not audit");
  assert.notEqual(state.lookupInvite(inviteIdOf(ENROLL_CODE_RAW)), undefined, "verifier does not consume invite");
});

test("native handler and audit receive effective request time", () => {
  const native = new RecordingNative();
  const { verifier, setClock, audit } = steppedHarness({ native, withAudit: true });
  const alice = materialFor(ROOT);
  const jump = NOW + 1000;

  setClock(jump);
  assert.equal(verifier.verify(signed(alice, { ts: jump, body: ping }).req).accepted, true, "advance high-water mark");
  setClock(jump - 20);
  const body = encoder.encode(JSON.stringify({
    jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: TOOL_ADMIN_USER_LIST, arguments: {} },
  }));
  const res = verifier.verify(signed(alice, { ts: jump, body }).req);
  // spec 01 section 4/task165: native Now and audit time use effective request time.
  assert.equal(res.accepted, true, "native call accepted");
  assert.equal(native.calls.length, 1, "native handler called once");
  assert.equal(native.calls[0]?.now, jump, "native receives high-water time");
  assert.equal(res.audit?.time, jump, "result audit uses high-water time");
  assert.equal(audit?.events()[0]?.time, jump, "audit sink uses high-water time");
});

test("invalid clock sample stays fail-closed and does not corrupt the high-water mark", () => {
  const { verifier, setClock } = steppedHarness();
  const alice = materialFor(ALICE);
  const jump = NOW + 1000;

  setClock(jump);
  assert.equal(verifier.verify(signed(alice, { ts: jump, body: ping }).req).accepted, true);

  setClock(Number.NaN);
  const broken = verifier.verify(signed(alice, { ts: jump, body: ping }).req);
  assert.equal(broken.accepted, false);
  assert.equal(broken.httpStatus, 500);
  assert.equal(broken.code, "internal_error");

  // A NaN mark would make every window compare false; the mark must still be jump.
  setClock(NOW);
  const old = verifier.verify(signed(alice, { ts: NOW, body: ping }).req);
  assert.equal(old.code, Code.TIMESTAMP_OUT_OF_WINDOW);
  assert.equal(verifier.verify(signed(alice, { ts: jump, body: ping }).req).accepted, true);
});
