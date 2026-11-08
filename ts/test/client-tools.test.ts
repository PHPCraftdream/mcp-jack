/** Typed tool-call tests, ported from Go client/tools_test.go (using the harness TestServer). */
import assert from "node:assert/strict";
import { test } from "node:test";
import { parseRequestAuth } from "../src/auth-header.js";
import { verify } from "../src/ed25519.js";
import { decodeBase64URL, decodeBase64URLFixed } from "../src/encoding.js";
import { requestSigningString, rotateProofString } from "../src/signing.js";
import { HTTPError, ToolError } from "../src/client/errors.js";
import { Client } from "../src/client/rpc.js";
import type { Signer } from "../src/client/signer.js";
import {
  newFixtureClient,
  newTestServer,
  queuedNonce,
  seedSignerByName,
  fixtureAud,
  fixtureNow,
  rpcResultBody,
} from "./client-harness.js";
import type { TestServer } from "./client-harness.js";
import { loadAdminVectors } from "./fixtures.js";
import type { Step } from "./fixtures.js";

const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

/** rpcResultBody with a fixture step's expected structuredContent as the payload. */
function rpcResult(step: Step): Uint8Array {
  assert.ok(step.expect.structured !== undefined, `case step has no expect.structured`);
  return utf8('{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}],"isError":false,"structuredContent":' + JSON.stringify(step.expect.structured) + "}}");
}

/** adminCase finds the named case in the admin vectors. */
function adminCase(id: string): Step {
  const c = loadAdminVectors().cases.find((c) => c.id === id);
  assert.ok(c !== undefined, `admin vectors have no case ${JSON.stringify(id)}`);
  const step = c.steps[0];
  assert.ok(step !== undefined && c.steps.length > 0, `case ${id} has no steps`);
  return step;
}

/** The Jack-Auth header value of a fixture request. */
function fixtureHeaderValue(step: Step): string {
  const hv = step.request.headers.find((h) => h.name === "Jack-Auth")?.value;
  assert.ok(hv !== undefined, "fixture request has no Jack-Auth header");
  return hv;
}

/** The base64url nonce of a fixture Jack-Auth header. */
function fixtureNonce(step: Step): string {
  return parseRequestAuth([fixtureHeaderValue(step)]).nonce;
}

/** Whether the two byte strings are identical. */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  return Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0;
}

/** Asserts the fake fetch observed a signed POST /mcp request whose body is exactly expectedBodyText and whose signature verifies under signer; everything is captured from the fake, nothing hard-coded. */
function assertSignedRequest(server: TestServer, signer: Signer, expectedBodyText: string): void {
  const last = server.lastRequest;
  assert.ok(last !== null, "the fake fetch observed no request");
  assert.equal(last.method, "POST", "captured method");
  assert.equal(last.target, "/mcp", "captured target");
  assert.ok(last.header !== null, "captured request carries no Jack-Auth header");
  const auth = parseRequestAuth([last.header]);
  assert.equal(auth.kid, signer.kid(), "captured header kid");
  assert.equal(bytesEqual(last.body, utf8(expectedBodyText)), true, "captured body bytes");
  const msg = utf8(requestSigningString(last.method, last.target, fixtureAud, auth.kid, auth.ts, auth.nonce, last.body));
  assert.equal(verify(signer.publicKey(), msg, decodeBase64URLFixed(auth.sig, 64)), true, "captured request signature");
}

test("enroll matches the fixture", async () => {
  const step = adminCase("enroll-ok");
  const server = newTestServer();
  const newbieSigner = seedSignerByName("newbie");
  server.handle = (auth) => server.writeSignedJSON(auth, 200, rpcResult(step));
  const client = newFixtureClient(server, newbieSigner, fixtureNonce(step));
  const res = await client.enroll("NTpoPAFYwVkAdj8kps_x_Q_pgjkaWP-pvdbaV0eQau4", "newbie", newbieSigner);
  // Captured from the fake via server.lastRequest (no closure-narrowed lets).
  const fixtureBody = new TextDecoder().decode(decodeBase64URL(step.request.bodyB64u));
  assertSignedRequest(server, newbieSigner, fixtureBody);
  // Byte-exact contract: the whole Jack-Auth header equals the fixture header.
  const fixtureHeader = step.request.headers.find((pair) => pair.name.toLowerCase() === "jack-auth");
  assert.ok(fixtureHeader !== undefined, "the fixture carries a Jack-Auth header");
  assert.equal(server.lastRequest?.header, fixtureHeader.value, "captured header equals the fixture header");
  assert.deepStrictEqual(res, { kid: "imZX4AkHSrS_UT1wZ5oEPklelGqIooKk4TfK3ht5LYg", name: "newbie", kind: "human", scopes: ["read"] });
});

test("rotate matches the fixture", async () => {
  const step = adminCase("rotate-ok");
  const server = newTestServer();
  const aliceSigner = seedSignerByName("alice");
  const newbieSigner = seedSignerByName("newbie");
  server.handle = (auth) => server.writeSignedJSON(auth, 200, rpcResult(step));
  const client = newFixtureClient(server, aliceSigner, fixtureNonce(step));
  const res = await client.rotateKey(newbieSigner);

  // Captured from the fake via server.lastRequest (no closure-narrowed lets).
  const last = server.lastRequest;
  assert.ok(last !== null, "the fake fetch observed no request");
  assert.equal(last.method, "POST", "method");
  assert.equal(last.target, "/mcp", "target");
  assert.ok(last.header !== null, "captured request carries no Jack-Auth header");
  assert.equal(last.header, fixtureHeaderValue(step), "Jack-Auth header");
  assert.equal(bytesEqual(last.body, decodeBase64URL(step.request.bodyB64u)), true, "body bytes");

  // Independent re-derivation of the proof from the primitives (spec 03 section 3.1):
  // the client must have signed exactly rotateProofString(aud, oldKid, newKid, fixtureNow).
  const parsed = JSON.parse(new TextDecoder().decode(last.body)) as { params?: { arguments?: { public_key?: unknown; proof?: unknown } } };
  const args = parsed.params?.arguments;
  assert.ok(args !== undefined, "captured body has no params.arguments");
  assert.equal(args.public_key, "71JMCNs18t7E5IysFMZEKsnlr9Cw0kahC_h5FkDWrdQ", "arguments.public_key");
  assert.equal(typeof args.proof, "string", "arguments.proof must be a string");
  const proofBytes = decodeBase64URLFixed(args.proof as string, 64);
  const msg = utf8(rotateProofString(fixtureAud, aliceSigner.kid(), newbieSigner.kid(), fixtureNow));
  assert.equal(verify(newbieSigner.publicKey(), msg, proofBytes), true, "rotate proof does not verify under the newbie key");
  assert.equal(res.kid, "imZX4AkHSrS_UT1wZ5oEPklelGqIooKk4TfK3ht5LYg", "KidResult.kid");
});

test("whoami decodes the canned result", async () => {
  const server = newTestServer();
  server.handle = (auth) =>
    server.writeSignedJSON(
      auth,
      200,
      utf8('{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}],"isError":false,"structuredContent":' +
        '{"kid":"imZX4AkHSrS_UT1wZ5oEPklelGqIooKk4TfK3ht5LYg","name":"newbie","kind":"human","scopes":["read"],"not_before":null,"not_after":null}' +
        "}}"),
    );
  const client = newFixtureClient(server, seedSignerByName("newbie"), "assryd677-uYrqD4v-7HYw");
  const res = await client.whoAmI();
  assert.equal(res.kid, "imZX4AkHSrS_UT1wZ5oEPklelGqIooKk4TfK3ht5LYg", "kid");
  assert.equal(res.name, "newbie", "name");
  assert.equal(res.kind, "human", "kind");
  assert.deepStrictEqual(res.scopes, ["read"], "scopes");
  assert.equal(res.notBefore, null, "notBefore");
  assert.equal(res.notAfter, null, "notAfter");
});

test("admin list decodes the wrappers", async () => {
  const server = newTestServer();
  server.handle = (auth, body) => {
    const text = new TextDecoder().decode(body);
    if (text.includes('"jack.admin.user.list"')) {
      return server.writeSignedJSON(
        auth,
        200,
        utf8('{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}],"isError":false,"structuredContent":' +
          '{"users":[{"kid":"k1","public_key":"p1","name":"alice","kind":"human","scopes":["read"],"not_before":null,"not_after":1750000000}]}' +
          "}}"),
      );
    }
    return server.writeSignedJSON(
      auth,
      200,
      utf8('{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}],"isError":false,"structuredContent":' +
        '{"invites":[{"invite_id":"iv1","scopes":["read"],"kind":"human","created_by":"k1","created_at":1767225500,"expires_at":1767228600}]}' +
        "}}"),
    );
  };
  // Two calls are made, so the SAME nonce is queued twice; Go queues one and its
  // TestAdminListDecodesWrappers therefore fails on the second call.
  // Built inline instead of via newFixtureClient, whose single-nonce queue would
  // exhaust on the second call; config otherwise identical.
  const client = new Client({
    baseUrl: "https://mcp.test/mcp",
    aud: fixtureAud,
    signer: seedSignerByName("alice"),
    serverKey: server.pub,
    fetchImpl: server.fetch,
    clock: () => fixtureNow,
    windowSeconds: 30,
    nonceSource: queuedNonce(["assryd677-uYrqD4v-7HYw", "assryd677-uYrqD4v-7HYw"]),
  });

  const users = await client.adminUserList();
  assert.equal(users.length, 1, "len(users)");
  const user = users[0];
  assert.ok(user !== undefined, "users is empty");
  assert.equal(user.kind, "human", "users[0].kind");
  assert.equal(user.notAfter, 1750000000, "users[0].notAfter");
  assert.equal(user.notBefore, null, "users[0].notBefore");

  const invites = await client.adminInviteList();
  assert.equal(invites.length, 1, "len(invites)");
  const invite = invites[0];
  assert.ok(invite !== undefined, "invites is empty");
  assert.equal(invite.inviteId, "iv1", "invites[0].inviteId");
  assert.equal(invite.expiresAt, 1767228600, "invites[0].expiresAt");
});

test("adminUserCreate serializes and decodes", async () => {
  const server = newTestServer();
  server.handle = (auth) => server.writeSignedJSON(auth, 200, rpcResultBody('{"kid":"k-new"}'));
  const alice = seedSignerByName("alice");
  const client = newFixtureClient(server, alice, "assryd677-uYrqD4v-7HYw");
  const res = await client.adminUserCreate({ name: "dave", publicKey: "71JMCNs18t7E5IysFMZEKsnlr9Cw0kahC_h5FkDWrdQ", scopes: ["read", "lifecycle"] });
  // Argument field order pins the Go struct (name, public_key, scopes); kind
  // and the validity bounds are absent here, exercising the omitempty branch.
  assertSignedRequest(
    server,
    alice,
    '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"jack.admin.user.create","arguments":{"name":"dave","public_key":"71JMCNs18t7E5IysFMZEKsnlr9Cw0kahC_h5FkDWrdQ","scopes":["read","lifecycle"]}}}',
  );
  assert.deepStrictEqual(res, { kid: "k-new" });
});

test("adminUserSetScopes serializes and decodes", async () => {
  const server = newTestServer();
  server.handle = (auth) =>
    server.writeSignedJSON(auth, 200, rpcResultBody('{"kid":"k1","public_key":"p1","name":"alice","kind":"human","scopes":["read","write"],"not_before":null,"not_after":1750000000}'));
  const alice = seedSignerByName("alice");
  const client = newFixtureClient(server, alice, "assryd677-uYrqD4v-7HYw");
  const res = await client.adminUserSetScopes("k1", ["read", "write"]);
  assertSignedRequest(server, alice, '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"jack.admin.user.set_scopes","arguments":{"kid":"k1","scopes":["read","write"]}}}');
  assert.deepStrictEqual(res, { kid: "k1", publicKey: "p1", name: "alice", kind: "human", scopes: ["read", "write"], notBefore: null, notAfter: 1750000000 });
});

test("adminUserRevoke serializes and decodes", async () => {
  const server = newTestServer();
  server.handle = (auth) => server.writeSignedJSON(auth, 200, rpcResultBody('{"kid":"k1"}'));
  const alice = seedSignerByName("alice");
  const client = newFixtureClient(server, alice, "assryd677-uYrqD4v-7HYw");
  const res = await client.adminUserRevoke("k1");
  assertSignedRequest(server, alice, '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"jack.admin.user.revoke","arguments":{"kid":"k1"}}}');
  assert.deepStrictEqual(res, { kid: "k1" });
});

test("adminInviteCreate serializes and decodes", async () => {
  const server = newTestServer();
  server.handle = (auth) => server.writeSignedJSON(auth, 200, rpcResultBody('{"invite_id":"iv9","code":"CjvNqZF4P3z5UkoiYbBNcLfh5a8kNRxMLHUf9BLhErk","expires_at":1767229200}'));
  const alice = seedSignerByName("alice");
  const client = newFixtureClient(server, alice, "assryd677-uYrqD4v-7HYw");
  const res = await client.adminInviteCreate({ scopes: ["read"], kind: "human", ttlSeconds: 3600 });
  // Go struct order for the optional fields: kind, ttl_seconds, key_ttl_seconds.
  assertSignedRequest(server, alice, '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"jack.admin.invite.create","arguments":{"scopes":["read"],"kind":"human","ttl_seconds":3600}}}');
  assert.deepStrictEqual(res, { inviteId: "iv9", code: "CjvNqZF4P3z5UkoiYbBNcLfh5a8kNRxMLHUf9BLhErk", expiresAt: 1767229200 });
});

test("adminInviteRevoke serializes and decodes", async () => {
  const server = newTestServer();
  server.handle = (auth) => server.writeSignedJSON(auth, 200, rpcResultBody('{"invite_id":"iv1"}'));
  const alice = seedSignerByName("alice");
  const client = newFixtureClient(server, alice, "assryd677-uYrqD4v-7HYw");
  const res = await client.adminInviteRevoke("iv1");
  assertSignedRequest(server, alice, '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"jack.admin.invite.revoke","arguments":{"invite_id":"iv1"}}}');
  assert.deepStrictEqual(res, { inviteId: "iv1" });
});

test("http error surfaces status and code", async () => {
  const server = newTestServer();
  server.handle = (auth) => server.writeSignedJSON(auth, 403, utf8('{"error":{"code":"insufficient_scope","message":"no"}}'));
  const client = newFixtureClient(server, seedSignerByName("alice"), "assryd677-uYrqD4v-7HYw");
  await assert.rejects(
    client.adminUserGet("k1"),
    (err: unknown) => err instanceof HTTPError && err.status === 403 && err.code === "insufficient_scope",
  );
});

test("tool error surfaces the content text", async () => {
  const server = newTestServer();
  server.handle = (auth) =>
    server.writeSignedJSON(
      auth,
      200,
      utf8('{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"boom"}],"isError":true}}'),
    );
  const client = newFixtureClient(server, seedSignerByName("alice"), "assryd677-uYrqD4v-7HYw");
  await assert.rejects(client.whoAmI(), (err: unknown) => {
    assert.ok(err instanceof ToolError, `expected ToolError, got ${String(err)}`);
    assert.equal(err.message, "boom", "ToolError.message");
    return true;
  });
});
