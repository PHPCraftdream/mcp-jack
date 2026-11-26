/**
 * Spec 04 C7: the native `jack.*` result shape per era. In the modern era a
 * native result is the 0.1.x result plus `resultType: "complete"` and
 * `result._meta["io.modelcontextprotocol/serverInfo"]`; the legacy era is
 * byte-identical to 0.1.x, error answers carry no `resultType`, and the
 * refusal of a request never reaches a native tool.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  MODERN,
  assertSigned,
  errorCode,
  mirrorsFor,
  modernRequest,
  modernToolCallBody,
  newModernHarness,
  seedSignerByName,
} from "./support.js";

/** The members of the native result both eras share, plus the modern ones. */
interface NativeBody {
  readonly result: {
    readonly structuredContent?: Record<string, unknown>;
    readonly resultType?: string;
    readonly _meta?: Record<string, unknown>;
  };
}

test("native_result_era_shape", async () => {
  const alice = seedSignerByName("alice");
  const aliceKid = alice.kid();

  // Modern era: the complete-shaped result plus the serverInfo _meta.
  const modern = newModernHarness("modern");
  const who = modernRequest(alice, {
    body: modernToolCallBody("1", "jack.whoami"),
    headers: mirrorsFor("tools/call", "jack.whoami"),
  });
  const whoResponse = await modern.handle(who.request);
  assert.equal(whoResponse.status, 200);
  const whoBody = await assertSigned(whoResponse, modern.serverPub, who.sig);
  const parsedModern = JSON.parse(Buffer.from(whoBody).toString("utf-8")) as NativeBody;
  assert.equal(parsedModern.result.resultType, "complete", "C7: the modern result is complete");
  assert.deepEqual(parsedModern.result._meta?.["io.modelcontextprotocol/serverInfo"], {
    name: "mcp-jack",
    version: "0.1.0",
  });
  assert.equal(parsedModern.result.structuredContent?.["kid"], aliceKid, "the structured caller kid is unchanged");

  // Legacy era (explicit profile): the 0.1.x result, no resultType, no _meta.
  const legacy = newModernHarness("legacy");
  const legacyWho = modernRequest(alice, {
    body: modernToolCallBody("1", "jack.whoami"),
    headers: mirrorsFor("tools/call", "jack.whoami"),
  });
  const legacyResponse = await legacy.handle(legacyWho.request);
  assert.equal(legacyResponse.status, 200);
  const legacyBody = await assertSigned(legacyResponse, legacy.serverPub, legacyWho.sig);
  const parsedLegacy = JSON.parse(Buffer.from(legacyBody).toString("utf-8")) as { result: Record<string, unknown> };
  assert.equal(Object.hasOwn(parsedLegacy.result, "resultType"), false, "C7: no resultType in the legacy era");
  assert.equal(Object.hasOwn(parsedLegacy.result, "_meta"), false, "C7: no _meta in the legacy era");
  assert.deepEqual(parsedLegacy.result["structuredContent"], {
    kid: aliceKid,
    name: "alice",
    admin: false,
    not_before: null,
    not_after: null,
  });

  // An error answer is the 01 section 4 envelope and never carries resultType,
  // even though the request itself is modern-era.
  const denied = newModernHarness("modern");
  const userList = modernRequest(alice, {
    body: modernToolCallBody("1", "jack.admin.user.list"),
    headers: mirrorsFor("tools/call", "jack.admin.user.list"),
  });
  const deniedResponse = await denied.handle(userList.request);
  assert.equal(deniedResponse.status, 403);
  const deniedBody = await assertSigned(deniedResponse, denied.serverPub, userList.sig);
  const deniedText = Buffer.from(deniedBody).toString("utf-8");
  assert.equal(errorCode(deniedBody), "admin_required");
  const deniedParsed = JSON.parse(deniedText) as { error?: { code?: string; message?: string }; jsonrpc?: unknown };
  assert.deepEqual(Object.keys(deniedParsed), ["error"], "the refusal is the 01 section 4 envelope");
  assert.equal(deniedParsed.error?.code, "admin_required");
  assert.equal(typeof deniedParsed.error?.message, "string");
  assert.equal(deniedText.includes("resultType"), false, "error answers never carry resultType");

  // Ordering: the S6 refusal happens BEFORE native dispatch, so the refused
  // invite.create never reaches the tool and the invite list stays empty.
  const root = seedSignerByName("root");
  const adminHarness = newModernHarness("modern");
  const refused = modernRequest(root, {
    body: modernToolCallBody("1", "jack.admin.invite.create", "{}"),
    headers: [
      ["MCP-Protocol-Version", MODERN],
      ["Mcp-Method", "tools/call"],
      // Wrong on purpose: it names the mcp-name source of a different tool.
      ["Mcp-Name", "jack.admin.invite.list"],
    ],
  });
  const refusedResponse = await adminHarness.handle(refused.request);
  assert.equal(refusedResponse.status, 400);
  const refusedBody = await assertSigned(refusedResponse, adminHarness.serverPub, refused.sig);
  assert.deepEqual(JSON.parse(Buffer.from(refusedBody).toString("utf-8")), {
    jsonrpc: "2.0",
    id: 1,
    error: { code: -32020, message: "Header mismatch: Mcp-Name does not match the body value" },
  });
  assert.equal(adminHarness.seen.calls, 0);

  const inviteList = modernRequest(root, {
    body: modernToolCallBody("1", "jack.admin.invite.list"),
    headers: mirrorsFor("tools/call", "jack.admin.invite.list"),
  });
  const inviteResponse = await adminHarness.handle(inviteList.request);
  assert.equal(inviteResponse.status, 200);
  const inviteBody = await assertSigned(inviteResponse, adminHarness.serverPub, inviteList.sig);
  const parsedInvites = JSON.parse(Buffer.from(inviteBody).toString("utf-8")) as {
    result: { structuredContent: { invites: unknown[] } };
  };
  assert.deepEqual(parsedInvites.result.structuredContent.invites, [], "the refused create never reached the native tool");
});
