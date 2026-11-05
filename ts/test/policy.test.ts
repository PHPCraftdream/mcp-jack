/** Conformance: policy parsing (load vectors) and first-match-wins evaluation, porting policy_test.go. */
import assert from "node:assert/strict";
import { test } from "node:test";
import { parsePolicy, PolicyError, type Decision } from "../src/server/policy.js";
import { loadDefaultPolicy, loadLoadVectors, loadWildcardPolicy } from "./fixtures.js";

/** Re-derive the whole Decision as one deepStrictEqual so scope null vs "" cannot slip through. */
function expectDecision(
  policy: ReturnType<typeof parsePolicy>,
  method: string,
  tool: string | undefined,
  expected: Decision,
  label: string,
): void {
  assert.deepStrictEqual(
    { allowed: policy.evaluate(method, tool).allowed, scope: policy.evaluate(method, tool).scope },
    { allowed: expected.allowed, scope: expected.scope },
    label,
  );
}

// TestPolicyLoadVectors: every policies case of load-vectors.json through the TS parser.
test("load-vectors policies: every case", () => {
  const cases = loadLoadVectors().policies;
  assert.ok(cases.length > 0, "policies cases must be non-empty");
  for (const c of cases) {
    const run = () => parsePolicy(JSON.stringify(c.document));
    if (c.expect === "valid") {
      assert.doesNotThrow(run, `case ${c.id}`);
    } else {
      assert.throws(
        run,
        (err: unknown) => err instanceof PolicyError && err.reason === c.reason,
        `case ${c.id}`,
      );
    }
  }
});

// TestPolicyEvaluate against policy.json: first match wins, deny beats a later glob, no rule = deny.
test("policy.json evaluation (Go TestPolicyEvaluate)", () => {
  const policy = parsePolicy(JSON.stringify(loadDefaultPolicy()));
  expectDecision(policy, "ping", undefined, { allowed: true, scope: null }, "ping");
  expectDecision(policy, "tools/list", undefined, { allowed: true, scope: null }, "tools/list");
  // notifications/* glob covers the whole method name.
  expectDecision(policy, "notifications/initialized", undefined, { allowed: true, scope: null }, "notifications/initialized");
  // svc.* matches any svc.<rest> tool.
  expectDecision(policy, "tools/call", "svc.status", { allowed: true, scope: "read" }, "tools/call svc.status");
  // * crosses dots: svc.logs.query still matches svc.*.
  expectDecision(policy, "tools/call", "svc.logs.query", { allowed: true, scope: "read" }, "tools/call svc.logs.query");
  // Specific rule appears before svc.*; first match wins so it takes config:write.
  expectDecision(policy, "tools/call", "svc.config.set", { allowed: true, scope: "config:write" }, "tools/call svc.config.set");
  expectDecision(policy, "tools/call", "svc.reload", { allowed: true, scope: "lifecycle" }, "tools/call svc.reload");
  expectDecision(policy, "tools/call", "svc.restart", { allowed: true, scope: "lifecycle" }, "tools/call svc.restart");
  // Deny rule sits before svc.*; deny beats the later allow glob.
  expectDecision(policy, "tools/call", "svc.danger.wipe", { allowed: false, scope: null }, "tools/call svc.danger.wipe");
  // No rule names other.* — default deny.
  expectDecision(policy, "tools/call", "other.tool", { allowed: false, scope: null }, "tools/call other.tool");
  expectDecision(policy, "resources/read", undefined, { allowed: false, scope: null }, "resources/read");
  // Every tools/call rule carries a tool pattern; no tool name means no rule matches.
  expectDecision(policy, "tools/call", undefined, { allowed: false, scope: null }, "tools/call without tool");
});

// policy-wildcard.json: one tool-less tools/call allow-all rule with scope null.
test("policy-wildcard.json evaluation", () => {
  const policy = parsePolicy(JSON.stringify(loadWildcardPolicy()));
  expectDecision(policy, "tools/call", "other.tool", { allowed: true, scope: null }, "wildcard other.tool");
  // A rule without a tool pattern matches any tools/call, including one without a tool name.
  expectDecision(policy, "tools/call", undefined, { allowed: true, scope: null }, "wildcard no tool");
  // The wildcard policy only opens tools/call; other methods stay denied.
  expectDecision(policy, "ping", undefined, { allowed: false, scope: null }, "wildcard ping");
  // At the POLICY level the tool-less rule matches even jack.* names; the verifier
  // never asks the policy about jack.* tools — this asserts Policy alone.
  expectDecision(policy, "tools/call", "jack.whoami", { allowed: true, scope: null }, "wildcard jack.whoami");
});

// Pattern semantics observed THROUGH evaluation only (matchPattern has its own vectors in syntax.test.ts).
test("pattern behavior in evaluation", () => {
  const policy = parsePolicy(JSON.stringify(loadDefaultPolicy()));
  // * matches any run of characters including slashes.
  expectDecision(policy, "notifications/foo/bar", undefined, { allowed: true, scope: null }, "notifications/foo/bar");
  // notifications/* is a prefix glob; notificationsX does not match.
  expectDecision(policy, "notificationsX/initialized", undefined, { allowed: false, scope: null }, "notificationsX/initialized");
  // svc.danger.* needs the dot; bare svc.danger falls through to svc.* (read).
  expectDecision(policy, "tools/call", "svc.danger", { allowed: true, scope: "read" }, "tools/call svc.danger");
  // svc.* requires the literal dot; svcx.status matches nothing.
  expectDecision(policy, "tools/call", "svcx.status", { allowed: false, scope: null }, "tools/call svcx.status");
});

// Documents that the JSON fixture loader cannot carry (it parses first): raw text only.
test("missing scope vs null scope (raw JSON text)", () => {
  // A rule without a scope field at all is a load error.
  assert.throws(
    () => parsePolicy('{"version":1,"rules":[{"match":{"method":"ping"}}]}'),
    (err: unknown) => err instanceof PolicyError && err.reason === "missing_scope",
    "missing scope",
  );
  // scope: null parses and means "any authenticated key".
  const policy = parsePolicy('{"version":1,"rules":[{"match":{"method":"ping"},"scope":null}]}');
  expectDecision(policy, "ping", undefined, { allowed: true, scope: null }, "null scope ping");
});

// JSON.parse keeps the last duplicate key; the loader does not detect duplicates (spec README Q11).
test("duplicate object keys keep the last (spec README Q11)", () => {
  const policy = parsePolicy(
    '{"version":1,"rules":[{"match":{"method":"ping","method":"tools/list"},"scope":null}]}',
  );
  // The surviving "method" is tools/list, so ping matches nothing.
  expectDecision(policy, "ping", undefined, { allowed: false, scope: null }, "duplicate key ping");
  expectDecision(policy, "tools/list", undefined, { allowed: true, scope: null }, "duplicate key tools/list");
});

// A PRESENT effect must be exactly "allow" or "deny"; explicit null is neither
// and is rejected (spec 02 section 3 — Go and the reference verifier treat
// null as absent: reported divergence). An ABSENT effect defaults to allow.
test("explicit effect must be allow or deny; scope shape errors", () => {
  assert.throws(
    () => parsePolicy('{"version":1,"rules":[{"match":{"method":"ping"},"scope":null,"effect":null}]}'),
    (err: unknown) => err instanceof PolicyError && err.reason === "effect",
    "effect null",
  );
  // Positive control: an explicit "allow" still parses and evaluates.
  const explicitAllow = parsePolicy('{"version":1,"rules":[{"match":{"method":"ping"},"scope":null,"effect":"allow"}]}');
  expectDecision(explicitAllow, "ping", undefined, { allowed: true, scope: null }, "explicit allow");
  assert.throws(
    () => parsePolicy('{"version":1,"rules":[{"match":{"method":"ping"},"scope":5}]}'),
    (err: unknown) => err instanceof PolicyError && err.reason === "malformed_scope",
    "scope 5",
  );
  assert.throws(
    () => parsePolicy('{"version":1,"rules":[{"match":{"method":"ping","tool":null}}]}'),
    (err: unknown) => err instanceof PolicyError && err.reason === "tool",
    "tool null",
  );
  assert.throws(
    () => parsePolicy('{"version":1,"rules":[{"match":{"method":"ping"},"scope":null,"effect":"permit"}]}'),
    (err: unknown) => err instanceof PolicyError && err.reason === "effect",
    "effect permit",
  );
  // Deny + scope present at all — even null — is a contradiction.
  assert.throws(
    () => parsePolicy('{"version":1,"rules":[{"match":{"method":"ping"},"scope":null,"effect":"deny"}]}'),
    (err: unknown) => err instanceof PolicyError && err.reason === "scope_with_deny",
    "scope with deny",
  );
});

// Uint8Array input is accepted; invalid UTF-8 rejects the whole document (Go would replace the byte).
test("Uint8Array input and strict UTF-8", () => {
  assert.doesNotThrow(
    () => parsePolicy(new TextEncoder().encode('{"version":1,"rules":[]}')),
    "valid UTF-8 bytes",
  );
  // 0xff is not valid UTF-8; the fatal decoder turns it into a "document" error.
  assert.throws(
    () => parsePolicy(new Uint8Array([0x7b, 0xff, 0x7d])),
    (err: unknown) => err instanceof PolicyError && err.reason === "document",
    "invalid UTF-8 byte",
  );
});
