/** Load tests for the strict fixture loaders: every fixture file in spec/fixtures parses with the expected counts and unique ids. */
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  loadAdminVectors,
  loadDefaultPolicy,
  loadKeyVectors,
  loadKeys,
  loadLoadVectors,
  loadPatternVectors,
  loadRegistry,
  loadRequestVectors,
  loadResponseVectors,
  loadWildcardPolicy,
} from "./fixtures.js";

function assertUnique(ids: readonly string[], what: string): void {
  assert.strictEqual(new Set(ids).size, ids.length, `${what} are not unique`);
}

test("keys.json loads", () => {
  const file = loadKeys();
  assert.ok(file.keys.length >= 15, "expected at least 15 test keys");
  assertUnique(file.keys.map((key) => key.kid), "key kids");
  assert.strictEqual(typeof file.note, "string");
});

test("registry.json loads", () => {
  const registry = loadRegistry();
  assert.ok(registry.keys.length >= 7, "expected at least 7 registry entries");
  assertUnique(registry.keys.map((entry) => entry.kid), "registry kids");
});

test("policy.json loads", () => {
  const policy = loadDefaultPolicy();
  assert.ok(policy.rules.length >= 8, "expected at least 8 default policy rules");
  assert.ok(Number.isInteger(policy.version), "policy version must be an integer");
});

test("policy-wildcard.json loads", () => {
  const policy = loadWildcardPolicy();
  assert.ok(policy.rules.length >= 1, "expected at least 1 wildcard policy rule");
  assert.ok(Number.isInteger(policy.version), "policy version must be an integer");
});

test("request-vectors.json loads", () => {
  const vectors = loadRequestVectors();
  assert.ok(vectors.cases.length >= 79, "expected at least 79 request cases");
  assertUnique(vectors.cases.map((entry) => entry.id), "request case ids");
  assert.ok(Object.keys(vectors.policies).length >= 2, "expected at least 2 named policies");
});

test("admin-vectors.json loads", () => {
  const vectors = loadAdminVectors();
  assert.ok(vectors.cases.length >= 71, "expected at least 71 admin cases");
  assertUnique(vectors.cases.map((entry) => entry.id), "admin case ids");
  const steps = vectors.cases.reduce((sum, entry) => sum + entry.steps.length, 0);
  assert.ok(steps >= 95, "expected at least 95 admin steps in total");
});

test("response-vectors.json loads", () => {
  const vectors = loadResponseVectors();
  assert.ok(vectors.cases.length >= 14, "expected at least 14 response cases");
  assertUnique(vectors.cases.map((entry) => entry.id), "response case ids");
});

test("key-vectors.json loads", () => {
  const vectors = loadKeyVectors();
  assert.ok(vectors.cases.length >= 24, "expected at least 24 key cases");
  assertUnique(vectors.cases.map((entry) => entry.id), "key case ids");
});

test("load-vectors.json loads", () => {
  const vectors = loadLoadVectors();
  assert.ok(vectors.policies.length >= 17, "expected at least 17 policy load cases");
  assert.ok(vectors.registries.length >= 15, "expected at least 15 registry load cases");
  assertUnique(vectors.policies.map((entry) => entry.id), "policy load case ids");
  assertUnique(vectors.registries.map((entry) => entry.id), "registry load case ids");
});

test("pattern-vectors.json loads", () => {
  const vectors = loadPatternVectors();
  assert.ok(vectors.cases.length >= 22, "expected at least 22 pattern cases");
  assertUnique(vectors.cases.map((entry) => entry.id), "pattern case ids");
});
