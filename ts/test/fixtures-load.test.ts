/** Load tests for the strict fixture loaders: every fixture file in spec/fixtures parses with the expected counts and unique ids. */
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  loadAdminVectors,
  loadKeyVectors,
  loadKeys,
  loadLoadVectors,
  loadRegistry,
  loadRequestVectors,
  loadResponseVectors,
  loadStateFileVectors,
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

test("request-vectors.json loads", () => {
  const vectors = loadRequestVectors();
  assert.ok(vectors.cases.length >= 85, "expected at least 85 request cases");
  assertUnique(vectors.cases.map((entry) => entry.id), "request case ids");
});

test("admin-vectors.json loads", () => {
  const vectors = loadAdminVectors();
  assert.ok(vectors.cases.length >= 94, "expected at least 94 admin cases");
  assertUnique(vectors.cases.map((entry) => entry.id), "admin case ids");
  const steps = vectors.cases.reduce((sum, entry) => sum + entry.steps.length, 0);
  assert.ok(steps >= 100, "expected at least 100 admin steps in total");
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
  assert.ok(vectors.registries.length >= 19, "expected at least 19 registry load cases");
  assertUnique(vectors.registries.map((entry) => entry.id), "registry load case ids");
});

test("state-file-vectors.json loads", () => {
  const vectors = loadStateFileVectors();
  assert.ok(vectors.cases.length >= 18, "expected at least 18 state-file cases");
  assertUnique(vectors.cases.map((entry) => entry.id), "state-file case ids");
});
