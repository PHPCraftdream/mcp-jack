/** Conformance: every load-vectors.json registries case through the strict FileState loader. */
import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openFileState, StateCorruptError } from "../src/server/state-file.js";
import { loadLoadVectors, type JsonValue } from "./fixtures.js";

/** New temp directory cleaned up when the test ends. */
function tempDir(t: { after(fn: () => void): unknown }): string {
  const dir = mkdtempSync(join(tmpdir(), "mcp-jack-load-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

/**
 * Mapping: a registry document is {version, aud, keys}; the state document is
 * {version, keys, invites}. Feed the case's version and keys verbatim (so
 * document- and entry-level mutations survive the mapping), drop aud — the
 * state file carries no aud — and keep invites empty.
 */
function assertObject(value: unknown, message: string): asserts value is Record<string, unknown> {
  assert.ok(typeof value === "object" && value !== null && !Array.isArray(value), message);
}

function stateTextFor(document: JsonValue): string {
  assertObject(document, "registry document must be an object");
  const { aud: _aud, ...state } = document;
  return JSON.stringify({ ...state, invites: [] });
}

/**
 * The LITERAL per-entry admin expectation of a fixture document: kid -> the
 * document's own admin member under the spec default (absent is false).
 * Expectations follow each entry as written, never the case name.
 */
function expectedAdminByKid(document: JsonValue): ReadonlyMap<string, boolean> {
  assertObject(document, "registry document must be an object");
  assert.ok(Array.isArray(document.keys), "registry document keys must be an array");
  const keys: unknown[] = document.keys;
  const out = new Map<string, boolean>();
  for (const value of keys) {
    assertObject(value, "registry key entry must be an object");
    assert.ok(typeof value.kid === "string", "registry key kid must be a string");
    assert.ok(!Object.hasOwn(value, "admin") || typeof value.admin === "boolean", "registry key admin must be absent or a boolean");
    assert.ok(!out.has(value.kid), `duplicate registry key kid ${value.kid}`);
    out.set(value.kid, value.admin === true);
  }
  assert.equal(out.size, keys.length, "registry key kids must be unique");
  return out;
}

test("load-vectors registries: every case through the FileState loader", (t) => {
  const dir = tempDir(t);
  const path = join(dir, "state.json");
  for (const c of loadLoadVectors().registries) {
    writeFileSync(path, stateTextFor(c.document));
    if (c.expect === "valid") {
      const store = openFileState(path);
      // Per literal entry: the loaded admin member must match the document's
      // own member for THAT kid — present-and-true vs absent — never a
      // case-name-wide assumption.
      const expected = expectedAdminByKid(c.document);
      const loadedKeys = store.view().keys;
      assert.equal(loadedKeys.length, expected.size, `${c.id}: loaded key count`);
      assert.deepEqual(new Set(loadedKeys.map((key) => key.kid)), new Set(expected.keys()), `${c.id}: loaded kid set`);
      for (const k of loadedKeys) {
        const want = expected.get(k.kid);
        assert.ok(want !== undefined, `${c.id}: loaded kid ${k.kid} is not in the fixture document`);
        assert.equal(k.admin === true, want, `${c.id}: admin of ${k.kid}`);
        if (want) {
          assert.equal(k.admin, true, `${c.id}: admin member of ${k.kid} must be true`);
        } else {
          assert.equal(k.admin, undefined, `${c.id}: admin member of ${k.kid} must stay absent`);
        }
      }
    } else {
      const before = readFileSync(path);
      assert.throws(() => openFileState(path), (err) => err instanceof StateCorruptError, `${c.id}: expected invalid`);
      // Legacy rejection MUST name the offending member (spec 02 section 1).
      if (c.id === "invalid-legacy-kind" || c.id === "invalid-legacy-scopes") {
        const member = c.id === "invalid-legacy-kind" ? "kind" : "scopes";
        let message = "";
        try {
          openFileState(path);
        } catch (err) {
          message = err instanceof Error ? err.message : "";
        }
        assert.ok(message.includes(member), `${c.id}: error must name "${member}", got ${JSON.stringify(message)}`);
      }
      assert.deepEqual(readFileSync(path), before, `${c.id}: rejected input bytes must remain unchanged`);
    }
  }
});

test("load-vectors valid-admin-omitted: each entry loads and persists with its literal admin", (t) => {
  const dir = tempDir(t);
  const path = join(dir, "state.json");
  const c = loadLoadVectors().registries.find((x) => x.id === "valid-admin-omitted");
  assert.ok(c, "valid-admin-omitted case missing from load-vectors.json");
  assert.equal(c.expect, "valid");
  writeFileSync(path, stateTextFor(c.document));
  const expected = expectedAdminByKid(c.document);
  const store = openFileState(path);
  const loadedKeys = store.view().keys;
  assert.equal(loadedKeys.length, expected.size, "loaded key count");
  assert.deepEqual(new Set(loadedKeys.map((key) => key.kid)), new Set(expected.keys()), "loaded kid set");
  for (const k of loadedKeys) {
    const want = expected.get(k.kid);
    assert.ok(want !== undefined, `loaded kid ${k.kid} is not in the fixture document`);
    assert.equal(k.admin === true, want, `loaded admin of ${k.kid}`);
    if (!want) {
      assert.equal(k.admin, undefined, `admin member of ${k.kid} must stay absent`);
    }
  }
  // Write-back: a no-op update rewrites the file from memory. Each entry must
  // persist ITS OWN literal admin — true where the document carries it, false
  // where it does not — and no legacy kind/scopes member may appear.
  store.update(() => {});
  const text = readFileSync(path, "utf8");
  const rewritten: unknown = JSON.parse(text);
  assertObject(rewritten, "rewritten state document must be an object");
  assert.ok(Array.isArray(rewritten.keys), "rewritten state keys must be an array");
  const writtenKeys: unknown[] = rewritten.keys;
  assert.equal(writtenKeys.length, expected.size, "written-back key count");
  const writtenKids = new Set<string>();
  for (const value of writtenKeys) {
    assertObject(value, "written-back key entry must be an object");
    assert.ok(typeof value.kid === "string", "written-back key kid must be a string");
    assert.ok(Object.hasOwn(value, "admin") && typeof value.admin === "boolean", "written-back key admin must be a boolean");
    const want = expected.get(value.kid);
    assert.ok(want !== undefined, `written-back kid ${value.kid} is not in the fixture document`);
    assert.ok(!writtenKids.has(value.kid), `duplicate written-back kid ${value.kid}`);
    writtenKids.add(value.kid);
    assert.equal(value.admin, want, `written-back admin of ${value.kid}`);
  }
  assert.deepEqual(writtenKids, new Set(expected.keys()), "written-back kid set");
  assert.ok(!/"kind"\s*:/.test(text), "no kind member after write-back");
  assert.ok(!/"scopes"\s*:/.test(text), "no scopes member after write-back");
});
