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
function stateTextFor(document: JsonValue): string {
  const obj = document as Record<string, JsonValue>;
  const { aud: _aud, ...state } = obj;
  return JSON.stringify({ ...state, invites: [] });
}

test("load-vectors registries: every case through the FileState loader", (t) => {
  const dir = tempDir(t);
  const path = join(dir, "state.json");
  for (const c of loadLoadVectors().registries) {
    writeFileSync(path, stateTextFor(c.document));
    if (c.expect === "valid") {
      const store = openFileState(path);
      for (const k of store.view().keys) {
        assert.ok(k.kind === "human" || k.kind === "agent", `${c.id}: loaded kind ${String(k.kind)}`);
      }
    } else {
      assert.throws(() => openFileState(path), (err) => err instanceof StateCorruptError, `${c.id}: expected invalid`);
    }
  }
});

test("load-vectors valid-kind-omitted: omitted kind loads and persists as human", (t) => {
  const dir = tempDir(t);
  const path = join(dir, "state.json");
  const c = loadLoadVectors().registries.find((x) => x.id === "valid-kind-omitted");
  assert.ok(c, "valid-kind-omitted case missing from load-vectors.json");
  assert.equal(c.expect, "valid");
  writeFileSync(path, stateTextFor(c.document));
  const store = openFileState(path);
  for (const k of store.view().keys) {
    assert.equal(k.kind, "human");
  }
  // Write-back: a no-op update rewrites the file from memory, so the defaulted
  // kind must persist as "human", never as null.
  store.update(() => {});
  const text = readFileSync(path, "utf8");
  assert.ok(text.includes('"kind": "human"'), "written-back kind must be human");
  assert.ok(!text.includes('"kind": null'), "no null kind after write-back");
});
