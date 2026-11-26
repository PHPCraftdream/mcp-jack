import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

test("SDK identity versions match the package manifest", async () => {
  // Runs compiled from dist-test/test, so the manifest is two levels up.
  const manifest = JSON.parse(await readFile(join(dirname(fileURLToPath(import.meta.url)), "../../package.json"), "utf8")) as {
    name: string;
    version: string;
  };
  assert.ok(manifest.version.length > 0);
  const { JACK_SERVER_INFO } = await import("../src/modern/server.js");
  const { JACK_CLIENT_INFO } = await import("../src/client/modern.js");
  assert.strictEqual(JACK_SERVER_INFO.name, manifest.name);
  assert.strictEqual(JACK_SERVER_INFO.version, manifest.version);
  assert.strictEqual(JACK_CLIENT_INFO.name, manifest.name);
  assert.strictEqual(JACK_CLIENT_INFO.version, manifest.version);
});
