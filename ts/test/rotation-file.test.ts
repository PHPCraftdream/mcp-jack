import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, linkSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { RotationFileOwner } from "../src/rotation-file.js";
import { RotationError } from "../src/rotation-record.js";

const linux = process.platform === "linux";
const moduleURL = new URL("../src/rotation-file.js", import.meta.url).href;
const code = (expected: string) => (error: unknown): boolean => error instanceof RotationError && error.code === expected;

function directory(): string {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "mcp-jack-rotation-file-")));
  chmodSync(root, 0o700);
  return root;
}

test("private file owner: exclusive unused create, exact CAS, owned reads, clean close", { skip: !linux }, (context) => {
  const root = directory();
  context.after(() => rmSync(root, { recursive: true, force: true }));
  const path = join(root, "state");
  assert.throws(() => RotationFileOwner.open(path), code("rotation_state_unavailable"));
  assert.equal(existsSync(path), false);
  assert.equal(existsSync(path + ".owner"), false);
  RotationFileOwner.initializeUnused(path, Buffer.from("initial public fixture"));
  assert.throws(() => RotationFileOwner.initializeUnused(path, Buffer.from("replacement")), code("rotation_state_unavailable"));
  assert.equal(readFileSync(path, "utf8"), "initial public fixture");
  const owner = RotationFileOwner.open(path);
  context.after(() => { try { owner.close(); } catch { /* Только test-owned cleanup. */ } });
  assert.throws(() => RotationFileOwner.open(path), code("rotation_state_unavailable"));
  assert.throws(() => owner.replace(Buffer.from("wrong"), Buffer.from("next")), code("rotation_state_changed"));
  assert.equal(Buffer.from(owner.read()).toString(), "initial public fixture");
  owner.replace(Buffer.from("initial public fixture"), Buffer.from("next public fixture"));
  const owned = owner.read();
  owned.fill(0);
  assert.equal(Buffer.from(owner.read()).toString(), "next public fixture");
  owner.close();
  owner.close();
  assert.equal(existsSync(path + ".owner"), false);
  const reopened = RotationFileOwner.open(path);
  assert.equal(Buffer.from(reopened.read()).toString(), "next public fixture");
  reopened.close();
});

test("private file owner: fenced/abandoned marker never auto-breaks across processes", { skip: !linux }, (context) => {
  const root = directory();
  context.after(() => rmSync(root, { recursive: true, force: true }));
  const path = join(root, "state");
  RotationFileOwner.initializeUnused(path, Buffer.from("public owner fixture"));
  const owner = RotationFileOwner.open(path);
  const probe = spawnSync(process.execPath, ["--input-type=module", "-e",
    "const {RotationFileOwner}=await import(process.argv[1]); try { RotationFileOwner.open(process.argv[2]); process.exit(2); } catch(error) { process.exit(error.code==='rotation_state_unavailable'?0:1); }",
    moduleURL, path], { timeout: 3000, encoding: "utf8" });
  assert.equal(probe.error, undefined);
  assert.equal(probe.status, 0, probe.stderr);
  owner.close();
  const abandoned = spawnSync(process.execPath, ["--input-type=module", "-e",
    "const {RotationFileOwner}=await import(process.argv[1]); RotationFileOwner.open(process.argv[2]); process.exit(0);",
    moduleURL, path], { timeout: 3000, encoding: "utf8" });
  assert.equal(abandoned.error, undefined);
  assert.equal(abandoned.status, 0, abandoned.stderr);
  assert.equal(existsSync(path + ".owner"), true);
  const before = readFileSync(path);
  assert.throws(() => RotationFileOwner.open(path), code("rotation_state_unavailable"));
  assert.deepEqual(readFileSync(path), before);
  // Отдельная test-owned state: fence не очищает marker или payload.
  const fencedPath = join(root, "fenced");
  RotationFileOwner.initializeUnused(fencedPath, Buffer.from("public fenced fixture"));
  const fenced = RotationFileOwner.open(fencedPath);
  fenced.fence();
  assert.throws(() => fenced.close(), code("rotation_state_unavailable"));
  assert.throws(() => fenced.read(), code("rotation_state_unavailable"));
  assert.equal(existsSync(fencedPath + ".owner"), true);
  assert.equal(readFileSync(fencedPath, "utf8"), "public fenced fixture");
});

test("private file owner rejects aliases, unsafe modes and marker replacement without repair", { skip: !linux }, (context) => {
  const root = directory();
  context.after(() => rmSync(root, { recursive: true, force: true }));
  const target = join(root, "target");
  writeFileSync(target, "public target", { mode: 0o600 });
  const symbolic = join(root, "symbolic");
  symlinkSync(target, symbolic);
  assert.throws(() => RotationFileOwner.open(symbolic), code("rotation_state_unavailable"));
  assert.equal(readFileSync(target, "utf8"), "public target");
  const alias = join(root, "hard");
  linkSync(target, alias);
  assert.throws(() => RotationFileOwner.open(alias), code("rotation_state_unavailable"));
  const unsafe = join(root, "unsafe");
  writeFileSync(unsafe, "public unsafe mode", { mode: 0o644 });
  assert.throws(() => RotationFileOwner.open(unsafe), code("rotation_state_unavailable"));
  const fifo = join(root, "fifo");
  const created = spawnSync("mkfifo", [fifo], { timeout: 3000, encoding: "utf8" });
  assert.equal(created.error, undefined);
  assert.equal(created.status, 0, created.stderr);
  const fifoProbe = spawnSync(process.execPath, ["--input-type=module", "-e",
    "const {RotationFileOwner}=await import(process.argv[1]); try { RotationFileOwner.open(process.argv[2]); process.exit(2); } catch(error) { process.exit(error.code==='rotation_state_unavailable'?0:1); }",
    moduleURL, fifo], { timeout: 3000, encoding: "utf8" });
  assert.equal(fifoProbe.error, undefined, "nonregular path blocked an owned child");
  assert.equal(fifoProbe.status, 0, fifoProbe.stderr);
  const path = join(root, "owned");
  RotationFileOwner.initializeUnused(path, Buffer.from("public intact fixture"));
  const owner = RotationFileOwner.open(path);
  writeFileSync(path + ".owner", "different owner marker", { mode: 0o600 });
  assert.throws(() => owner.replace(Buffer.from("public intact fixture"), Buffer.from("not committed")), code("rotation_state_unknown"));
  assert.throws(() => owner.close(), code("rotation_state_unavailable"));
  assert.equal(readFileSync(path + ".owner", "utf8"), "different owner marker");
  assert.equal(readFileSync(path, "utf8"), "public intact fixture");
});

test("private file owner unsupported platforms fail closed before file creation", { skip: linux }, (context) => {
  const root = directory();
  context.after(() => rmSync(root, { recursive: true, force: true }));
  const path = join(root, "unsupported");
  assert.throws(() => RotationFileOwner.initializeUnused(path, Buffer.from("not created")), code("rotation_state_unavailable"));
  assert.throws(() => RotationFileOwner.open(path), code("rotation_state_unavailable"));
  assert.equal(existsSync(path), false);
  assert.equal(existsSync(path + ".owner"), false);
});
