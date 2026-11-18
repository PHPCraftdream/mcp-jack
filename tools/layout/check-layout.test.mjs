import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, describe, test } from "node:test";
import { fileURLToPath } from "node:url";

import {
  countLines,
  findViolations,
  formatViolation,
  isCodeFile,
  MAX_FILE_LINES,
  MAX_FILES_PER_DIR,
} from "./check-layout.mjs";

const SCRIPT = path.join(path.dirname(fileURLToPath(import.meta.url)), "check-layout.mjs");

describe("isCodeFile", () => {
  test("code and test extensions count", () => {
    for (const name of [
      "a.go",
      "a_test.go",
      "a.rs",
      "a.ts",
      "a.d.ts",
      "a.tsx",
      "a.mts",
      "a.cts",
      "a.js",
      "a.mjs",
      "a.cjs",
      "a.sh",
      "a.py",
      "deep/dir/a.test.mjs",
    ]) {
      assert.equal(isCodeFile(name), true, name);
    }
  });

  test("docs, data and config do not count", () => {
    for (const name of ["a.md", "a.json", "a.toml", "a.yml", "a.txt", "Cargo.lock", "go.sum", "go.mod", ".gitignore", "LICENSE-MIT", "a"]) {
      assert.equal(isCodeFile(name), false, name);
    }
  });
});

describe("countLines", () => {
  test("matches wc -l plus an unterminated last line", () => {
    const cases = [
      ["", 0],
      ["a", 1],
      ["a\n", 1],
      ["a\nb", 2],
      ["a\nb\n", 2],
      ["\n\n", 2],
      ["a\r\nb\r\n", 2],
    ];
    for (const [text, want] of cases) {
      assert.equal(countLines(Buffer.from(text)), want, JSON.stringify(text));
    }
  });
});

describe("findViolations", () => {
  test("the limits themselves are allowed", () => {
    const entries = [{ path: "a/big.go", lines: MAX_FILE_LINES }];
    for (let i = 0; i < MAX_FILES_PER_DIR - 1; i++) entries.push({ path: `a/f${i}.go`, lines: 1 });
    assert.deepEqual(findViolations(entries), []);
  });

  test("one line over the limit is reported", () => {
    const got = findViolations([{ path: "a/big.go", lines: MAX_FILE_LINES + 1 }]);
    assert.deepEqual(got, [{ kind: "file-too-long", path: "a/big.go", count: MAX_FILE_LINES + 1, max: MAX_FILE_LINES }]);
  });

  test("one file over the folder limit is reported once for the folder", () => {
    const entries = [];
    for (let i = 0; i <= MAX_FILES_PER_DIR; i++) entries.push({ path: `a/b/f${i}.rs`, lines: 1 });
    assert.deepEqual(findViolations(entries), [
      { kind: "too-many-files", path: "a/b", count: MAX_FILES_PER_DIR + 1, max: MAX_FILES_PER_DIR },
    ]);
  });

  test("subfolders are counted on their own", () => {
    const entries = [];
    for (let i = 0; i < MAX_FILES_PER_DIR; i++) {
      entries.push({ path: `a/f${i}.ts`, lines: 1 });
      entries.push({ path: `a/sub/f${i}.ts`, lines: 1 });
    }
    assert.deepEqual(findViolations(entries), []);
  });

  test("the repository root is a folder too", () => {
    const entries = [];
    for (let i = 0; i <= MAX_FILES_PER_DIR; i++) entries.push({ path: `f${i}.go`, lines: 1 });
    assert.deepEqual(findViolations(entries), [
      { kind: "too-many-files", path: ".", count: MAX_FILES_PER_DIR + 1, max: MAX_FILES_PER_DIR },
    ]);
  });

  test("output order is stable: kind, then path", () => {
    const entries = [
      { path: "z/big.go", lines: MAX_FILE_LINES + 5 },
      { path: "a/big.go", lines: MAX_FILE_LINES + 5 },
    ];
    assert.deepEqual(
      findViolations(entries).map((v) => v.path),
      ["a/big.go", "z/big.go"],
    );
  });
});

describe("formatViolation", () => {
  test("names the path, the count and the limit", () => {
    assert.equal(
      formatViolation({ kind: "file-too-long", path: "a/x.go", count: 1200, max: 1000 }),
      "a/x.go: 1200 lines, limit 1000; split the file by topic",
    );
    assert.equal(
      formatViolation({ kind: "too-many-files", path: "a/b", count: 9, max: 7 }),
      "a/b/: 9 code files, limit 7; move files into subfolders",
    );
    assert.equal(
      formatViolation({ kind: "too-many-files", path: ".", count: 9, max: 7 }),
      "(repository root): 9 code files, limit 7; move files into subfolders",
    );
  });
});

describe("command line on a real git work tree", () => {
  const roots = [];
  after(() => {
    for (const root of roots) rmSync(root, { recursive: true, force: true });
  });

  function makeRepo(files) {
    const root = mkdtempSync(path.join(os.tmpdir(), "layout-lint-"));
    roots.push(root);
    const init = spawnSync("git", ["init", "-q"], { cwd: root, encoding: "utf8" });
    assert.equal(init.status, 0, init.stderr);
    for (const [name, text] of Object.entries(files)) {
      const target = path.join(root, name);
      mkdirSync(path.dirname(target), { recursive: true });
      writeFileSync(target, text);
    }
    return root;
  }

  function lint(root) {
    return spawnSync(process.execPath, [SCRIPT, "--root", root], { encoding: "utf8" });
  }

  const lines = (n) => "x\n".repeat(n);

  test("a clean tree passes", () => {
    const root = makeRepo({ "a/one.go": lines(MAX_FILE_LINES), "docs/big.md": lines(5000) });
    const result = lint(root);
    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.match(result.stdout, /layout ok: 1 code files checked/);
  });

  test("a long file and a crowded folder fail with both messages", () => {
    const files = { "long/a.rs": lines(MAX_FILE_LINES + 1) };
    for (let i = 0; i <= MAX_FILES_PER_DIR; i++) files[`crowd/f${i}.ts`] = lines(1);
    const result = lint(makeRepo(files));
    assert.equal(result.status, 1, result.stdout + result.stderr);
    assert.match(result.stdout, /crowd\/: 8 code files, limit 7/);
    assert.match(result.stdout, /long\/a\.rs: 1001 lines, limit 1000/);
    assert.match(result.stdout, /layout: 2 violation\(s\)/);
  });

  test("git-ignored folders do not count", () => {
    const files = { ".gitignore": "build/\n" };
    for (let i = 0; i <= MAX_FILES_PER_DIR; i++) files[`build/f${i}.js`] = lines(2000);
    const result = lint(makeRepo(files));
    assert.equal(result.status, 0, result.stdout + result.stderr);
  });

  test("a staged file deleted from the work tree does not count", () => {
    const files = {};
    for (let i = 0; i <= MAX_FILES_PER_DIR; i++) files[`pkg/f${i}.py`] = lines(1);
    const root = makeRepo(files);
    const add = spawnSync("git", ["add", "."], { cwd: root, encoding: "utf8" });
    assert.equal(add.status, 0, add.stderr);
    unlinkSync(path.join(root, "pkg", "f0.py"));
    const result = lint(root);
    assert.equal(result.status, 0, result.stdout + result.stderr);
  });

  test("an unknown argument is a usage error", () => {
    const result = spawnSync(process.execPath, [SCRIPT, "--bogus"], { encoding: "utf8" });
    assert.equal(result.status, 2);
    assert.match(result.stderr, /usage:/);
  });
});
