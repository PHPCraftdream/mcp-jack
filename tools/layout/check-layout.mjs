// Layout lint: no code or test file longer than MAX_FILE_LINES physical lines,
// and no folder holding more than MAX_FILES_PER_DIR code or test files
// directly (subfolders are counted on their own). Only code and test files
// count; docs, JSON, TOML, YAML and lock files are ignored.
// The file list comes from git (tracked plus untracked-and-not-ignored), so
// build output and other ignored folders never count.
// Usage: node tools/layout/check-layout.mjs [--root <dir>]
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const MAX_FILE_LINES = 1000;
export const MAX_FILES_PER_DIR = 7;
export const CODE_EXTENSIONS = new Set([
  ".go",
  ".rs",
  ".ts",
  ".tsx",
  ".mts",
  ".cts",
  ".js",
  ".mjs",
  ".cjs",
  ".sh",
  ".py",
]);

export function isCodeFile(filePath) {
  return CODE_EXTENSIONS.has(path.posix.extname(filePath));
}

// Physical lines as `wc -l` would count them, plus a final line without a
// trailing newline. An empty file has zero lines.
export function countLines(content) {
  if (content.length === 0) return 0;
  let newlines = 0;
  for (const byte of content) {
    if (byte === 0x0a) newlines++;
  }
  return content[content.length - 1] === 0x0a ? newlines : newlines + 1;
}

// entries: [{ path, lines }] for code files only, paths with forward slashes.
export function findViolations(entries) {
  const violations = [];
  const perDir = new Map();
  for (const entry of entries) {
    if (entry.lines > MAX_FILE_LINES) {
      violations.push({
        kind: "file-too-long",
        path: entry.path,
        count: entry.lines,
        max: MAX_FILE_LINES,
      });
    }
    const dir = path.posix.dirname(entry.path);
    perDir.set(dir, (perDir.get(dir) ?? 0) + 1);
  }
  for (const [dir, count] of perDir) {
    if (count > MAX_FILES_PER_DIR) {
      violations.push({ kind: "too-many-files", path: dir, count, max: MAX_FILES_PER_DIR });
    }
  }
  return violations.sort(
    (a, b) => (a.kind < b.kind ? -1 : a.kind > b.kind ? 1 : a.path < b.path ? -1 : a.path > b.path ? 1 : 0),
  );
}

export function formatViolation(violation) {
  if (violation.kind === "file-too-long") {
    return `${violation.path}: ${violation.count} lines, limit ${violation.max}; split the file by topic`;
  }
  const where = violation.path === "." ? "(repository root)" : `${violation.path}/`;
  return `${where}: ${violation.count} code files, limit ${violation.max}; move files into subfolders`;
}

export function listFiles(root) {
  const output = execFileSync("git", ["ls-files", "-z", "--cached", "--others", "--exclude-standard"], {
    cwd: root,
    encoding: "utf8",
    maxBuffer: 256 * 1024 * 1024,
  });
  return [...new Set(output.split("\0").filter(Boolean))];
}

export function collectEntries(root, files) {
  const entries = [];
  for (const file of files) {
    if (!isCodeFile(file)) continue;
    const absolute = path.join(root, file);
    // A tracked file deleted in the working tree is not part of the tree.
    if (!existsSync(absolute)) continue;
    entries.push({ path: file, lines: countLines(readFileSync(absolute)) });
  }
  return entries;
}

export function run(root, log = console.log) {
  const entries = collectEntries(root, listFiles(root));
  const violations = findViolations(entries);
  for (const violation of violations) log(formatViolation(violation));
  if (violations.length > 0) {
    log(
      `layout: ${violations.length} violation(s); limits: ${MAX_FILE_LINES} lines per file, ${MAX_FILES_PER_DIR} code files per folder`,
    );
    return 1;
  }
  log(`layout ok: ${entries.length} code files checked`);
  return 0;
}

function main(argv) {
  let root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--root" && i + 1 < argv.length) {
      root = path.resolve(argv[++i]);
    } else {
      console.error("usage: node tools/layout/check-layout.mjs [--root <dir>]");
      return 2;
    }
  }
  return run(root);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = main(process.argv.slice(2));
}
