#!/usr/bin/env node
// Verifies that the repository itself consistently declares the dual licence
// "MIT OR Apache-2.0": both licence files exist, both SDK manifests carry the
// exact SPDX expression, and no stray licence files are present.
// Two licence files are the CORRECT shape for a dual licence: recipients
// choose one of the two (OR), they are not required to comply with both (AND).
// Usage: node check-own-license.mjs [--root <directory>]
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
let root = resolve(here, "../..");
const rootFlag = args.indexOf("--root");
if (rootFlag !== -1 && args[rootFlag + 1]) root = resolve(args[rootFlag + 1]);

const want = "MIT OR Apache-2.0";
const problems = [];
const check = (ok, file, reason) => {
  if (!ok) problems.push(`${file}: ${reason}`);
};
const read = (p) => readFileSync(join(root, p), "utf8");
const exists = (p) => {
  try {
    readFileSync(join(root, p));
    return true;
  } catch {
    return false;
  }
};

// Rust: exact SPDX expression, no license-file override.
const cargo = exists("rust/Cargo.toml") ? read("rust/Cargo.toml") : null;
check(cargo !== null, "rust/Cargo.toml", "missing");
if (cargo !== null) {
  const m = cargo.match(/^license\s*=\s*"([^"]*)"\s*$/m);
  check(m !== null, "rust/Cargo.toml", 'no license = "..." key');
  if (m) check(m[1] === want, "rust/Cargo.toml", `licence is "${m[1]}", want "${want}"`);
  check(!/^license-file\s*=/m.test(cargo), "rust/Cargo.toml", "license-file must not override the SPDX expression");
}

// TypeScript: exact SPDX expression.
const pkg = exists("ts/package.json") ? JSON.parse(read("ts/package.json")) : null;
check(pkg !== null, "ts/package.json", "missing or invalid JSON");
if (pkg !== null) {
  check(pkg.license === want, "ts/package.json", `licence is "${String(pkg.license)}", want "${want}"`);
}

// Go: go.mod has no licence field by design; the root licence files apply
// to the module, enforced by the file checks below.

// Licence files: exactly LICENSE-APACHE and LICENSE-MIT at the root.
const mitOk = exists("LICENSE-MIT");
const apacheOk = exists("LICENSE-APACHE");
check(mitOk, "LICENSE-MIT", "missing");
check(apacheOk, "LICENSE-APACHE", "missing");
const listed = readdirSync(root).filter((f) => /^LICENSE/i.test(f)).sort();
const expected = ["LICENSE-APACHE", "LICENSE-MIT"];
check(
  JSON.stringify(listed) === JSON.stringify(expected),
  `root licence files (${listed.join(", ") || "none"})`,
  `expected exactly ${expected.join(" and ")}; two files are the dual-licence (OR) shape, a third suggests an accidental extra licence`,
);

// Content spot checks.
if (mitOk) {
  const text = read("LICENSE-MIT");
  check(
    text.includes("MIT License") && text.includes("Permission is hereby granted"),
    "LICENSE-MIT",
    "does not look like the MIT licence text",
  );
}
if (apacheOk) {
  const text = read("LICENSE-APACHE");
  check(
    text.includes("Apache License") && text.includes("Version 2.0, January 2004"),
    "LICENSE-APACHE",
    "does not look like the Apache-2.0 licence text",
  );
}

// README documents the dual licence by linking both files.
if (exists("README.md")) {
  const readme = read("README.md");
  check(
    readme.includes("LICENSE-APACHE") && readme.includes("LICENSE-MIT"),
    "README.md",
    "should document the dual licence by linking LICENSE-APACHE and LICENSE-MIT",
  );
}

if (problems.length > 0) {
  console.error(`dual-licence manifest check FAILED (${problems.length} problem(s)):`);
  for (const p of problems) console.error(`  - ${p}`);
  process.exit(1);
}
console.log(`dual-licence manifest check passed for ${root}`);
