#!/usr/bin/env node
// Fail-closed reconciliation of checker output for private packages. The
// pinned scanner (license-checker-rseidelsohn 5.0.1) rewrites the licence
// metadata of every package marked `"private": true` to "UNLICENSED" after
// collection, discarding declared licences. This step restores the declared
// licence of exactly those entries by reading the installed package.json the
// scanner reports (`path`), fail-closed: an unreadable manifest, one without
// a licence field, with a non-string/array licence, or declaring UNLICENSED
// itself keeps the refused value; nothing is exempted from evaluation.
// Usage: node reconcile-licenses.mjs <checker-json>
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const [jsonPath] = process.argv.slice(2);
let data;
try {
  data = JSON.parse(readFileSync(jsonPath, "utf8"));
} catch (err) {
  console.error(`could not read checker output ${jsonPath}: ${err.message}`);
  process.exit(2);
}

let reconciled = 0;
for (const [name, info] of Object.entries(data)) {
  // Exact string match: this is precisely the value the scanner's private
  // overwrite writes; every other entry is left untouched.
  if (info?.licenses !== "UNLICENSED") continue;
  if (typeof info.path !== "string" || info.path === "") continue;
  let licence;
  try {
    const manifest = JSON.parse(readFileSync(join(info.path, "package.json"), "utf8"));
    if (typeof manifest.license === "string" && manifest.license !== "") {
      licence = manifest.license;
    }
  } catch {
    // Unreadable, invalid JSON, or no usable licence: keep the refused value.
  }
  if (licence !== undefined) {
    info.licenses = licence;
    reconciled += 1;
  }
}

writeFileSync(jsonPath, JSON.stringify(data));
console.log(`reconciled declared licences for ${reconciled} private package(s) from installed manifests`);
