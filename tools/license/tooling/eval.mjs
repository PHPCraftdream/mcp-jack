#!/usr/bin/env node
// SPDX policy decision for npm dependency licence metadata collected by the
// checker. Expressions are parsed with the pinned parser (invalid syntax and
// unknown SPDX identifiers fail) and then satisfied against the allowlist:
// OR passes when one branch is allowed, AND requires every branch.
// Usage: node eval.mjs <checker-json> <allowlist-file>
import { readFileSync } from "node:fs";
import spdxParse from "spdx-expression-parse";
import spdxSatisfies from "spdx-satisfies";
import spdxLicenseIds from "spdx-license-ids";

const [jsonPath, policyPath] = process.argv.slice(2);
let allowlist;
try {
  allowlist = readFileSync(policyPath, "utf8")
    .split(/\r?\n/)
    .map((line) => line.replace(/#.*$/, "").trim())
    .filter(Boolean);
} catch (err) {
  console.error(`could not read allowlist ${policyPath}: ${err.message}`);
  process.exit(2);
}

// The allowlist must be single SPDX licence identifiers: satisfies() checks
// each identifier of an expression against this set.
for (const entry of allowlist) {
  try {
    const parsed = spdxParse(entry);
    if (parsed.left || parsed.right) throw new Error("must be a single licence identifier");
  } catch (err) {
    console.error(`allowlist entry "${entry}" is invalid: ${err.message}`);
    process.exit(2);
  }
}

let data;
try {
  data = JSON.parse(readFileSync(jsonPath, "utf8"));
} catch (err) {
  console.error(`could not read checker output ${jsonPath}: ${err.message}`);
  process.exit(2);
}

const problems = [];
const knownIdentifier = (id) => id.startsWith("LicenseRef-") || spdxLicenseIds.includes(id);

for (const [name, info] of Object.entries(data)) {
  const licence = info?.licenses;
  if (typeof licence !== "string") {
    problems.push(`${name}: licence metadata is not a single string (arrays are ambiguous): ${JSON.stringify(licence)}`);
    continue;
  }
  if (licence === "UNKNOWN") {
    problems.push(`${name}: no licence could be determined`);
    continue;
  }
  if (licence === "UNLICENSED") {
    problems.push(`${name}: declared UNLICENSED`);
    continue;
  }
  if (licence.endsWith("*")) {
    problems.push(`${name}: "${licence}" was guessed from a licence file, not declared`);
    continue;
  }
  let parsed;
  try {
    parsed = spdxParse(licence);
  } catch (err) {
    problems.push(`${name}: "${licence}" is not a valid SPDX expression (${err.message})`);
    continue;
  }
  const identifiers = [];
  const walk = (node) => {
    if (node.license) identifiers.push(node.license);
    if (node.left) walk(node.left);
    if (node.right) walk(node.right);
  };
  walk(parsed);
  for (const id of identifiers) {
    if (!knownIdentifier(id)) problems.push(`${name}: unknown SPDX identifier "${id}"`);
  }
  if (!spdxSatisfies(licence, allowlist)) {
    problems.push(`${name}: "${licence}" is not satisfied by the allowlist (${allowlist.join(", ")})`);
  }
}

for (const problem of problems) console.error(`licence policy: ${problem}`);
if (problems.length > 0) {
  console.error(`licence policy FAILED for ${problems.length} of ${Object.keys(data).length} packages`);
  process.exit(1);
}
console.log(`licence policy satisfied for ${Object.keys(data).length} packages`);
