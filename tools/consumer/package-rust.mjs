import { execFileSync } from "node:child_process";
import { copyFile, mkdir, readFile, readdir, realpath, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Packages the Rust SDK crate (rust/) as a .crate artifact for the standalone
// Rust consumer. CI-only, same stage discipline as package-ts.mjs.
//
// NOTE ON Cargo.lock: `cargo package` auto-includes the crate's Cargo.lock
// because the package defines bins (cargo requirement). This is expected and
// harmless: when a downstream crate depends on mcp-jack as a path/git/registry
// dependency, Cargo IGNORES the dependency's own lockfile and resolves the
// consumer's dependency graph fresh, so the consumer boundary stays real.
// verify-rust.mjs proves this by byte-comparing the consumer-generated
// Cargo.lock against rust/Cargo.lock (they must differ).

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, "../..");
const rustRoot = path.join(repoRoot, "rust");
const scratchRoot = path.join(scriptDir, ".scratch");
const stage = process.argv[2];
function fail(message) {
  throw new Error(`Rust package staging: ${message}`);
}

if (stage === undefined || stage.trim() === "") {
  throw new Error("usage: node tools/consumer/package-rust.mjs <stage-directory>");
}
if (process.env.GITHUB_ACTIONS !== "true") fail("package staging is restricted to GitHub Actions");
const requestedStageDir = path.resolve(stage);
const relativeStage = path.relative(scratchRoot, requestedStageDir);
if (relativeStage === "" || relativeStage === ".." || relativeStage.startsWith(`..${path.sep}`) || path.isAbsolute(relativeStage)) {
  fail("stage directory must be inside tools/consumer/.scratch");
}
if (path.dirname(requestedStageDir) !== scratchRoot) fail("stage directory must be a direct child of tools/consumer/.scratch");
await mkdir(scratchRoot, { recursive: true });
const realRepoRoot = await realpath(repoRoot);
const realScratchRoot = await realpath(scratchRoot);
const scratchRelative = path.relative(realRepoRoot, realScratchRoot);
if (scratchRelative === ".." || scratchRelative.startsWith(`..${path.sep}`) || path.isAbsolute(scratchRelative)) {
  fail("scratch directory resolves outside the repository");
}
// Fresh stage: mkdir (no recursive) fails if the directory already exists.
await mkdir(requestedStageDir);
const stageDir = await realpath(requestedStageDir);
const realStageRelative = path.relative(realScratchRoot, stageDir);
if (realStageRelative === "" || realStageRelative === ".." || realStageRelative.startsWith(`..${path.sep}`) || path.isAbsolute(realStageRelative)) {
  fail("stage directory resolves outside tools/consumer/.scratch");
}

const manifestPath = path.join(rustRoot, "Cargo.toml");
const manifest = await readFile(manifestPath, "utf8");
// Exact raw-manifest assertions: these values are part of the packaged
// boundary contract and must not drift silently.
if (!/^publish\s*=\s*false$/m.test(manifest)) fail("rust/Cargo.toml must keep publish = false");
if (!/^version\s*=\s*"0\.1\.0"$/m.test(manifest)) fail('rust/Cargo.toml version must remain "0.1.0"');
if (!/^rust-version\s*=\s*"1\.85"$/m.test(manifest)) fail('rust/Cargo.toml rust-version must remain "1.85"');
if (!/^license\s*=\s*"MIT OR Apache-2\.0"$/m.test(manifest)) fail('rust/Cargo.toml license must remain "MIT OR Apache-2.0"');

const stageTarget = path.join(stageDir, "target");
const packageEnv = { ...process.env, CARGO_TARGET_DIR: stageTarget };

const listOutput = execFileSync("cargo", ["package", "--list"], {
  cwd: rustRoot,
  env: packageEnv,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "inherit"],
  shell: process.platform === "win32",
});
const members = listOutput
  .split(/\r?\n/u)
  .map((line) => line.trim().replaceAll("\\", "/"))
  .filter((line) => line !== "")
  .sort();

execFileSync("cargo", ["package", "--locked", "--all-features"], {
  cwd: rustRoot,
  env: packageEnv,
  stdio: "inherit",
  shell: process.platform === "win32",
});

const artifactSource = path.join(stageTarget, "package", "mcp-jack-0.1.0.crate");
const artifactPath = path.join(stageDir, "mcp-jack-0.1.0.crate");
if (!(await stat(artifactSource)).isFile()) fail("cargo package did not produce mcp-jack-0.1.0.crate");
await copyFile(artifactSource, artifactPath);

const inventory = {
  artifact: "mcp-jack-0.1.0.crate",
  members,
  version: "0.1.0",
  publish: false,
};
await writeFile(path.join(stageDir, "inventory.json"), `${JSON.stringify(inventory, null, 2)}\n`, "utf8");

// Required members: manifest, lib entrypoint, readme, both licenses, and
// every Rust source file currently under rust/src (recursively, including
// src/bin/**).
const required = ["Cargo.toml", "src/lib.rs", "README.md", "LICENSE-MIT", "LICENSE-APACHE"];
async function repoRustSources(directory, relative = "") {
  const entries = await readdir(path.join(directory, relative), { withFileTypes: true });
  const out = [];
  for (const entry of entries) {
    const rel = relative === "" ? entry.name : `${relative}/${entry.name}`;
    if (entry.isDirectory()) out.push(...(await repoRustSources(directory, rel)));
    else if (entry.isFile() && entry.name.endsWith(".rs")) out.push(`src/${rel}`.replace(/^src\/src\//u, "src/"));
  }
  return out;
}
for (const member of required) {
  if (!members.includes(member)) fail(`cargo package omitted required member: ${member}`);
}
for (const rel of await repoRustSources(path.join(rustRoot, "src"))) {
  if (!members.includes(rel)) fail(`cargo package omitted packaged source file: ${rel}`);
}

// Forbidden members: build output, VCS metadata, foreign archives.
const forbidden = /(?:^|\/)(?:target\/|\.git(?:\/|$)|.*\.tgz$|.*\.crate$)/u;
for (const member of members) {
  if (forbidden.test(member)) fail(`cargo package included a forbidden member: ${member}`);
}

// Allow list: exactly what a source package may contain. Cargo.toml.orig is
// cargo's own backup of a templated manifest and is tolerated when emitted;
// deny.toml is the crate's cargo-deny configuration and belongs in the
// package. Dotfiles (rust/.gitignore) are excluded by cargo itself.
// .cargo_vcs_info.json is cargo's own generated VCS metadata and is the
// only dotfile allowed here.
const allowed = /^(?:Cargo\.toml|Cargo\.lock|Cargo\.toml\.orig|deny\.toml|\.cargo_vcs_info\.json|README\.md|LICENSE-MIT|LICENSE-APACHE|src\/.+|tests\/.+)$/u;
for (const member of members) {
  if (!allowed.test(member)) fail(`cargo package included an unexpected member: ${member}`);
}

console.log(`Rust artifact: mcp-jack-0.1.0.crate`);
console.log(`Rust inventory: inventory.json (${members.length} members)`);
