import { execFileSync } from "node:child_process";
import { copyFile, mkdir, readFile, readdir, stat } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Verifies the packaged Rust .crate from a fresh standalone consumer crate.
// CI-only, same stage discipline as verify-ts.mjs.
//
// The consumer resolves its dependency graph FRESH on Rust 1.85: no product
// lockfile is copied into the consumer, and afterwards the consumer-generated
// Cargo.lock must exist and must differ byte-wise from rust/Cargo.lock —
// proof of independent resolution (Cargo ignores path-dependency lockfiles).
// server-http NOTE: the run with --features server-http drives the REAL packaged JackLayer adapter in-process (HandlerConfig + tower::service_fn inner + a signed client round trip, plus wrong-pin and tampered-body refusals); its supporting crates (ed25519-dalek, getrandom, http, bytes, http-body-util, tower, futures) are harness-only optional deps behind the consumer's own server-http feature, while the SDK dependency itself stays the extracted .crate.

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, "../..");
const rustRoot = path.join(repoRoot, "rust");
const fixtureDir = path.join(scriptDir, "rust");
const scratchRoot = path.join(scriptDir, ".scratch");
const stageArg = process.argv[2];
if (stageArg === undefined || stageArg.trim() === "") {
  throw new Error("usage: node tools/consumer/verify-rust.mjs <stage-directory>");
}
if (process.env.GITHUB_ACTIONS !== "true") throw new Error("Rust consumer verification is restricted to GitHub Actions");
const stageDir = path.resolve(stageArg);
const relativeStage = path.relative(scratchRoot, stageDir);
if (relativeStage === "" || relativeStage === ".." || relativeStage.startsWith(`..${path.sep}`) || path.isAbsolute(relativeStage)) {
  throw new Error("Rust consumer stage directory must be inside tools/consumer/.scratch");
}

const artifact = path.join(stageDir, "mcp-jack-0.1.0.crate");
const inventoryPath = path.join(stageDir, "inventory.json");
const inventory = JSON.parse(await readFile(inventoryPath, "utf8"));
// .cargo_vcs_info.json is cargo's own generated VCS metadata and is the
// only dotfile allowed here.
const allowed = /^(?:Cargo\.toml|Cargo\.lock|Cargo\.toml\.orig|deny\.toml|\.cargo_vcs_info\.json|README\.md|LICENSE-MIT|LICENSE-APACHE|src\/.+|tests\/.+)$/u;
const forbidden = /(?:^|\/)(?:target\/|\.git(?:\/|$)|.*\.tgz$|.*\.crate$)/u;
if (inventory.artifact !== "mcp-jack-0.1.0.crate" || inventory.version !== "0.1.0" || inventory.publish !== false) {
  throw new Error("staged package identity/publish metadata changed");
}
if (!Array.isArray(inventory.members)) throw new Error("staged package inventory is incomplete");
for (const member of inventory.members) {
  if (typeof member !== "string" || !allowed.test(member)) throw new Error(`forbidden staged package member: ${String(member)}`);
  if (forbidden.test(member)) throw new Error(`forbidden staged package member: ${member}`);
}
for (const member of ["Cargo.toml", "src/lib.rs", "README.md", "LICENSE-MIT", "LICENSE-APACHE"]) {
  if (!inventory.members.includes(member)) throw new Error(`missing staged package member: ${member}`);
}
if (!(await stat(artifact)).isFile()) throw new Error("staged package archive is missing");

const vendor = path.join(stageDir, "vendor");
await mkdir(vendor);
execFileSync("tar", ["-xzf", artifact, "-C", vendor], { stdio: "inherit", shell: process.platform === "win32" });
const topEntries = (await readdir(vendor)).filter((name) => name !== ".");
if (topEntries.length !== 1 || topEntries[0] !== "mcp-jack-0.1.0") {
  throw new Error(`crate must extract to a single mcp-jack-0.1.0 top directory, got: ${topEntries.join(", ")}`);
}
const packageRoot = path.join(vendor, "mcp-jack-0.1.0");

async function enumerateFiles(directory, relative = "") {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const entryRelative = relative === "" ? entry.name : `${relative}/${entry.name}`;
    if (entry.isDirectory()) {
      files.push(...(await enumerateFiles(path.join(directory, entry.name), entryRelative)));
    } else if (entry.isFile()) {
      files.push(entryRelative);
    } else {
      throw new Error(`unexpected archive member kind: ${entryRelative}`);
    }
  }
  return files;
}
const extractedMembers = (await enumerateFiles(packageRoot)).sort();
for (const member of extractedMembers) {
  if (!allowed.test(member) || forbidden.test(member)) throw new Error(`forbidden extracted archive member: ${member}`);
}
if (JSON.stringify(extractedMembers) !== JSON.stringify([...inventory.members].sort())) throw new Error("extracted archive members differ from the saved cargo package inventory");

for (const [packagedLicense, rootLicense] of [["LICENSE-MIT", "LICENSE-MIT"], ["LICENSE-APACHE", "LICENSE-APACHE"]]) {
  const [actual, original] = await Promise.all([
    readFile(path.join(packageRoot, packagedLicense)),
    readFile(path.join(repoRoot, rootLicense)),
  ]);
  if (!actual.equals(original)) throw new Error(`${packagedLicense} in the crate differs from the root license bytes`);
}

const packagedManifest = await readFile(path.join(packageRoot, "Cargo.toml"), "utf8");
if (!/^publish\s*=\s*false$/m.test(packagedManifest)) throw new Error("packaged Cargo.toml lost publish = false");
if (!/^version\s*=\s*"0\.1\.0"$/m.test(packagedManifest)) throw new Error('packaged Cargo.toml lost version "0.1.0"');
if (!/^rust-version\s*=\s*"1\.85"$/m.test(packagedManifest)) throw new Error('packaged Cargo.toml lost rust-version "1.85"');
if (!/^license\s*=\s*"MIT OR Apache-2\.0"$/m.test(packagedManifest)) throw new Error('packaged Cargo.toml lost license "MIT OR Apache-2.0"');
for (const feature of ["default", "http", "client-http", "interop"]) {
  if (!new RegExp(`^${feature}\\s*=`, "mu").test(packagedManifest)) throw new Error(`packaged Cargo.toml lost feature ${feature}`);
}

const consumerDir = path.join(stageDir, "consumer");
await mkdir(consumerDir);
for (const name of await readdir(fixtureDir, { recursive: true })) {
  const source = path.join(fixtureDir, name);
  if (!(await stat(source)).isFile()) continue;
  const destination = path.join(consumerDir, name);
  await mkdir(path.dirname(destination), { recursive: true });
  await copyFile(source, destination);
}
try {
  await stat(path.join(consumerDir, "Cargo.lock"));
  throw new Error("consumer fixture must ship without a Cargo.lock (fresh resolution required)");
} catch (error) {
  if (error && typeof error === "object" && error.code !== "ENOENT") throw error;
}

function cargo(args) {
  execFileSync("cargo", args, {
    cwd: consumerDir,
    env: {
      ...process.env,
      CARGO_HOME: path.join(stageDir, "cargo-home"),
      CARGO_TARGET_DIR: path.join(stageDir, "consumer-target"),
    },
    stdio: "inherit",
    shell: process.platform === "win32",
  });
}
// Default features, then each optional feature: every run executes the full
// core smoke plus the feature-gated extras.
cargo(["run"]);
cargo(["run", "--features", "client-http"]);
cargo(["run", "--features", "server-http"]);

const consumerLock = await readFile(path.join(consumerDir, "Cargo.lock"));
const productLock = await readFile(path.join(rustRoot, "Cargo.lock"));
if (!consumerLock.equals(productLock)) {
  console.log(`consumer Cargo.lock: fresh resolution confirmed (${consumerLock.length} bytes vs product ${productLock.length} bytes)`);
} else {
  throw new Error("consumer Cargo.lock is byte-identical to the product lockfile; fresh resolution is not proven");
}
console.log(`Rust consumer verified from mcp-jack-0.1.0.crate (${inventory.members.length} package members)`);
