import { execFileSync } from "node:child_process";
import { copyFile, mkdir, readFile, readdir, realpath, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Packages the Go SDK module (root package + client/ + server/ + userkey/ +
// spec/) plus the exact root licence texts (LICENSE-MIT, LICENSE-APACHE) as
// a staged MODULE SNAPSHOT for the standalone Go consumer.
// CI-only. Stage discipline here matches package-rust.mjs/package-ts.mjs:
// argv-literal trust plus scratch containment, and it additionally re-checks
// containment after realpath canonicalization of the repo root, scratch root,
// and stage directory (scratch-inside-repo + stage-inside-scratch on real
// paths). package-rust.mjs/package-ts.mjs perform the same realpath pass;
// CI passes fixed literal paths, so the stricter argv containment here is
// a superset, not a divergence.
//
// NOTE ON RESOLUTION: there is no archive step. The staged module snapshot at
// <stage>/module IS the module artifact; the consumer's go.mod documents the
// resolution with a replace directive pointing at the snapshot
// (`replace github.com/PHPCraftdream/mcp-jack => ../module`), never at the
// repo checkout.
// Корневой replacement не требует checksum, но внешние зависимости требуют
// точных reviewed go.mod/go.sum. Оба файла входят в staged snapshot.

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, "../..");
const scratchRoot = path.join(scriptDir, ".scratch");
const stage = process.argv[2];
function fail(message) {
  throw new Error(`Go package staging: ${message}`);
}

if (stage === undefined || stage.trim() === "") {
  throw new Error("usage: node tools/consumer/package-go.mjs <stage-directory>");
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
if (scratchRelative === "" || scratchRelative.startsWith(`..${path.sep}`) || path.isAbsolute(scratchRelative)) {
  fail("scratch directory must be inside the repository");
}
// Fresh stage: mkdir (no recursive) fails if the directory already exists.
await mkdir(requestedStageDir);
const stageDir = await realpath(requestedStageDir);
const realStageRelative = path.relative(realScratchRoot, stageDir);
if (realStageRelative === "" || realStageRelative === ".." || realStageRelative.startsWith(`..${path.sep}`) || path.isAbsolute(realStageRelative)) {
  fail("stage directory resolves outside tools/consumer/.scratch");
}

const goModPath = path.join(repoRoot, "go.mod");
const goMod = await readFile(goModPath, "utf8");
// Exact raw-manifest assertions: these values are part of the packaged
// boundary contract and must not drift silently.
if (!/^module github\.com\/PHPCraftdream\/mcp-jack$/mu.test(goMod)) {
  fail('go.mod module line must remain exactly "module github.com/PHPCraftdream/mcp-jack"');
}
if (!/^go 1\.25\.0$/mu.test(goMod)) fail('go.mod must declare the approved "go 1.25.0" floor');

// Enumerate tracked files and keep ONLY the module scope: root-level *.go +
// go.mod + client/*.go + client/rotation/*.go + server/*.go + userkey/*.go + spec/** (spec/spec.go
// embeds spec/fixtures/*.json via //go:embed, so the whole spec/ tree is in
// scope). The root LICENSE-MIT/LICENSE-APACHE files are also in scope so the
// staged module artifact carries both exact dual-licence texts. Everything
// else (rust/, ts/, tools/, interop/, docs/, .github/, readme files,
// .gitattributes) is excluded by construction.
const scope = /^(?:[^/]+\.go|go\.(?:mod|sum)|LICENSE-MIT|LICENSE-APACHE|client\/[^/]+\.go|client\/rotation\/[^/]+\.go|server\/[^/]+\.go|server\/rotation\/[^/]+\.go|userkey\/[^/]+\.go|rotation\/[^/]+\.go|durable\/[^/]+\.go|spec\/.+)$/u;
const listOutput = execFileSync("git", ["ls-files", "-z"], {
  cwd: repoRoot,
  encoding: "buffer",
  stdio: ["ignore", "pipe", "inherit"],
  shell: process.platform === "win32",
});
const tracked = listOutput
  .toString("utf8")
  .split("\u0000")
  .map((line) => line.replaceAll("\\", "/"))
  .filter((line) => line !== "");
const members = tracked.filter((rel) => scope.test(rel)).sort();
if (members.length === 0) fail("git ls-files produced no in-scope module files");

const moduleRoot = path.join(stageDir, "module");
await mkdir(moduleRoot);
for (const rel of members) {
  const source = path.join(repoRoot, rel);
  if (!(await stat(source)).isFile()) fail(`tracked module file is missing on disk: ${rel}`);
  const destination = path.join(moduleRoot, rel);
  await mkdir(path.dirname(destination), { recursive: true });
  await copyFile(source, destination);
}

const inventory = {
  module: "github.com/PHPCraftdream/mcp-jack",
  goVersion: "1.25.0",
  files: members,
  snapshot: "staged",
};
await writeFile(path.join(stageDir, "inventory.json"), `${JSON.stringify(inventory, null, 2)}\n`, "utf8");

// Required members: the manifest, the embedded spec entrypoint, and every
// root-level *.go file currently on disk per ls-files (fail on mismatch).
if (!members.includes("go.mod")) fail("staged module snapshot omitted go.mod");
for (const source of ["client/rotation/controller.go", "client/rotation/refresh.go", "client/rotation/http.go", "server/rotation/provider.go", "server/rotation/publication.go"]) {
  if (!members.includes(source)) fail(`staged module snapshot omitted ${source}`);
}
if (!members.includes("spec/spec.go")) fail("staged module snapshot omitted spec/spec.go (go:embed fixtures/*.json)");
// The dual-licence texts must ship with the module artifact, byte-exact
// against the repo root copies.
for (const licence of ["LICENSE-MIT", "LICENSE-APACHE"]) {
  if (!members.includes(licence)) fail(`staged module snapshot omitted ${licence}`);
  const [staged, root] = await Promise.all([
    readFile(path.join(moduleRoot, licence)),
    readFile(path.join(repoRoot, licence)),
  ]);
  if (!staged.equals(root)) fail(`staged ${licence} differs from the repo root licence bytes`);
}
for (const rel of tracked.filter((t) => /^[^/]+\.go$/u.test(t))) {
  if (!members.includes(rel)) fail(`staged module snapshot omitted root-level Go file: ${rel}`);
}
const diskRootGo = (await readdir(repoRoot))
  .filter((name) => name.endsWith(".go"))
  .sort();
for (const name of diskRootGo) {
  if (!members.includes(name)) fail(`root-level Go file on disk is missing from the staged snapshot: ${name}`);
}
// Ничего за пределами явного module scope не попадает в snapshot.
for (const rel of members) {
  if (!scope.test(rel)) fail(`staged module snapshot included an out-of-scope file: ${rel}`);
}
if (!members.includes("go.sum")) fail("reviewed dependency checksums are missing");
for (const name of ["go.mod", "go.sum"]) {
  const [staged, original] = await Promise.all([
    readFile(path.join(moduleRoot, name)), readFile(path.join(repoRoot, name)),
  ]);
  if (!staged.equals(original)) fail(`staged ${name} differs from the reviewed source`);
}

console.log(`Go module snapshot: stage/module (${members.length} files)`);
console.log(`Go inventory: inventory.json (module ${inventory.module}, go ${inventory.goVersion})`);
