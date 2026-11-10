import { execFileSync } from "node:child_process";
import { copyFile, mkdir, readFile, readdir, realpath, stat } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Verifies the staged Go module snapshot from a fresh standalone Go consumer.
// CI-only. Stage discipline here is stricter than verify-rust.mjs/verify-ts.mjs:
// this script additionally canonicalizes the stage path with realpath and
// re-checks containment after resolution (scratch-inside-repo + stage-inside-
// scratch on real paths); verify-rust.mjs performs no realpath canonicalization
// and verify-ts.mjs realpaths only the installed node_modules tree. All CI
// callers pass fixed literal paths, so the looser argv handling there is
// acceptable.
//
// RESOLUTION DOCUMENTATION: the consumer's go.mod (tools/consumer/go/go.mod)
// resolves the module artifact with the documented directive
//   replace github.com/PHPCraftdream/mcp-jack => ../module
// which targets the STAGED SNAPSHOT directory (stage/module) produced by
// package-go.mjs — never the repo checkout. This is the documented resolution
// of the staged module artifact. Because the dependency is a filesystem-path
// replacement plus standard library only, no go.sum is required (replaced
// modules bypass the proxy/checksum database entirely; GOFLAGS=-mod=mod and
// isolated GOPATH/GOMODCACHE/GOCACHE keep the resolution hermetic, and
// GOTOOLCHAIN=local pins the toolchain to the CI-installed Go 1.25).

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, "../..");
const fixtureDir = path.join(scriptDir, "go");
const scratchRoot = path.join(scriptDir, ".scratch");
const stageArg = process.argv[2];
if (stageArg === undefined || stageArg.trim() === "") {
  throw new Error("usage: node tools/consumer/verify-go.mjs <stage-directory>");
}
if (process.env.GITHUB_ACTIONS !== "true") throw new Error("Go consumer verification is restricted to GitHub Actions");
const requestedStageDir = path.resolve(stageArg);
const relativeStage = path.relative(scratchRoot, requestedStageDir);
if (relativeStage === "" || relativeStage === ".." || relativeStage.startsWith(`..${path.sep}`) || path.isAbsolute(relativeStage)) {
  throw new Error("Go consumer stage directory must be inside tools/consumer/.scratch");
}
if (path.dirname(requestedStageDir) !== scratchRoot) {
  throw new Error("Go consumer stage directory must be a direct child of tools/consumer/.scratch");
}
await mkdir(scratchRoot, { recursive: true });
const realRepoRoot = await realpath(repoRoot);
const realScratchRoot = await realpath(scratchRoot);
const scratchRelative = path.relative(realRepoRoot, realScratchRoot);
if (scratchRelative === "" || scratchRelative.startsWith(`..${path.sep}`) || path.isAbsolute(scratchRelative)) {
  throw new Error("scratch directory must be inside the repository");
}
const stageDir = await realpath(requestedStageDir);
const realStageRelative = path.relative(realScratchRoot, stageDir);
if (realStageRelative === "" || realStageRelative === ".." || realStageRelative.startsWith(`..${path.sep}`) || path.isAbsolute(realStageRelative)) {
  throw new Error("stage directory resolves outside tools/consumer/.scratch");
}

const inventoryPath = path.join(stageDir, "inventory.json");
const inventory = JSON.parse(await readFile(inventoryPath, "utf8"));
const allowed = /^(?:[^/]+\.go|go\.mod|LICENSE-MIT|LICENSE-APACHE|client\/[^/]+\.go|server\/[^/]+\.go|userkey\/[^/]+\.go|rotation\/[^/]+\.go|spec\/.+)$/u;
if (inventory.module !== "github.com/PHPCraftdream/mcp-jack" || inventory.goVersion !== "1.25.0" || inventory.snapshot !== "staged") {
  throw new Error("staged module identity metadata changed");
}
if (!Array.isArray(inventory.files) || inventory.files.length === 0) throw new Error("staged module inventory is incomplete");
for (const member of inventory.files) {
  if (typeof member !== "string" || !allowed.test(member)) throw new Error(`out-of-scope staged module file: ${String(member)}`);
  if (member.endsWith("go.sum")) throw new Error("staged module snapshot must not contain go.sum (product has no deps)");
}
for (const member of ["go.mod", "LICENSE-MIT", "LICENSE-APACHE", "spec/spec.go"]) {
  if (!inventory.files.includes(member)) throw new Error(`missing staged module file: ${member}`);
}

const moduleRoot = path.join(stageDir, "module");
const stagedGoMod = await readFile(path.join(moduleRoot, "go.mod"));
const repoGoMod = await readFile(path.join(repoRoot, "go.mod"));
if (!stagedGoMod.equals(repoGoMod)) throw new Error("staged go.mod differs byte-wise from the repo go.mod");
const moduleEntries = await readdir(moduleRoot, { recursive: true });
if (moduleEntries.some((name) => name.endsWith("go.sum"))) {
  throw new Error("staged module snapshot contains go.sum; the product must ship without one");
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

function go(args, encoding) {
  return execFileSync("go", args, {
    cwd: consumerDir,
    env: {
      ...process.env,
      GOFLAGS: "-mod=mod",
      GOPATH: path.join(stageDir, "gopath"),
      GOMODCACHE: path.join(stageDir, "gopath", "pkg", "mod"),
      GOCACHE: path.join(stageDir, "gocache"),
      GOTOOLCHAIN: "local",
    },
    encoding,
    stdio: encoding === "utf8" ? ["ignore", "pipe", "inherit"] : "inherit",
    shell: process.platform === "win32",
  });
}

// Full standalone smoke: key lifecycle, credential flow, and a real signed
// loopback client/server round trip against the staged snapshot.
go(["run", "."]);

// Resolution proof: `go list -m` prints the replacement for a replaced
// module. Assert it resolved to the staged snapshot via the documented
// replace directive, never the repo checkout.
const resolved = go(["list", "-m", "github.com/PHPCraftdream/mcp-jack"], "utf8").trim();
if (!resolved.includes("=> ../module")) {
  throw new Error(`module artifact did not resolve to the staged snapshot via ../module; got: ${resolved}`);
}
console.log(`resolved module: ${resolved}`);
console.log(`Go consumer verified against staged module snapshot (${inventory.files.length} module files)`);
