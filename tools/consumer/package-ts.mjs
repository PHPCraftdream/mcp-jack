import { execFileSync } from "node:child_process";
import { copyFile, mkdir, readFile, readdir, realpath, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, "../..");
const tsRoot = path.join(repoRoot, "ts");
const scratchRoot = path.join(scriptDir, ".scratch");
const stage = process.argv[2];
function fail(message) {
  throw new Error(`TypeScript package staging: ${message}`);
}

if (stage === undefined || stage.trim() === "") {
  throw new Error("usage: node tools/consumer/package-ts.mjs <stage-directory>");
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
await mkdir(requestedStageDir);
const stageDir = await realpath(requestedStageDir);
const realStageRelative = path.relative(realScratchRoot, stageDir);
if (realStageRelative === "" || realStageRelative === ".." || realStageRelative.startsWith(`..${path.sep}`) || path.isAbsolute(realStageRelative)) {
  fail("stage directory resolves outside tools/consumer/.scratch");
}
const buildDir = path.join(stageDir, "build");
const packageStage = path.join(stageDir, "package");
const npmCache = path.join(stageDir, "npm-cache");
const archivePath = path.join(stageDir, "mcp-jack-0.0.0.tgz");
const inventoryPath = path.join(stageDir, "inventory.json");

async function exists(target) {
  try {
    await stat(target);
    return true;
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return false;
    throw error;
  }
}

async function copyLibraryTree(source, destination, relative = "") {
  const entries = await readdir(path.join(source, relative), { withFileTypes: true });
  for (const entry of entries) {
    const rel = relative === "" ? entry.name : `${relative}/${entry.name}`;
    if (entry.isDirectory()) {
      // The library-only tsconfig already excludes src/interop; a directory
      // named interop in the build output is a packaging defect, not
      // something to skip silently.
      if (relative !== "" || !["client", "server"].includes(entry.name)) fail(`unexpected library output directory ${rel}`);
      await mkdir(path.join(destination, rel), { recursive: true });
      await copyLibraryTree(source, destination, rel);
      continue;
    }
    if (!entry.isFile() || !/^[^/]+\.(?:js|d\.ts)$/u.test(entry.name)) fail(`unexpected library output member ${rel}`);
    await copyFile(path.join(source, rel), path.join(destination, rel));
  }
}

const sourceManifest = JSON.parse(await readFile(path.join(tsRoot, "package.json"), "utf8"));
if (sourceManifest.private !== true) fail("source package must retain private=true");
if (sourceManifest.version !== "0.0.0") fail("source package version must remain 0.0.0");
if (sourceManifest.type !== "module" || sourceManifest.main !== "./dist/index.js" || sourceManifest.types !== "./dist/index.d.ts") {
  fail("source package ESM entry metadata is incomplete");
}

await mkdir(buildDir);
await mkdir(packageStage);
await mkdir(npmCache);
execFileSync("npm", ["run", "build:package", "--", "--outDir", buildDir], {
  cwd: tsRoot,
  env: { ...process.env, npm_config_cache: npmCache },
  stdio: "inherit",
  shell: process.platform === "win32",
});

const stagedManifest = { ...sourceManifest };
// The packed package contains compiled output; its source-only build/test commands and toolchain dependencies belong to the private workspace, not package consumers.
delete stagedManifest.scripts;
delete stagedManifest.devDependencies;
await mkdir(path.join(packageStage, "dist"), { recursive: true });
await copyLibraryTree(buildDir, path.join(packageStage, "dist"));
await writeFile(path.join(packageStage, "package.json"), `${JSON.stringify(stagedManifest, null, 2)}\n`, "utf8");
for (const file of ["README.md"]) {
  await copyFile(path.join(tsRoot, file), path.join(packageStage, file));
}
for (const file of ["LICENSE-MIT", "LICENSE-APACHE"]) {
  await copyFile(path.join(repoRoot, file), path.join(packageStage, file));
}

const packOutput = execFileSync("npm", ["pack", "--json", "--pack-destination", stageDir], {
  cwd: packageStage,
  env: { ...process.env, npm_config_cache: npmCache },
  encoding: "utf8",
  stdio: ["ignore", "pipe", "inherit"],
  shell: process.platform === "win32",
});
const packed = JSON.parse(packOutput);
if (!Array.isArray(packed) || packed.length !== 1 || packed[0] === undefined || !Array.isArray(packed[0].files)) {
  fail("npm pack did not return one package inventory");
}
const packedInfo = packed[0];
const members = packedInfo.files.map((file) => String(file.path).replaceAll("\\", "/")).sort();
const allowed = /^(?:package\.json|README\.md|LICENSE-MIT|LICENSE-APACHE|dist\/(?:[^/]+\.(?:js|d\.ts)|(?:client|server)\/[^/]+\.(?:js|d\.ts)))$/u;
for (const member of members) {
  if (!allowed.test(member)) fail(`npm pack included a forbidden member: ${member}`);
}
for (const required of ["package.json", "README.md", "LICENSE-MIT", "LICENSE-APACHE", "dist/index.js", "dist/index.d.ts"]) {
  if (!members.includes(required)) fail(`npm pack omitted required member: ${required}`);
}
if (packedInfo.filename !== path.basename(archivePath)) fail("npm pack returned an unexpected archive filename");
const inventory = {
  name: packedInfo.name,
  version: packedInfo.version,
  private: sourceManifest.private,
  artifact: path.basename(archivePath),
  members,
};
await writeFile(inventoryPath, `${JSON.stringify(inventory, null, 2)}\n`, "utf8");
console.log(`TypeScript artifact: ${path.basename(archivePath)}`);
console.log(`TypeScript inventory: ${path.basename(inventoryPath)}`);
