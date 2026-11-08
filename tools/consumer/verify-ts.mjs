import { execFileSync } from "node:child_process";
import { copyFile, mkdir, readFile, readdir, realpath, stat } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, "../..");
const fixtureDir = path.join(scriptDir, "ts");
const scratchRoot = path.join(scriptDir, ".scratch");
const stageArg = process.argv[2];
if (stageArg === undefined || stageArg.trim() === "") {
  throw new Error("usage: node tools/consumer/verify-ts.mjs <stage-directory>");
}
if (process.env.GITHUB_ACTIONS !== "true") throw new Error("TypeScript consumer verification is restricted to GitHub Actions");
const stageDir = path.resolve(stageArg);
const relativeStage = path.relative(scratchRoot, stageDir);
if (relativeStage === "" || relativeStage === ".." || relativeStage.startsWith(`..${path.sep}`) || path.isAbsolute(relativeStage)) {
  throw new Error("TypeScript consumer stage directory must be inside tools/consumer/.scratch");
}
const artifact = path.join(stageDir, "mcp-jack-0.0.0.tgz");
const inventoryPath = path.join(stageDir, "inventory.json");
const inventory = JSON.parse(await readFile(inventoryPath, "utf8"));
const allowed = /^(?:package\.json|README\.md|LICENSE-MIT|LICENSE-APACHE|dist\/(?:[^/]+\.(?:js|d\.ts)|(?:client|server)\/[^/]+\.(?:js|d\.ts)))$/u;
const required = ["package.json", "README.md", "LICENSE-MIT", "LICENSE-APACHE", "dist/index.js", "dist/index.d.ts"];
if (inventory.name !== "mcp-jack" || inventory.version !== "0.0.0" || inventory.private !== true) {
  throw new Error("staged package identity/private metadata changed");
}
if (inventory.artifact !== path.basename(artifact) || !Array.isArray(inventory.members)) {
  throw new Error("staged package inventory is incomplete");
}
for (const member of inventory.members) {
  if (typeof member !== "string" || !allowed.test(member)) throw new Error(`forbidden staged package member: ${String(member)}`);
}
for (const member of required) {
  if (!inventory.members.includes(member)) throw new Error(`missing staged package member: ${member}`);
}
if (!(await stat(artifact)).isFile()) throw new Error("staged package archive is missing");

const consumerDir = path.join(stageDir, "consumer");
await mkdir(consumerDir);
await copyFile(path.join(fixtureDir, "package.json"), path.join(consumerDir, "package.json"));
await copyFile(path.join(fixtureDir, "tsconfig.json"), path.join(consumerDir, "tsconfig.json"));
await copyFile(path.join(fixtureDir, "tsconfig.runtime.json"), path.join(consumerDir, "tsconfig.runtime.json"));
await copyFile(path.join(fixtureDir, "smoke.ts"), path.join(consumerDir, "smoke.ts"));
await copyFile(artifact, path.join(consumerDir, "artifact.tgz"));

const childEnv = { ...process.env, npm_config_cache: path.join(stageDir, "npm-cache") };
delete childEnv.NODE_PATH;
execFileSync("npm", ["install", "--no-audit", "--no-fund", "--ignore-scripts"], {
  cwd: consumerDir,
  env: childEnv,
  stdio: "inherit",
  shell: process.platform === "win32",
});

const packageRoot = await realpath(path.join(consumerDir, "node_modules", "mcp-jack"));
const installedArchive = await realpath(path.join(consumerDir, "artifact.tgz"));
const resolved = execFileSync(
  "node",
  ["--input-type=module", "-e", "process.stdout.write(import.meta.resolve('mcp-jack'))"],
  { cwd: consumerDir, env: childEnv, encoding: "utf8", stdio: ["ignore", "pipe", "inherit"], shell: process.platform === "win32" },
).trim();
const resolvedPath = await realpath(new URL(resolved));
if (!resolvedPath.startsWith(packageRoot + path.sep)) throw new Error("package-root import did not resolve inside the installed archive");
const installedManifest = JSON.parse(await readFile(path.join(packageRoot, "package.json"), "utf8"));
if (installedManifest.name !== inventory.name || installedManifest.version !== inventory.version || installedManifest.private !== true) {
  throw new Error("installed archive metadata differs from the private staged package");
}
if (installedManifest.main !== "./dist/index.js" || installedManifest.types !== "./dist/index.d.ts" || installedManifest.type !== "module") {
  throw new Error("installed archive root ESM metadata is incomplete");
}
if (installedArchive !== await realpath(path.join(consumerDir, "artifact.tgz"))) throw new Error("consumer dependency is not the staged tarball");

async function enumerateFiles(directory, relative = "") {
  const result = [];
  for (const entry of await readdir(path.join(directory, relative), { withFileTypes: true })) {
    const name = relative === "" ? entry.name : `${relative}/${entry.name}`;
    if (entry.isDirectory()) result.push(...(await enumerateFiles(directory, name)));
    else if (entry.isFile()) result.push(name);
    else throw new Error(`unexpected installed package member kind: ${name}`);
  }
  return result;
}
const installedMembers = (await enumerateFiles(packageRoot)).sort();
for (const member of installedMembers) {
  if (!allowed.test(member)) throw new Error(`forbidden installed package member: ${member}`);
}
if (JSON.stringify(installedMembers) !== JSON.stringify([...inventory.members].sort())) {
  throw new Error("installed package inventory differs from npm pack inventory");
}
for (const [packageLicense, rootLicense] of [["LICENSE-MIT", "LICENSE-MIT"], ["LICENSE-APACHE", "LICENSE-APACHE"]]) {
  const [actual, original] = await Promise.all([
    readFile(path.join(packageRoot, packageLicense)),
    readFile(path.join(repoRoot, rootLicense)),
  ]);
  if (!actual.equals(original)) throw new Error(`${packageLicense} differs from the root license bytes`);
}

execFileSync("npm", ["exec", "--", "tsc", "--project", "tsconfig.json"], {
  cwd: consumerDir,
  env: childEnv,
  stdio: "inherit",
  shell: process.platform === "win32",
});
execFileSync("npm", ["exec", "--", "tsc", "--project", "tsconfig.runtime.json"], {
  cwd: consumerDir,
  env: childEnv,
  stdio: "inherit",
  shell: process.platform === "win32",
});
execFileSync("node", [path.join(consumerDir, "out", "smoke.js")], {
  cwd: consumerDir,
  env: childEnv,
  stdio: "inherit",
});
console.log(`TypeScript consumer verified from ${path.basename(artifact)} (${installedMembers.length} package files)`);
