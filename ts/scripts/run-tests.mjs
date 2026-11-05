// Runs the compiled tests: `node --test <dir>` and globs differ between Node 20 and 22.
import { spawnSync } from "node:child_process";
import { readdirSync } from "node:fs";
import { join } from "node:path";

const dir = join("dist-test", "test");
const files = readdirSync(dir)
  .filter((name) => name.endsWith(".test.js"))
  .sort()
  .map((name) => join(dir, name));
const result = spawnSync(process.execPath, ["--test", ...files], { stdio: "inherit" });
process.exit(result.status ?? 1);
