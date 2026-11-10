import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { GENERATED } from './fixture-build.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '../../..');
const outputs = GENERATED;
if (process.argv.includes('--check')) {
  const stale = Object.entries(outputs).filter(([relative, expected]) => {
    const file = join(ROOT, 'spec', relative);
    return !existsSync(file) || readFileSync(file, 'utf8') !== expected;
  });
  if (stale.length) {
    console.error(`candidate outputs missing or stale: ${stale.map(([relative]) => `spec/${relative}`).join(', ')}`);
    process.exitCode = 1;
  } else console.log(`candidate fixtures current: ${Object.keys(outputs).length} outputs`);
} else {
  for (const [relative, content] of Object.entries(outputs)) writeFileSync(join(ROOT, 'spec', relative), content);
  console.log(`wrote ${Object.keys(outputs).length} candidate outputs`);
}
