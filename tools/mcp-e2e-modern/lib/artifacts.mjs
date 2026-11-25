import { mkdir, readdir, rm, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { validateCell } from './ledger.mjs';

export async function prepareArtifacts({ root, keep = false } = {}) {
  const base = resolve(root ?? 'tools/mcp-e2e-modern/artifacts');
  await mkdir(base, { recursive: true });
  if (keep) {
    const entries = (await readdir(base, { withFileTypes: true })).filter((entry) => entry.isDirectory()).sort((a, b) => a.name.localeCompare(b.name));
    if (entries.length) return join(base, entries.at(-1).name);
  }
  const stamp = new Date().toISOString().replaceAll(':', '-').replaceAll('.', '-');
  const dir = join(base, stamp);
  await mkdir(dir, { recursive: false });
  return dir;
}

export async function writeLedger(dir, cells) {
  for (const [index, cell] of cells.entries()) {
    const result = validateCell(cell);
    if (!result.ok) throw new TypeError(`invalid ledger cell ${index}: ${result.errors.join('; ')}`);
  }
  await writeFile(join(dir, 'ledger.jsonl'), cells.map((cell) => JSON.stringify(cell)).join('\n') + (cells.length ? '\n' : ''), 'utf8');
}

export async function writeCapture(dir, cellId, captures) {
  const safe = String(cellId).replace(/[^a-zA-Z0-9._-]/g, '_');
  await writeFile(join(dir, `${safe}.captures.json`), JSON.stringify(captures, null, 2) + '\n', 'utf8');
}

export async function writeLogs(dir, name, text) {
  const safe = String(name).replace(/[^a-zA-Z0-9._-]/g, '_');
  await writeFile(join(dir, `${safe}.log`), String(text), 'utf8');
}

export async function pruneIfNotKept(dir, keep = false, cells = [], processFailing = false) {
  if (keep || processFailing || cells.some((cell) => cell?.outcome === 'FAIL')) return false;
  await rm(dir, { recursive: true, force: true });
  return true;
}
