import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { TransferCheckFailure } from './transfer-checks.mjs';
import { loadTransferFixtures } from './transfer-fixtures.mjs';
import { runCredentialPairs } from './transfer-matrix.mjs';
import { runRefusalPairs } from './transfer-refusals.mjs';
import { runTrustPairs } from './transfer-trust.mjs';
import { runPublicPairs } from './transfer-public.mjs';
import { TransferFailure, runProbe, shutdownOwned } from './transfer-process.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const LANGS = Object.freeze(['go', 'rust', 'typescript']);
const DEFAULT_TARGETS = join(ROOT, 'interop', 'targets.json');
let interrupted = false;

function requireCheck(condition, label) {
  if (!condition) throw new TransferCheckFailure(label);
}

function readJson(path, label) {
  try { return JSON.parse(readFileSync(path, 'utf8')); }
  catch { throw new TransferCheckFailure(label); }
}

function validateTargets(value) {
  requireCheck(value && typeof value === 'object' && !Array.isArray(value), 'targets shape');
  requireCheck(Object.keys(value).length === LANGS.length && LANGS.every((lang) => Object.hasOwn(value, lang)), 'target languages');
  for (const lang of LANGS) {
    const transfer = value[lang]?.transfer;
    requireCheck(Array.isArray(transfer) && transfer.length > 0 && transfer.every((arg) => typeof arg === 'string' && arg.length > 0), `transfer target ${lang}`);
  }
  return value;
}

export async function runMatrix(targets, f, { invoke = runProbe, report = (line) => process.stdout.write(`${line}\n`) } = {}) {
  const validatedTargets = validateTargets(targets);
  const credential = await runCredentialPairs(validatedTargets, f, { invoke, report });
  const state = { issued: credential.issued, imported: credential.imported };
  const refusals = await runRefusalPairs(validatedTargets, f, state, { invoke, report });
  const trust = await runTrustPairs(validatedTargets, f, state, { invoke, report });
  const publicPairs = await runPublicPairs(validatedTargets, f, state, { invoke, report });
  const counts = {
    ...credential.counters,
    caseVisits: refusals.caseVisits,
    trustPairs: trust.trustPairs,
    publicPairs: publicPairs.publicPairs,
    publicExports: publicPairs.publicExports,
    invocations: credential.counters.invocations + refusals.invocations + trust.invocations + publicPairs.invocations,
    operations: credential.counters.operations + refusals.operations + trust.operations + publicPairs.operations,
  };
  requireCheck(counts.credentialPairs === 9 && counts.credentialHandoffs === 63 && counts.caseVisits === 594 &&
    counts.trustPairs === 9 && counts.publicPairs === 9 && counts.publicExports === 225 &&
    counts.invocations > 0 && counts.operations > 0, 'matrix counts');
  return counts;
}

function parseArgs(argv) {
  let targetsPath = DEFAULT_TARGETS;
  let selfTest = false;
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === '--self-test' && argv.length === 1) selfTest = true;
    else if (argv[index] === '--targets' && index + 1 < argv.length && index === 0 && argv.length === 2) {
      targetsPath = resolve(ROOT, argv[index + 1]);
      index += 1;
    } else throw new TransferCheckFailure('arguments');
  }
  return { targetsPath, selfTest };
}

async function main() {
  const signals = [];
  const interrupt = (code) => {
    interrupted = true;
    process.exitCode = code;
    void shutdownOwned().catch(() => {
      process.stderr.write('cleanup_timeout: transfer cleanup\n');
      process.exitCode = 1;
    });
  };
  const onInt = () => interrupt(130);
  const onTerm = () => interrupt(143);
  process.on('SIGINT', onInt);
  process.on('SIGTERM', onTerm);
  signals.push(['SIGINT', onInt], ['SIGTERM', onTerm]);
  try {
    const options = parseArgs(process.argv.slice(2));
    if (options.selfTest) {
      const selfTestPath = join(ROOT, 'interop', 'transfer-self-test.mjs');
      const selfTestModule = await import(pathToFileURL(selfTestPath));
      await selfTestModule.selfTest();
      process.stdout.write('PASS transfer self-test\n');
      return;
    }
    const targets = validateTargets(readJson(options.targetsPath, 'targets file'));
    let fixtures;
    try { fixtures = loadTransferFixtures(ROOT); }
    catch { throw new TransferFailure('internal_error', 'fixture loading'); }
    const invoke = (argv, operations, label) => {
      if (interrupted) throw new TransferFailure('interrupted', label);
      return runProbe(argv, operations, label);
    };
    const counts = await runMatrix(targets, fixtures, { invoke });
    if (!interrupted) process.stdout.write(
      `transfer: credential-pairs=${counts.credentialPairs} handoffs=${counts.credentialHandoffs} ` +
      `case-visits=${counts.caseVisits} trust-pairs=${counts.trustPairs} public-pairs=${counts.publicPairs} ` +
      `public-exports=${counts.publicExports} invocations=${counts.invocations} operations=${counts.operations}\n`,
    );
  } catch (error) {
    if (!interrupted) {
      const message = error instanceof TransferFailure || error instanceof TransferCheckFailure
        ? error.message : 'transfer fixture/harness failure';
      process.stderr.write(`${message}\n`);
      process.exitCode = 1;
    }
  } finally {
    try {
      await shutdownOwned();
    } catch {
      process.stderr.write('cleanup_timeout: transfer cleanup\n');
      process.exitCode = 1;
    }
    for (const [signal, handler] of signals) process.off(signal, handler);
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
