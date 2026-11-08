import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkErrorResult, checkIssueResult, checkPublicResult, checkSignerResult, TransferCheckFailure, verificationControls } from './transfer-checks.mjs';
import { b64u, loadTransferFixtures } from './transfer-fixtures.mjs';
import { TransferFailure, ownedCount, runProbe, validateResults } from './transfer-process.mjs';
import { lifecycleTests } from './transfer-lifecycle-test.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const LANGS = ['go', 'rust', 'typescript'];
const fail = (label) => { throw new TransferCheckFailure(label); };

export async function selfTest() {
  const report = (line) => process.stdout.write(`${line}\n`);
  let total = 0;
  let controls = 0;
  const passed = (label, control = false) => {
    total += 1;
    if (control) controls += 1;
    report(`self-test PASS ${label}`);
  };
  const expect = (callback, ErrorType, label) => {
    let caught;
    try { callback(); } catch (error) { caught = error; }
    if (!(caught instanceof ErrorType)) fail(label);
    passed(label, true);
  };
  const rawTargets = JSON.parse(readFileSync(join(ROOT, 'interop/targets.json'), 'utf8'));
  if (!rawTargets || typeof rawTargets !== 'object' || Array.isArray(rawTargets) ||
      Object.keys(rawTargets).length !== LANGS.length || !LANGS.every((lang) => Object.hasOwn(rawTargets, lang))) {
    fail('self-test transfer targets');
  }
  for (const lang of LANGS) {
    const transfer = rawTargets[lang]?.transfer;
    if (!Array.isArray(transfer) || transfer.length === 0 ||
        !transfer.every((arg) => typeof arg === 'string' && arg.length > 0)) fail('self-test transfer targets');
  }
  const targets = rawTargets;
  const f = loadTransferFixtures(ROOT);
  const fixture = f.credentialCases.find((item) => item.id === 'cred-alice');
  if (!fixture) fail('fixture cred-alice');
  const messages = f.messages;
  const encodedMessages = messages.map((message) => b64u(message.bytes));
  const records = Object.create(null);

  // Run and validate every SDK positive before exercising any negative control.
  for (const lang of LANGS) {
    const issueOp = { id: `issue-${lang}`, op: 'issue', seed_b64u: Buffer.from(fixture.key.seed_hex, 'hex').toString('base64url'), expected: fixture.expected };
    const issue = (await runProbe(targets[lang].transfer, [issueOp], `self-test issue ${lang}`, { timeoutMs: 20000 }))[0];
    checkIssueResult(issue, fixture, `self-test issue ${lang}`);
    passed(`issue ${lang}`);
    const importOp = { id: `import-${lang}`, op: 'import-credential', document_b64u: issue.credential_b64u, expected: fixture.expected, messages_b64u: encodedMessages };
    const signer = (await runProbe(targets[lang].transfer, [importOp], `self-test import ${lang}`, { timeoutMs: 20000 }))[0];
    checkSignerResult(signer, fixture.key, messages, `self-test import ${lang}`, fixture.expected);
    passed(`import ${lang}`);
    const controls = verificationControls(signer, messages, f.keys.bob.seed_hex);
    const publicOp = { id: `public-${lang}`, op: 'import-public', document_b64u: signer.public_envelope_b64u, role: 'server', verifications: controls.verifications };
    const publicResult = (await runProbe(targets[lang].transfer, [publicOp], `self-test public ${lang}`, { timeoutMs: 20000 }))[0];
    checkPublicResult(publicResult, { public_key: signer.public_key, kid: signer.kid }, controls.verdicts, `self-test public ${lang}`);
    passed(`public ${lang}`);
    records[lang] = { issue, signer, publicResult, controls };
  }

  const { issue, signer, publicResult, controls: verification } = records.go;
  const bobEnvelope = f.positives.find((item) => item.id === 'pub-bob');
  if (!bobEnvelope) fail('fixture pub-bob');
  const bobSigner = structuredClone(signer);
  bobSigner.public_key = f.keys.bob.public_key;
  bobSigner.kid = f.keys.bob.kid;
  bobSigner.public_envelope_b64u = b64u(bobEnvelope.bytes);
  expect(() => checkSignerResult(bobSigner, fixture.key, messages, 'wrong complete bob identity', fixture.expected), TransferCheckFailure, 'wrong identity');

  const badSignature = structuredClone(signer);
  const signature = Buffer.from(badSignature.signatures_b64u[0], 'base64url');
  signature[0] ^= 1;
  badSignature.signatures_b64u[0] = b64u(signature);
  expect(() => checkSignerResult(badSignature, fixture.key, messages, 'wrong signature bit', fixture.expected), TransferCheckFailure, 'wrong signature');
  const alteredMessages = structuredClone(messages);
  alteredMessages[1].bytes[0] ^= 1;
  expect(() => checkSignerResult(structuredClone(signer), fixture.key, alteredMessages, 'wrong message', fixture.expected), TransferCheckFailure, 'wrong message');
  const badEnvelope = structuredClone(signer);
  const envelope = Buffer.from(badEnvelope.public_envelope_b64u, 'base64url');
  envelope[0] ^= 1;
  badEnvelope.public_envelope_b64u = b64u(envelope);
  expect(() => checkSignerResult(badEnvelope, fixture.key, messages, 'wrong public envelope', fixture.expected), TransferCheckFailure, 'wrong envelope');
  const badConnection = structuredClone(signer);
  badConnection.connection.url = 'https://other.example.test';
  expect(() => checkSignerResult(badConnection, fixture.key, messages, 'wrong connection URL', fixture.expected), TransferCheckFailure, 'wrong connection URL');

  const badCredential = structuredClone(issue);
  const credentialBytes = Buffer.from(badCredential.credential_b64u, 'base64url');
  credentialBytes[0] ^= 1;
  badCredential.credential_b64u = b64u(credentialBytes);
  expect(() => checkIssueResult(badCredential, fixture, 'mutated issued bytes'), TransferCheckFailure, 'issued bytes mutation');
  const staleFresh = structuredClone(issue);
  staleFresh.export_fresh = false;
  expect(() => checkIssueResult(staleFresh, fixture, 'stale issue export'), TransferCheckFailure, 'export freshness');

  for (const verdict of [true, false]) {
    const wrongVerdicts = structuredClone(publicResult);
    wrongVerdicts.verification_results = Array(10).fill(verdict);
    expect(() => checkPublicResult(wrongVerdicts, { public_key: signer.public_key, kid: signer.kid }, verification.verdicts, 'forced verifier verdict'), TransferCheckFailure, `verifier all-${verdict ? 'true' : 'false'}`);
  }
  expect(() => checkSignerResult({ id: 'reject', ok: false, class: 'server_identity_mismatch' }, fixture.key, messages, 'all-reject signer', fixture.expected), TransferCheckFailure, 'all-reject signer');
  expect(() => checkErrorResult({ id: 'accept', ok: true }, 'server_identity_mismatch', 'all-accept refusal'), TransferCheckFailure, 'all-accept refusal');
  expect(() => checkErrorResult({ id: 'wrong-class', ok: false, class: 'malformed_json' }, 'server_identity_mismatch', 'wrong refusal class'), TransferCheckFailure, 'wrong refusal class');

  const validateFails = (operations, parsed, label) => expect(() => validateResults(operations, parsed, label), TransferFailure, label);
  const one = [{ id: 'one', op: 'from-seed' }];
  validateFails(one, {}, 'missing results');
  validateResults([{ id: 'one', op: 'validate-credential' }], { results: [{ id: 'one', ok: true }] }, 'valid validator result');
  validateFails([{ id: 'one', op: 'validate-credential' }], { results: [{ id: 'other', ok: true }] }, 'wrong result id');
  const validationOps = [
    { id: 'one', op: 'validate-credential' },
    { id: 'two', op: 'validate-credential' },
  ];
  validateFails(validationOps, { results: [{ id: 'one', ok: true }, { id: 'one', ok: true }] }, 'duplicate result ids');
  validateFails([{ id: 'signer-extra', op: 'from-seed' }], { results: [{ id: 'signer-extra', ok: false, class: 'server_identity_mismatch', public_key: signer.public_key }] }, 'failure signer extra');
  validateFails([{ id: 'connection-extra', op: 'import-credential' }], { results: [{ id: 'connection-extra', ok: false, class: 'server_identity_mismatch', connection: fixture.expected }] }, 'failure connection extra');

  const lifecycleCount = await lifecycleTests(report);
  if (lifecycleCount !== 15 || ownedCount() !== 0) fail('lifecycle count or owned processes');
  total += lifecycleCount;
  report(`self-test controls=${controls} total=${total}`);
}
