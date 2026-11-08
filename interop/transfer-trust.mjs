import { b64u, decodeB64u } from './transfer-fixtures.mjs';
import { TransferCheckFailure, checkErrorResult, checkSignerResult, mutationFromBaseline, trustVariants } from './transfer-checks.mjs';
import { validateResults } from './transfer-process.mjs';

const LANGS = Object.freeze(['go', 'rust', 'typescript']);
const messageBytes = (messages) => messages.map((message) => b64u(message.bytes));

function replaceOnce(bytes, before, after, label) {
  const start = bytes.indexOf(before);
  if (start < 0 || bytes.indexOf(before, start + before.length) >= 0) {
    throw new TransferCheckFailure(label);
  }
  return Buffer.concat([bytes.subarray(0, start), after, bytes.subarray(start + before.length)]);
}

function replaceBetween(bytes, prefix, suffix, value, label) {
  const start = bytes.indexOf(prefix);
  const end = start < 0 ? -1 : bytes.indexOf(suffix, start + prefix.length);
  if (start < 0 || end < 0) throw new TransferCheckFailure(label);
  return Buffer.concat([
    bytes.subarray(0, start + prefix.length), value, bytes.subarray(end),
  ]);
}

function innerPrivateEnvelope(credential, expected, label) {
  let parsed;
  try { parsed = JSON.parse(credential.toString('utf8')); }
  catch { throw new TransferCheckFailure(label); }
  if (!parsed || typeof parsed.client_key !== 'string') throw new TransferCheckFailure(label);
  const inner = Buffer.from(parsed.client_key, 'utf8');
  if (!inner.equals(expected)) throw new TransferCheckFailure(label);
  return inner;
}

function checkedResults(operations, response, label) {
  return validateResults(operations, Array.isArray(response) ? { results: response } : response, label);
}

/** Check trust behavior for every cross-language issuer/client pair. */
export async function runTrustPairs(targets, f, state, { invoke, report }) {
  const measured = { invocations: 0, operations: 0, trustPairs: 0 };
  const messages = f.messages;
  const encodedMessages = messageBytes(messages);
  const aliceFixture = f.positives.find((fixture) => fixture.id === 'cred-alice');
  if (!aliceFixture) throw new TransferCheckFailure('cred-alice fixture');

  for (const issuer of LANGS) for (const client of LANGS) {
    const pair = `issuer=${issuer} client=${client}`;
    const issuedAlice = state.issued[issuer]?.['cred-alice'];
    const importedAlice = state.imported[client]?.find((entry) =>
      entry.issuer === issuer && entry.fixture.id === 'cred-alice');
    if (!issuedAlice || !importedAlice) throw new TransferCheckFailure(`${pair} cred-alice state`);
    const actualAlice = decodeB64u(issuedAlice.credential_b64u);
    const aliceBytes = mutationFromBaseline(actualAlice, aliceFixture.bytes, aliceFixture.bytes, `${pair} cred-alice baseline`);
    const innerAlice = innerPrivateEnvelope(actualAlice, f.positives.find((item) => item.id === 'priv-alice').bytes, `${pair} cred-alice inner`);
    const actualPublic = decodeB64u(importedAlice.result.public_envelope_b64u);
    const operations = [];
    const checks = [];
    const add = (operation, checker) => {
      operations.push({ id: `c${operations.length}`, ...operation });
      checks.push(checker);
    };
    const addError = (operation, caseName, expectedClass) => {
      add(operation, (result) => checkErrorResult(
        result, expectedClass, `${pair} ${caseName} expected_class=${expectedClass}`,
      ));
    };
    const addImport = (document, extra = {}) => ({
      op: 'import-credential', document_b64u: b64u(document), messages_b64u: encodedMessages, ...extra,
    });
    const addValidation = (document, extra = {}) => ({
      op: 'validate-credential', document_b64u: b64u(document), ...extra,
    });

    // A matching tuple must succeed, including the five independently checked signatures.
    add(addImport(aliceBytes, { expected: f.svcExpected }), (result) =>
      checkSignerResult(result, f.keys.alice, messages, `${pair} matching-credential`, f.svcExpected));

    for (const variant of trustVariants(f.svcExpected, f.keys.bob)) {
      const extra = Object.hasOwn(variant, 'expected') ? { expected: variant.expected } : {};
      addError(addImport(aliceBytes, extra), `trust-variant-${variant.id}`, 'server_identity_mismatch');
    }

    for (const negative of f.negatives.filter((item) => item.sink === 'credential')) {
      const document = mutationFromBaseline(actualAlice, aliceFixture.bytes, negative.bytes, `${pair} ${negative.id}`);
      addError(addImport(document), `import-${negative.id}`, negative.expect_class);
      addError(addValidation(document), `validate-${negative.id}`, negative.expect_class);
    }

    for (const fixture of f.credentialCases) {
      const issued = state.issued[issuer]?.[fixture.id];
      if (!issued) throw new TransferCheckFailure(`${pair} issued ${fixture.id}`);
      const document = decodeB64u(issued.credential_b64u);
      add(addValidation(document, { expected: fixture.expected }), (result) => {
        if (result.ok !== true) throw new TransferCheckFailure(`${pair} validate-${fixture.id} expected ok`);
      });
    }
    addError(addValidation(aliceBytes, { expected: null }), 'validate-null-trust-tuple', 'server_identity_mismatch');

    // These sink changes preserve actual credential/key bytes and vary only the receiving operation.
    addError({ op: 'import-public', document_b64u: b64u(innerAlice), role: 'server', verifications: [] },
      'server-public-import-private-inner', 'private_material_rejected');
    addError({ op: 'import-public', document_b64u: b64u(aliceBytes), role: 'server', verifications: [] },
      'server-public-import-credential', 'private_material_rejected');
    addError({ op: 'import-public', document_b64u: b64u(innerAlice), role: 'client', verifications: [] },
      'client-public-import-private-inner', 'wrong_envelope_type');
    addError(addImport(actualPublic), 'credential-import-public-export', 'wrong_envelope_type');

    // Ordering controls are byte edits to the actual canonical credential, not parsed/re-serialized JSON.
    const escapedInnerVersion = Buffer.from([0x5c, 0x22, 0x76, 0x5c, 0x22, 0x3a, 0x31]);
    const escapedInnerVersion2 = Buffer.from([0x5c, 0x22, 0x76, 0x5c, 0x22, 0x3a, 0x32]);
    const innerV2OuterSpace = Buffer.concat([
      replaceOnce(aliceBytes, escapedInnerVersion, escapedInnerVersion2, `${pair} inner v2`), Buffer.from(' '),
    ]);
    addError(addImport(innerV2OuterSpace), 'inner-unknown-version-before-outer-canonicality', 'unknown_version');

    const keyPrefix = Buffer.from(',"client_key":"', 'utf8');
    const keySuffix = Buffer.from('","server_kid":', 'utf8');
    const outerV2InnerOpen = replaceOnce(
      replaceBetween(aliceBytes, keyPrefix, keySuffix, Buffer.from('{'), `${pair} inner open`),
      Buffer.from('"v":1}', 'utf8'), Buffer.from('"v":2}', 'utf8'), `${pair} outer v2`,
    );
    addError(addImport(outerV2InnerOpen), 'outer-unknown-version-before-inner-parse', 'unknown_version');

    const truncated = aliceBytes.subarray(0, aliceBytes.length - 1);
    addError(addImport(truncated, { expected: { ...f.svcExpected, url: 'https://other.example.test' } }),
      'malformed-before-trust-check', 'malformed_json');
    addError(addImport(Buffer.concat([aliceBytes, Buffer.from(' ')])),
      'noncanonical-before-omitted-trust', 'non_canonical_bytes');

    const unicodeFixture = f.credentialCases.find((fixture) => fixture.id === 'cred-aud-codepoints');
    if (!unicodeFixture) throw new TransferCheckFailure(`${pair} Unicode fixture`);
    const unicodeDocument = decodeB64u(state.issued[issuer]['cred-aud-codepoints'].credential_b64u);
    const decomposedAud = { ...unicodeFixture.expected, aud: 'e\u0301😀' };
    addError(addImport(unicodeDocument, { expected: decomposedAud }),
      'unicode-audience-no-normalization-import', 'server_identity_mismatch');
    addError(addValidation(unicodeDocument, { expected: decomposedAud }),
      'unicode-audience-no-normalization-validator', 'server_identity_mismatch');

    const uppercaseURL = { ...f.svcExpected, url: 'https://SVC.EXAMPLE.TEST' };
    addError(addImport(aliceBytes, { expected: uppercaseURL }),
      'uppercase-expected-url-import', 'server_identity_mismatch');
    addError(addValidation(aliceBytes, { expected: uppercaseURL }),
      'uppercase-expected-url-validator', 'server_identity_mismatch');

    const label = `credential trust ${pair}`;
    const response = await invoke(targets[client].transfer, operations, label);
    measured.invocations += 1;
    measured.operations += operations.length;
    const results = checkedResults(operations, response, label);
    for (let index = 0; index < results.length; index += 1) checks[index](results[index]);
    measured.trustPairs += 1;
    if (typeof report === 'function') await report(`PASS ${pair} trust operations=${operations.length}`);
  }
  return measured;
}
