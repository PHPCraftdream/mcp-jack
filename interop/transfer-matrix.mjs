import { b64u } from './transfer-fixtures.mjs';
import { TransferCheckFailure, checkIssueResult, checkSignerResult } from './transfer-checks.mjs';
import { validateResults } from './transfer-process.mjs';

const LANGS = Object.freeze(['go', 'rust', 'typescript']);

function checkedResults(operations, response, label) {
  // runProbe-style callers may already return the results array; raw invoke
  // adapters commonly return the process response envelope instead.
  return validateResults(operations, Array.isArray(response) ? { results: response } : response, label);
}

/** Run deterministic credential issuance and the positive cross-language handoffs. */
export async function runCredentialPairs(targets, f, { invoke, report }) {
  const issued = Object.create(null);
  const imported = Object.fromEntries(LANGS.map((lang) => [lang, []]));
  const counters = { credentialPairs: 0, credentialHandoffs: 0, invocations: 0, operations: 0 };
  const fixtures = f.credentialCases;
  const messages = f.messages;

  for (const issuer of LANGS) {
    const operations = [];
    for (const fixture of fixtures) {
      for (const repetition of ['first', 'second']) {
        const id = `issue-${fixture.id}-${repetition}`;
        operations.push({
          id,
          op: 'issue',
          seed_b64u: Buffer.from(fixture.key.seed_hex, 'hex').toString('base64url'),
          expected: fixture.expected,
        });
      }
    }

    const label = `credential issue issuer=${issuer}`;
    const response = await invoke(targets[issuer].transfer, operations, label);
    counters.invocations += 1;
    counters.operations += operations.length;
    const results = checkedResults(operations, response, label);
    const byId = new Map(results.map((result) => [result.id, result]));
    issued[issuer] = Object.create(null);

    for (const fixture of fixtures) {
      const first = byId.get(`issue-${fixture.id}-first`);
      const second = byId.get(`issue-${fixture.id}-second`);
      checkIssueResult(first, fixture, `${label} ${fixture.id} first`);
      checkIssueResult(second, fixture, `${label} ${fixture.id} second`);
      if (first.credential_b64u !== second.credential_b64u) {
        throw new TransferCheckFailure(`${issuer} ${fixture.id} repeat export`);
      }
      for (const previousIssuer of LANGS) {
        const previous = issued[previousIssuer]?.[fixture.id];
        if (previous && previous.credential_b64u !== first.credential_b64u) {
          throw new TransferCheckFailure(`${issuer} ${fixture.id} issuer export`);
        }
      }
      issued[issuer][fixture.id] = first;
    }
  }

  for (const issuer of LANGS) {
    for (const client of LANGS) {
      const operations = fixtures.map((fixture) => ({
        id: `handoff-${issuer}-${client}-${fixture.id}`,
        op: 'import-credential',
        document_b64u: issued[issuer][fixture.id].credential_b64u,
        expected: fixture.expected,
        messages_b64u: messages.map((message) => b64u(message.bytes)),
      }));
      const pairLabel = `issuer=${issuer} client=${client}`;
      const label = `credential handoff ${pairLabel}`;
      const response = await invoke(targets[client].transfer, operations, label);
      counters.invocations += 1;
      counters.operations += operations.length;
      const results = checkedResults(operations, response, label);

      for (let index = 0; index < fixtures.length; index += 1) {
        const fixture = fixtures[index];
        const result = results[index];
        checkSignerResult(result, fixture.key, messages, `${label} ${fixture.id}`, fixture.expected);
        counters.credentialHandoffs += 1;
        imported[client].push({ issuer, fixture, result });
      }
      counters.credentialPairs += 1;
      if (typeof report === 'function') await report(`PASS ${pairLabel}`);
    }
  }

  return { issued, imported, counters };
}
