import { b64u } from './transfer-fixtures.mjs';
import {
  checkErrorResult, checkPublicResult, checkSignerResult, TransferCheckFailure, verificationControls,
} from './transfer-checks.mjs';
import { validateResults } from './transfer-process.mjs';

const LANGS = Object.freeze(['go', 'rust', 'typescript']);
const PEOPLE = Object.freeze(['alice', 'bob', 'carol']);
const requireCheck = (condition, label) => {
  if (!condition) throw new TransferCheckFailure(label);
};

export async function runPublicPairs(targets, f, state, { invoke, report } = {}) {
  const counters = { publicPairs: 0, publicExports: 0, invocations: 0, operations: 0 };
  const messages = f.messages;
  const encodedMessages = messages.map((message) => b64u(message.bytes));
  const publicNegatives = f.negatives.filter((fixture) => fixture.sink === 'public');
  const recordsByClient = Object.create(null);

  for (const client of LANGS) {
    const operations = [{ id: `generate-${client}`, op: 'generate', messages_b64u: encodedMessages }];
    for (const person of PEOPLE) operations.push({
      id: `seed-${client}-${person}`, op: 'from-seed',
      seed_b64u: b64u(Buffer.from(f.keys[person].seed_hex, 'hex')), messages_b64u: encodedMessages,
    });
    const label = `public signer exports client=${client}`;
    const results = validateResults(operations, { results: await invoke(targets[client].transfer, operations, label) }, label);
    counters.invocations += 1;
    counters.operations += operations.length;
    const records = results.map((result, index) => {
      const person = PEOPLE[index - 1];
      checkSignerResult(result, person ? f.keys[person] : null, messages, `${label} ${operations[index].id}`);
      return result;
    });
    requireCheck(state.imported[client]?.length === 21, `credential signer exports client=${client}`);
    records.push(...state.imported[client].map((entry) => entry.result));
    requireCheck(records.length === 25, `public export count client=${client}`);
    recordsByClient[client] = records;
  }

  for (const client of LANGS) for (const server of LANGS) {
    const records = recordsByClient[client];
    const operations = records.map((signer, index) => {
      const wrongSeed = signer.public_key === f.keys.bob.public_key ? f.keys.alice.seed_hex : f.keys.bob.seed_hex;
      const controls = verificationControls(signer, messages, wrongSeed);
      return {
        id: `public-${client}-${server}-${index}`, op: 'import-public',
        document_b64u: signer.public_envelope_b64u, role: 'server', verifications: controls.verifications,
      };
    });
    for (const [index, fixture] of publicNegatives.entries()) operations.push({
      id: `public-neg-${client}-${server}-${index}`, op: 'import-public',
      document_b64u: b64u(fixture.bytes), role: 'server', verifications: [],
    });
    const label = `public handoff client=${client} server=${server}`;
    const results = validateResults(operations, { results: await invoke(targets[server].transfer, operations, label) }, label);
    counters.invocations += 1;
    counters.operations += operations.length;
    for (let index = 0; index < records.length; index += 1) {
      const signer = records[index];
      const identity = { public_key: signer.public_key, kid: signer.kid };
      checkPublicResult(results[index], identity, verificationControls(signer, messages,
        signer.public_key === f.keys.bob.public_key ? f.keys.alice.seed_hex : f.keys.bob.seed_hex).verdicts,
      `${label} export=${index}`);
      counters.publicExports += 1;
    }
    for (let index = 0; index < publicNegatives.length; index += 1) {
      checkErrorResult(results[records.length + index], publicNegatives[index].expect_class,
        `${label} ${publicNegatives[index].id}`);
    }
    counters.publicPairs += 1;
    if (typeof report === 'function') await report(`PASS client=${client} server=${server} public-exports=${records.length}`);
  }
  return counters;
}
