import { b64u, decodeB64u } from './transfer-fixtures.mjs';
import { checkErrorResult, checkPublicResult, checkSignerResult, mutationFromBaseline, TransferCheckFailure } from './transfer-checks.mjs';
import { validateResults } from './transfer-process.mjs';

const LANGS = Object.freeze(['go', 'rust', 'typescript']);
const requireCase = (condition, label) => {
  if (!condition) throw new TransferCheckFailure(label);
};

export async function runRefusalPairs(targets, f, state, { invoke, report }) {
  const measured = { caseVisits: 0, invocations: 0, operations: 0 };
  const messages = f.messages;
  const messageBytes = messages.map((message) => b64u(message.bytes));

  for (const issuer of LANGS) for (const client of LANGS) {
    const pair = `issuer=${issuer} client=${client}`;
    const fixtureById = new Map(f.positives.map((item) => [item.id, item]));
    const importedAlice = state.imported[client].find((entry) =>
      entry.issuer === issuer && entry.fixture.id === 'cred-alice');
    requireCase(Boolean(importedAlice), `${pair} imported cred-alice`);
    const issuedAlice = state.issued[issuer]['cred-alice'];
    requireCase(Boolean(issuedAlice), `${pair} issued cred-alice`);
    const actualCredential = decodeB64u(issuedAlice.credential_b64u);
    const actualPublic = decodeB64u(importedAlice.result.public_envelope_b64u);
    const publicFixture = fixtureById.get('pub-alice');
    const credentialFixture = fixtureById.get('cred-alice');
    requireCase(Boolean(publicFixture && credentialFixture), `${pair} fixture baselines`);

    for (const fixture of f.credentialCases) {
      requireCase(state.imported[client].some((entry) => entry.issuer === issuer && entry.fixture.id === fixture.id),
        `${pair} passed ${fixture.id}`);
    }

    const privateDocuments = Object.create(null);
    for (const id of ['cred-alice', 'cred-bob']) {
      const issued = state.issued[issuer][id];
      requireCase(Boolean(issued), `${pair} issued ${id}`);
      const credential = JSON.parse(decodeB64u(issued.credential_b64u).toString('utf8'));
      privateDocuments[id === 'cred-alice' ? 'priv-alice' : 'priv-bob'] = Buffer.from(credential.client_key, 'utf8');
    }
    const positiveOps = [];
    const positiveMeta = [];
    for (const fixture of f.positives.filter((item) => item.kind === 'private_envelope')) {
      const bytes = privateDocuments[fixture.id] ?? fixture.bytes;
      positiveOps.push({ id: `pos-${fixture.id}`, op: 'import-private', document_b64u: b64u(bytes), messages_b64u: messageBytes });
      positiveMeta.push({ fixture, bytes });
    }
    for (const fixture of f.positives.filter((item) => item.kind === 'public_envelope')) {
      const bytes = fixture.id === 'pub-alice' ? actualPublic : fixture.bytes;
      positiveOps.push({ id: `pos-${fixture.id}`, op: 'import-public', document_b64u: b64u(bytes), role: 'client', verifications: [] });
      positiveMeta.push({ fixture, bytes });
    }
    const positiveLabel = `transfer refusal positives ${pair}`;
    const positiveResults = validateResults(positiveOps, { results: await invoke(targets[client].transfer, positiveOps, positiveLabel) }, positiveLabel);
    measured.invocations += 1;
    measured.operations += positiveOps.length;
    for (let i = 0; i < positiveOps.length; i += 1) {
      const { fixture } = positiveMeta[i];
      if (fixture.kind === 'private_envelope') checkSignerResult(positiveResults[i], fixture.key, messages, `${pair} ${fixture.id}`);
      else checkPublicResult(positiveResults[i], fixture.key, [], `${pair} ${fixture.id}`);
    }

    const baselines = { credential: actualCredential, private: privateDocuments['priv-alice'], public: actualPublic };
    const fixtureBaselines = { credential: credentialFixture.bytes, private: fixtureById.get('priv-alice').bytes, public: publicFixture.bytes };
    const negatives = f.negatives.map((negative, index) => {
      const sink = negative.sink;
      const document = mutationFromBaseline(baselines[sink], fixtureBaselines[sink], negative.bytes, `${pair} ${negative.id}`);
      const common = { id: `neg-${index}`, document_b64u: b64u(document) };
      if (sink === 'credential') return { ...common, op: 'import-credential', expected: f.svcExpected, messages_b64u: messageBytes };
      if (sink === 'private') return { ...common, op: 'import-private', messages_b64u: messageBytes };
      return { ...common, op: 'import-public', role: 'client', verifications: [] };
    });
    const negativeLabel = `transfer refusal negatives ${pair}`;
    const negativeResults = validateResults(negatives, { results: await invoke(targets[client].transfer, negatives, negativeLabel) }, negativeLabel);
    measured.invocations += 1;
    measured.operations += negatives.length;
    for (let i = 0; i < negatives.length; i += 1) checkErrorResult(negativeResults[i], f.negatives[i].expect_class, `${pair} ${f.negatives[i].id}`);

    const context = f.context[0];
    const contextBytes = mutationFromBaseline(actualCredential, credentialFixture.bytes, context.bytes, `${pair} ${context.id}`);
    const contextOps = [
      { id: 'context-refusal', op: 'import-credential', document_b64u: b64u(contextBytes), expected: f.svcExpected, messages_b64u: messageBytes },
      { id: 'context-structural', op: 'import-credential', document_b64u: b64u(contextBytes), expected: context.structuralExpected, messages_b64u: messageBytes },
    ];
    const contextLabel = `transfer refusal context ${pair}`;
    const contextResults = validateResults(contextOps, { results: await invoke(targets[client].transfer, contextOps, contextLabel) }, contextLabel);
    measured.invocations += 1;
    measured.operations += contextOps.length;
    checkErrorResult(contextResults[0], context.trust_outcome, `${pair} ${context.id}`);
    checkSignerResult(contextResults[1], context.key, messages, `${pair} ${context.id} structural`, context.structuralExpected);
    measured.caseVisits += 66;
    if (typeof report === 'function') await report(`PASS shared-table ${pair} cases=66`);
  }
  return measured;
}
