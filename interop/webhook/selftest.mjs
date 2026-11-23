// Self-test for the webhook matrix (contract section 9). It proves what the
// matrix itself cannot: that the relay rewrites exactly the bytes it claims and
// leaves the others alone, that the driver's own verification agrees with the
// independent fakes, that the scenario table and the contract agree on the
// categories and the enqueue expectation, and that the negative controls are
// still negative. The module owns its exit code because interop/webhook.mjs
// falls through to the matrix once it returns.
//
// node interop/webhook.mjs --self-test
import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { BODIES, deriveKeys, emissionHeader, w1Header } from '../tools/fakes/webhook/webhook-sign.mjs';
import * as D from './derive.mjs';
import { loadScenarios, runMatrix } from './matrix.mjs';
import { INFLATED_LENGTH, transformBody, transformHead } from './relay.mjs';
import * as S from './support.mjs';

const HEAD =
  'POST /hooks/alice HTTP/1.1\r\n' +
  'Host: hooks.example.test\r\n' +
  'content-type: application/json\r\n' +
  'webhook-id: msg_7Qk2mZ4rT9xV1bN6pL3sD8wY5cJ\r\n' +
  'webhook-timestamp: 1800000000\r\n' +
  'webhook-signature: v1,AAAA v1a,BBBB\r\n' +
  'X-MCP-Subscription-Id: sub_a3f1c8e2b0d49f7e\r\n' +
  'content-length: 2\r\n' +
  '\r\n';
const HEAD_END = '\r\n\r\n';
const TIMESTAMP = 1800000000;

const headLines = (text) => text.slice(0, -HEAD_END.length).split('\r\n');
const headerLine = (lines, name) => lines.find((line) => line.toLowerCase().startsWith(name + ':'));

function runChild(args, extraEnv) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [join(S.REPO_ROOT, 'interop', 'webhook.mjs'), ...args], {
      cwd: S.REPO_ROOT,
      env: { ...process.env, ...extraEnv },
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    });
    let out = '';
    let err = '';
    child.stdout.on('data', (chunk) => { out += chunk; });
    child.stderr.on('data', (chunk) => { err += chunk; });
    child.on('error', reject);
    child.on('close', (code) => resolve({ code, out, err }));
  });
}

export async function selfTest() {
  const fakeDir = join(S.REPO_ROOT, 'interop', 'tools', 'fakes', 'webhook');
  const fakeSender = join(fakeDir, 'fake-webhook-sender.mjs');
  const fakeReceiver = join(fakeDir, 'fake-webhook-receiver.mjs');
  if (!existsSync(fakeSender)) S.fail(`missing self-test fake: ${fakeSender}`);
  if (!existsSync(fakeReceiver)) S.fail(`missing self-test fake: ${fakeReceiver}`);

  const targets = { fake: { webhook_sender: [process.execPath, fakeSender], webhook_receiver: [process.execPath, fakeReceiver] } };
  const scenarios = loadScenarios();
  const fixtures = S.loadFixtures();
  let checks = 0;
  const ok = (condition, what) => {
    if (!condition) {
      process.stderr.write('self-test failed: ' + what + '\n');
      process.exit(1);
    }
    checks += 1;
    process.stdout.write('self-test: ' + what + '\n');
  };

  const tmp = mkdtempSync(join(tmpdir(), 'mcp-jack-webhook-selftest-'));
  const removeTmp = () => {
    try { rmSync(tmp, { recursive: true, force: true }); } catch { /* best effort */ }
  };
  process.once('exit', removeTmp);
  try {
    const targetsPath = join(tmp, 'targets.json');
    writeFileSync(targetsPath, JSON.stringify(targets));
    ok(scenarios.scenarios['ssrf-private-address'].expected.sender.results[0].last_error === 'ssrf_blocked_address',
      'the private-address row pins ssrf_blocked_address');
    ok(scenarios.scenarios['ssrf-dns-rebinding'].expected.sender.results[0].last_error === 'ssrf_rebinding_blocked',
      'the rebinding row pins ssrf_rebinding_blocked');
    ok(scenarios.scenarios['retry-http-503'].expected.attempts.length === 4,
      'the retry row pins four relay-recorded attempts');
    ok(scenarios.scenarios['dedup-repeated-delivery'].expected.deliveries[1].enqueued === 1
      && scenarios.scenarios['dedup-repeated-delivery'].expected.deliveries[1].forwarded.length === 0,
    'the duplicate row pins the unchanged enqueue count');

    const retryAttempts = scenarios.scenarios['retry-http-503'].expected.attempts;
    ok(retryAttempts.every((attempt) => attempt.signatures.v1.valid === true
      && JSON.stringify(attempt.signature_schemes) === JSON.stringify(['v1'])),
    'every retry attempt carries one valid v1 signature');

    for (const id of ['refuse-tampered-body', 'refuse-tampered-header', 'refuse-body-too-large']) {
      const attempts = scenarios.scenarios[id].expected.attempts;
      ok(attempts.length === 1 && attempts[0].signatures.v1.valid === true,
        `the ${id} row records one attempt the relay saw as validly signed`);
    }

    const enqueueFailed = scenarios.scenarios['retry-enqueue-failed'].expected.deliveries;
    ok(enqueueFailed[0].enqueued === 0 && enqueueFailed[0].forwarded.length === 0,
      'the failed enqueue forwards nothing');
    ok(enqueueFailed[1].enqueued === 1 && enqueueFailed[1].forwarded.length === 1,
      'the retried delivery enqueues and forwards exactly once');

    for (const id of ['verify-challenge', 'verify-challenge-w1']) {
      const deliveries = scenarios.scenarios[id].expected.deliveries;
      ok(deliveries[0].enqueued === 0 && deliveries[0].forwarded.length === 0,
        `the ${id} challenge envelope is never forwarded`);
      ok(deliveries[1].enqueued === 1, `the ${id} event is enqueued once`);
    }

    for (const id of ['ssrf-private-address', 'ssrf-dns-rebinding']) {
      const expected = scenarios.scenarios[id].expected;
      ok(expected.shadow_connections === 0 && expected.attempts.length === 0
        && expected.deliveries.length === 0,
      `the ${id} row opens no shadow connection and records nothing`);
    }

    // ---- 1. relay rewrites, no process needed ----
    const original = headLines(HEAD);
    ok(transformHead(HEAD, 'pass') === HEAD, 'pass returns the head unchanged');

    const tampered = transformHead(HEAD, 'tamper-header');
    const tamperedLines = headLines(tampered);
    ok(tamperedLines.length === original.length
      && headerLine(tamperedLines, 'webhook-id') !== headerLine(original, 'webhook-id')
      && headerLine(tamperedLines, 'webhook-signature') === headerLine(original, 'webhook-signature')
      && tampered.endsWith(HEAD_END), 'tamper-header rewrites the webhook-id line and nothing else');

    const inflated = transformHead(HEAD, 'inflate-length');
    const inflatedLines = headLines(inflated);
    const inflatedLength = (headerLine(inflatedLines, 'content-length') ?? '').toLowerCase();
    ok(inflatedLines.length === original.length && inflatedLength === `content-length: ${INFLATED_LENGTH}`,
      'inflate-length sets the declared length in place');

    const event = Buffer.from(BODIES.event);
    ok(transformBody(event, 'pass').equals(event), 'pass returns the body unchanged');
    const changed = transformBody(event, 'tamper-body');
    ok(changed.length === event.length && changed.includes(Buffer.from('incident.createX')),
      'tamper-body changes one character and keeps the length');
    const plain = Buffer.from('{"a":1}');
    ok(transformBody(plain, 'tamper-body').equals(plain), 'tamper-body leaves a body without the marker unchanged');
    ok(transformHead(HEAD, 'drop') === HEAD && transformBody(event, 'drop').equals(event),
      'drop leaves the request bytes untouched');

    let threw = 0;
    try { transformHead(HEAD, 'nope'); } catch { threw += 1; }
    try { transformBody(event, 'nope'); } catch { threw += 1; }
    ok(threw === 2, 'an unknown preset throws in both rewrites');

    // ---- 2. derivations and the driver's own signature verification ----
    const eventId = D.webhookId('selftest', 0, 'event');
    ok(/^msg_[A-Za-z0-9]{32}$/.test(eventId), 'the derived event id carries the prefix and 32 characters');
    ok(D.webhookId('selftest', 0, 'event') === eventId && D.webhookId('selftest', 1, 'event') !== eventId,
      'the derived id is stable per index and differs across indices');
    ok(D.webhookId('selftest', 0, 'gap').startsWith('msg_gap_'), 'a gap id carries the gap prefix');
    ok(/^sub_[0-9a-f]{16}$/.test(D.subscriptionId(D.callbackUrl(8443))), 'the derived subscription id matches sub_ and 16 hex characters');

    const url = D.callbackUrl(8443);
    const sub = D.subscriptionId(url);
    const secret = D.secretBytes();
    const keys = deriveKeys(fixtures.keysByName.newbie.seed_hex);
    const emission = emissionHeader({
      secret,
      keys: [keys],
      webhookId: eventId,
      timestamp: TIMESTAMP,
      body: D.EVENT_BODY,
      endpointId: sub,
    });
    const entries = D.parseEmission(emission);
    const accepted = D.verifyEmission({
      entries,
      secret,
      keys: [keys.publicKey],
      subscriptionId: sub,
      webhookId: eventId,
      timestamp: TIMESTAMP,
      body: D.EVENT_BODY,
    });
    ok(accepted.v1.present && accepted.v1.valid && accepted.v1a.valid && accepted.v2a.valid,
      'the driver verifies a fake emission with the pinned secret and key');
    ok(JSON.stringify((entries ?? []).map((entry) => entry.scheme)) === JSON.stringify(['v1', 'v1a', 'v2a']),
      'the emission order is v1, v1a, v2a');

    const altered = Buffer.from(D.EVENT_BODY);
    altered[1] = altered[1] ^ 0x20;
    const refused = D.verifyEmission({
      entries,
      secret,
      keys: [keys.publicKey],
      subscriptionId: sub,
      webhookId: eventId,
      timestamp: TIMESTAMP,
      body: altered,
    });
    ok(!refused.v1.valid && !refused.v1a.valid && !refused.v2a.valid, 'a changed body invalidates all three entries');

    const jack = w1Header({
      priv: keys.priv,
      kid: keys.kid,
      aud: D.AUD,
      subscriptionId: sub,
      webhookId: eventId,
      timestamp: TIMESTAMP,
      callbackUrl: url,
      body: D.EVENT_BODY,
    });
    const jackParts = {
      aud: D.AUD,
      subscriptionId: sub,
      webhookId: eventId,
      timestamp: TIMESTAMP,
      callbackUrl: url,
      body: D.EVENT_BODY,
    };
    const w1 = D.verifyW1({ value: jack, keys: [keys.publicKey], parts: jackParts });
    ok(w1.present && w1.valid && w1.kid === keys.kid, 'the driver verifies a fake w1 header with the pinned key');
    const w1OtherUrl = D.verifyW1({ value: jack, keys: [keys.publicKey], parts: { ...jackParts, callbackUrl: url + '/' } });
    ok(!w1OtherUrl.valid, 'a different callback URL invalidates the w1 header');

    // ---- 3. the ordinary in-process matrix run over the fakes ----
    const expectedProcesses = scenarios.order.reduce((sum, id) => sum + 1 + (scenarios.scenarios[id].receiver.start ? 1 : 0), 0);
    const res = await runMatrix({
      senders: ['fake'],
      receivers: ['fake'],
      targets,
      fixtures,
      scenarios,
      scenarioFilter: null,
    });
    ok(res.failures.length === 0, `the in-process fake run has no failures (got ${res.failures.length})`);
    ok(res.skipped.length === 0, 'the fake language declares no gaps');
    ok(res.pairSummaries.length === 1 && res.pairSummaries[0].passed === scenarios.order.length,
      `the fake pair passes all ${scenarios.order.length} scenarios`);
    ok(res.processesSpawned === expectedProcesses,
      `the fake pair spawns one sender and one receiver per run where asked (${expectedProcesses}, got ${res.processesSpawned})`);

    // ---- 4. subprocess controls ----
    const matrixArgs = ['--targets', targetsPath, '--senders', 'fake', '--receivers', 'fake'];

    const deviated = await runChild([...matrixArgs, '--scenario', 'deliver-v1'], { JACK_WEBHOOK_DEVIATE: 'deliver-v1' });
    ok(deviated.code === 1, `a deviating sender exits 1 (got ${deviated.code})`);
    ok(deviated.out.includes('FAIL deliver-v1'), 'a deviating sender fails deliver-v1');

    const noTamper = await runChild(
      [...matrixArgs, '--scenario', 'refuse-tampered-body,dedup-repeated-delivery'],
      { JACK_WEBHOOK_SELFTEST_NO_TAMPER: '1' },
    );
    ok(noTamper.code === 1, `the no-tamper control exits 1 (got ${noTamper.code})`);
    ok(noTamper.out.includes('FAIL refuse-tampered-body'), 'a relay that only passes fails refuse-tampered-body');
    ok(noTamper.out.includes('FAIL dedup-repeated-delivery'), 'a relay that only passes fails dedup-repeated-delivery');

    const listed = await runChild(['--list'], {});
    const listedIds = listed.out.split('\n').map((line) => line.trim()).filter(Boolean);
    ok(listed.code === 0 && JSON.stringify(listedIds) === JSON.stringify(scenarios.order),
      `--list prints exactly the ${scenarios.order.length} scenario ids in order`);

    const roleLessPath = join(tmp, 'roles-targets.json');
    writeFileSync(roleLessPath, JSON.stringify({ fake: { server: ['node', 'x'], client: ['node', 'y'] } }));
    const roleLess = await runChild(['--targets', roleLessPath, '--senders', 'fake', '--receivers', 'fake'], {});
    ok(roleLess.code === 2, `targets without the webhook roles exit 2 (got ${roleLess.code})`);

    const clean = await runChild(matrixArgs, {});
    ok(clean.code === 0, `the clean subprocess run exits 0 (got ${clean.code}; stderr tail: ${clean.err.trim().split('\n').slice(-5).join(' | ')})`);
    ok(clean.out.includes('webhook matrix: all pairs pass'), 'the clean subprocess prints the all-pairs-pass line');
    ok(clean.out.includes('INTEROP-SUMMARY matrix=webhook'), 'the clean subprocess prints the webhook summary line');
  } finally {
    removeTmp();
  }

  process.stdout.write(`self-test: ok (${checks} checks)\n`);
  process.exit(0);
}
