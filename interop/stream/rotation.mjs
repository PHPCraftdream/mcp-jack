// rotation-stream lifecycle: announce evidence, cutoff injection, successor reopen over two client invocations.
import { sign, createPrivateKey, createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';

const keyFromSeed = seed => createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(seed, 'hex')]), format: 'der', type: 'pkcs8' });
const requireSingleTerminal = (records, label) => {
  const terminals = records.filter(record => record?.type === 'terminal');
  if (terminals.length !== 1 || records.at(-1) !== terminals[0]) throw Error(`${label} must end with exactly one terminal record`);
  if (records.slice(0, -1).some(record => record?.type !== 'message')) throw Error(`${label} contains a non-message record before its terminal`);
  return terminals[0];
};
const recordsToMessages = records => records.filter(record => record?.type === 'message').map(record => (typeof record.data === 'string' ? JSON.parse(record.data) : record.message));

export async function runRotationScenario(ctx) {
  const { scenario, activation, clock } = ctx;
  const data = JSON.stringify({ jsonrpc: '2.0', method: 'notifications/jack/stream_error', params: { code: 'stream_after_cutoff' } });
  const previous = Buffer.alloc(64).toString('base64url');
  const digest = createHash('sha256').update(Buffer.from(data, 'utf8')).digest('base64url');
  const text = ['mcp-jack/stream1/frame', scenario.sid, '0', String(activation), previous, digest].join('\n');
  const sig = sign(null, Buffer.from(text, 'utf8'), keyFromSeed(ctx.svc.seed_hex)).toString('base64url');
  const cutoffFrame = Buffer.from(`event: message\ndata: ${data}\njack: seq=0,ts=${activation},sig=${sig}\n\n`, 'latin1');
  let relay, first, second;
  try {
    relay = await ctx.startRelay({ upstreamPort: ctx.upstreamPort, transform: 'after-cutoff', scenario: { ...scenario, relayCutoffFrame: cutoffFrame, relayCutoffSid: scenario.sid } });
    const firstArgs = ctx.clientArgs.map((value, index) => (index > 0 && ctx.clientArgs[index - 1] === '--url' ? `http://127.0.0.1:${relay.port}` : value));
    firstArgs.push('--known-server-key', `kid=${ctx.erin.kid},public=${ctx.erin.public_key},activation=${activation}`);
    first = ctx.launchResolved(ctx.resolvedTargets[`${ctx.client}:client`], firstArgs);
    const firstResult = await first.done;
    if (firstResult.code !== 0) throw Error(`rotation cutoff client exit ${firstResult.code}: ${firstResult.stderr}`);
    const firstRecords = ctx.parseJsonLines(firstResult.stdout);
    const firstTerminal = requireSingleTerminal(firstRecords, 'cutoff stream');
    for (const record of firstRecords) ctx.verifyRecord(record, scenario.request_id);
    if (firstTerminal.outcome !== 'error' || firstTerminal.code !== 'stream_after_cutoff') throw Error(`cutoff stream terminal is ${firstTerminal.outcome}/${firstTerminal.code}, expected error/stream_after_cutoff`);
    if (!firstTerminal.failure_frame || !Number.isSafeInteger(firstTerminal.failure_frame.ts) || firstTerminal.failure_frame.ts < activation) throw Error('cutoff stream lacks failure-frame evidence at/after activation');
    if (!relay.applied()) throw Error("relay transform 'after-cutoff' was not applied");
    writeFileSync(ctx.clockFile, `${activation}\n`);
    const reopenNonce = ctx.deterministicVariant(scenario.nonce, 'reopen');
    const reopenSid = ctx.deterministicVariant(scenario.sid, 'reopen');
    const secondArgs = [...firstArgs];
    secondArgs.splice(secondArgs.indexOf('--nonce') + 1, 1, reopenNonce);
    secondArgs.splice(secondArgs.indexOf('--sid') + 1, 1, reopenSid);
    second = ctx.launchResolved(ctx.resolvedTargets[`${ctx.client}:client`], secondArgs);
    const secondResult = await second.done;
    if (secondResult.code !== 0) throw Error(`rotation reopen client exit ${secondResult.code}: ${secondResult.stderr}`);
    const secondRecords = ctx.parseJsonLines(secondResult.stdout);
    const secondTerminal = requireSingleTerminal(secondRecords, 'reopened stream');
    for (const record of secondRecords) ctx.verifyRecord(record, scenario.request_id);
    if (!secondRecords.some(record => record?.type === 'message' && record.open?.kid === ctx.erin.kid)) throw Error(`reopened stream was not signed by successor ${ctx.erin.kid}`);
    const rows = ctx.readRows(ctx.requestLog);
    if (!rows.some(row => row.event === 'rotation_announced' && row.published_at === clock && row.activates_at === activation && typeof row.head_hash === 'string')) throw Error('rotation request log lacks the validated announce record');
    if (!rows.some(row => row.request_verified === true && row.nonce === scenario.nonce) || !rows.some(row => row.request_verified === true && row.nonce === reopenNonce)) throw Error('rotation request log lacks verified rows for both client invocations');
    const actual = { old: { messages: recordsToMessages(firstRecords), terminal: firstTerminal }, reopened: { messages: recordsToMessages(secondRecords), terminal: secondTerminal } };
    if (!ctx.scenarioSubset(actual, scenario.expected)) throw Error(`rotation oracle mismatch expected=${JSON.stringify(scenario.expected)} actual=${JSON.stringify(actual)}`);
    if (scenario.expected.reopened.open_kid !== ctx.erin.kid) throw Error('rotation oracle open_kid does not match the announced successor');
    console.log(`PASS ${scenario.id}`);
    return true;
  } finally {
    if (first) await ctx.stopChild(first);
    if (second) await ctx.stopChild(second);
    if (relay) await relay.close();
  }
}
