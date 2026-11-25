// rotation-stream lifecycle: announce evidence, chained cutoff injection, successor reopen over two client invocations.
import { sign, createHash, createPrivateKey } from 'node:crypto';
import { writeFileSync } from 'node:fs';

const keyFromSeed = seed => createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(seed, 'hex')]), format: 'der', type: 'pkcs8' });
const sha256 = bytes => createHash('sha256').update(bytes).digest('base64url');
const b64 = bytes => Buffer.from(bytes).toString('base64url');
const canonicalSid = value => typeof value === 'string' && /^[A-Za-z0-9_-]+$/.test(value) && Buffer.from(value, 'base64url').length === 16 && b64(Buffer.from(value, 'base64url')) === value;
const requireSingleTerminal = (records, label) => {
  const terminals = records.filter(record => record?.type === 'terminal');
  if (terminals.length !== 1 || records.at(-1) !== terminals[0]) throw Error(`${label} must end with exactly one terminal record`);
  if (records.slice(0, -1).some(record => record?.type !== 'message')) throw Error(`${label} contains a non-message record before its terminal`);
  return terminals[0];
};
const recordsToMessages = records => records.filter(record => record?.type === 'message').map(record => (typeof record.data === 'string' ? JSON.parse(record.data) : record.message));

export async function runRotationScenario(ctx) {
  const { scenario, activation, clock, erin } = ctx;
  let observedSid = null;
  // Called by the relay at injection time so seq/prev bind to the live chain and the
  // frame is signed by the predecessor key only after they are fixed.
  const signCutoff = ({ sid, seq, prev }) => {
    if (sid !== observedSid || !Number.isSafeInteger(seq) || seq < 0 || typeof prev !== 'string' || !prev) throw Error(`cutoff injection chain mismatch sid=${sid} seq=${seq}`);
    const data = JSON.stringify({ jsonrpc: '2.0', method: 'notifications/jack/stream_error', params: { code: 'stream_after_cutoff' } });
    const text = ['mcp-jack/stream1/frame', sid, String(seq), String(activation), prev, sha256(Buffer.from(data, 'utf8'))].join('\n');
    const sig = sign(null, Buffer.from(text, 'utf8'), keyFromSeed(ctx.svc.seed_hex)).toString('base64url');
    return Buffer.from(`event: message\ndata: ${data}\njack: seq=${seq},ts=${activation},sig=${sig}\n\n`, 'latin1');
  };
  const knownServerKey = `kid=${erin.kid},public=${erin.public_key},activation=${activation}`;
  let relay, first, second;
  try {
    relay = await ctx.startRelay({ upstreamPort: ctx.upstreamPort, transform: 'after-cutoff', scenario: { ...scenario, relayCutoffSign: signCutoff } });
    // Old stream: through the cutoff relay, predecessor identity, shared clock still at publish P.
    const firstArgs = ctx.clientArgs.map((value, index) => (index > 0 && ctx.clientArgs[index - 1] === '--url' ? `http://127.0.0.1:${relay.port}` : value));
    firstArgs.push('--known-server-key', knownServerKey);
    first = ctx.launchResolved(ctx.resolvedTargets[`${ctx.client}:client`], firstArgs);
    const firstRecords = [];
    for (let i = 0; i < 2; i++) {
      let record;
      try { record = JSON.parse(await first.nextLine(10000)); } catch (error) { throw Error(`rotation old-stream record ${i + 1} is unreadable: ${error.message}: client stderr: ${String(first.stderr).slice(-1500)}`); }
      if (record?.type !== 'message') throw Error(`rotation old-stream record ${i + 1} is ${record?.type}, expected a delivered message before the cutoff`);
      firstRecords.push(record);
    }
    for (const record of firstRecords) ctx.verifyRecord(record, scenario.request_id);
    const observedSids = firstRecords.map(record => record?.open?.sid);
    if (!observedSids.every(canonicalSid)) throw Error('rotation old-stream records lack a canonical 16-byte base64url open sid');
    if (new Set(observedSids).size !== 1) throw Error('rotation old-stream open sid is not consistent across records');
    observedSid = observedSids[0];
    // Cutoff: advance the shared clock to A, then release the server hold so the end
    // frame crosses (and is replaced) while the client clock reads A.
    writeFileSync(ctx.clockFile, `${activation}\n`);
    ctx.server.write(`${JSON.stringify({ action: 'release' })}\n`);
    let releaseAck;
    try { releaseAck = JSON.parse(await ctx.server.nextLine(10000)); } catch { throw Error('rotation server did not acknowledge the held-stream release'); }
    if (releaseAck?.control !== 'released' || releaseAck.sid !== observedSid) throw Error('rotation release acknowledgement does not match the held old stream');
    const firstResult = await first.done;
    if (firstResult.code !== 0) throw Error(`rotation cutoff client exit ${firstResult.code}: ${firstResult.stderr}`);
    const firstAll = ctx.parseJsonLines(firstResult.stdout);
    if (firstAll.length !== firstRecords.length + 1) throw Error('rotation old-stream emitted records beyond its two messages and terminal');
    const firstTerminal = requireSingleTerminal(firstAll, 'cutoff stream');
    if (firstTerminal.outcome !== 'error' || firstTerminal.code !== 'stream_after_cutoff') throw Error(`cutoff stream terminal is ${firstTerminal.outcome}/${firstTerminal.code}, expected error/stream_after_cutoff`);
    if (!firstTerminal.failure_frame || !Number.isSafeInteger(firstTerminal.failure_frame.ts) || firstTerminal.failure_frame.ts < activation) throw Error('cutoff stream lacks failure-frame evidence at/after activation');
    for (const record of firstAll) ctx.verifyRecord(record, scenario.request_id);
    if (!relay.applied()) throw Error("relay transform 'after-cutoff' was not applied");
    // Reopen: same logical request straight to the server (never through the cutoff relay),
    // successor identity, clock already at A.
    const reopenNonce = ctx.deterministicVariant(scenario.nonce, 'reopen');
    const reopenSid = ctx.deterministicVariant(scenario.sid, 'reopen');
    const secondArgs = ctx.clientArgs.map((value, index) => {
      if (index > 0 && ctx.clientArgs[index - 1] === '--url') return `http://127.0.0.1:${ctx.upstreamPort}`;
      if (index > 0 && ctx.clientArgs[index - 1] === '--nonce') return reopenNonce;
      if (index > 0 && ctx.clientArgs[index - 1] === '--sid') return reopenSid;
      return value;
    });
    secondArgs.push('--known-server-key', knownServerKey);
    second = ctx.launchResolved(ctx.resolvedTargets[`${ctx.client}:client`], secondArgs);
    const secondResult = await second.done;
    if (secondResult.code !== 0) throw Error(`rotation reopen client exit ${secondResult.code}: ${secondResult.stderr}`);
    const secondRecords = ctx.parseJsonLines(secondResult.stdout);
    const secondTerminal = requireSingleTerminal(secondRecords, 'reopened stream');
    if (secondTerminal.outcome !== 'complete') throw Error(`reopened stream terminal is ${secondTerminal.outcome}/${secondTerminal.code}, expected complete under ${erin.kid}`);
    for (const record of secondRecords) ctx.verifyRecord(record, scenario.request_id);
    if (!secondRecords.some(record => record?.type === 'message' && record.open?.kid === erin.kid)) throw Error(`reopened stream was not opened under successor ${erin.kid}`);
    const rows = ctx.readRows(ctx.requestLog);
    if (!rows.some(row => row.event === 'rotation_announced' && row.published_at === clock && row.activates_at === activation && typeof row.head_hash === 'string')) throw Error('rotation request log lacks the validated announce record');
    if (!rows.some(row => row.request_verified === true && row.nonce === scenario.nonce) || !rows.some(row => row.request_verified === true && row.nonce === reopenNonce)) throw Error('rotation request log lacks verified rows for both client invocations');
    const actual = { old: { messages: recordsToMessages(firstAll.slice(0, -1)), terminal: firstTerminal }, reopened: { messages: recordsToMessages(secondRecords.slice(0, -1)), terminal: secondTerminal } };
    if (!ctx.scenarioSubset(actual, scenario.expected)) throw Error(`rotation oracle mismatch expected=${JSON.stringify(scenario.expected)} actual=${JSON.stringify(actual)}`);
    console.log(`PASS ${scenario.id}`);
    return true;
  } finally {
    if (first) await ctx.stopChild(first);
    if (second) await ctx.stopChild(second);
    if (relay) await relay.close();
  }
}
