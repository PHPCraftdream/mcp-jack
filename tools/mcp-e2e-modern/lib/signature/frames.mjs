import { createHash, createPublicKey, verify } from 'node:crypto';

const decode = (value) => Buffer.from(value, 'base64url');
const keyFor = (value) => createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), decode(value)]), format: 'der', type: 'spki' });
const authParams = (header, scheme) => {
  if (typeof header !== 'string' || !header.startsWith(`${scheme} `)) return null;
  const result = {};
  for (const pair of header.slice(scheme.length + 1).split(',')) {
    const match = /^([a-z]+)=([A-Za-z0-9_-]+)$/.exec(pair);
    if (!match || Object.hasOwn(result, match[1])) return null;
    result[match[1]] = match[2];
  }
  return result;
};
function splitFrames(frames) {
  return frames.flatMap((item) => String(typeof item === 'string' ? item : item?.body ?? '').split(/(?:\r\n|\n|\r)(?:\r\n|\n|\r)/).filter((frame) => frame.trim()));
}
export function verifyStreamFrames({ openHeader, frames = [], serverPublicKeyBase64Url, requestSig, status = 200, expectedKid } = {}) {
  const fail = (reason, index = 0, verified = 0) => ({ ok: false, reason, frames: splitFrames(frames).length, verified, failedIndex: index, endSeen: false });
  try {
    const open = authParams(openHeader, 's1');
    if (!open || Object.keys(open).sort().join(',') !== 'kid,sid,sig,ts' || open.kid.length !== 43 || decode(open.kid).length !== 32 || open.sid.length !== 22 || decode(open.sid).length !== 16 || open.sig.length !== 86 || decode(open.sig).length !== 64 || !/^(0|[1-9][0-9]{0,11})$/.test(open.ts) || !Number.isInteger(status) || typeof requestSig !== 'string' || !/^[A-Za-z0-9_-]+$/.test(requestSig)) return fail('bad_open_header');
    if (expectedKid !== undefined && open.kid !== expectedKid) return fail('unknown_server_key');
    const publicKey = keyFor(serverPublicKeyBase64Url);
    const openString = ['mcp-jack/stream1/open', String(status), requestSig, open.kid, open.ts, open.sid].join('\n');
    if (!verify(null, Buffer.from(openString), publicKey, decode(open.sig))) return fail('bad_open_signature');
    const list = splitFrames(frames);
    let previous = open.sig;
    let endSeen = false;
    for (let index = 0; index < list.length; index += 1) {
      const lines = list[index].replace(/^\uFEFF/, '').split(/\r?\n/).filter((line) => !line.startsWith(':'));
      const events = lines.filter((line) => line.startsWith('event:'));
      const dataLines = lines.filter((line) => line.startsWith('data:'));
      const jacks = lines.filter((line) => line.startsWith('jack:'));
      if (events.length > 1 || jacks.length !== 1 || lines.some((line) => /^(id|retry)(:|$)/.test(line))) return fail('bad_frame', index, index);
      const event = events.length ? events[0].slice(6).replace(/^ /, '') : 'message';
      if (!['message', 'jack-end'].includes(event)) return fail('bad_frame', index, index);
      const params = authParams(`j ${jacks[0].slice(5).replace(/^ /, '')}`, 'j');
      if (!params || Object.keys(params).sort().join(',') !== 'seq,sig,ts' || !/^(0|[1-9][0-9]{0,14})$/.test(params.seq) || !/^[0-9]{1,12}$/.test(params.ts)) return fail('bad_frame', index, index);
      if (Number(params.seq) !== index) return fail('bad_seq', index, index);
      const data = dataLines.map((line) => line.slice(5).replace(/^ /, '')).join('\n');
      if ((event === 'message' && !data) || (event === 'jack-end' && data)) return fail('bad_frame', index, index);
      const hash = createHash('sha256').update(Buffer.from(data, 'utf8')).digest('base64url');
      const signing = ['mcp-jack/stream1/frame', open.sid, params.seq, params.ts, previous, hash].join('\n');
      if (!verify(null, Buffer.from(signing), publicKey, decode(params.sig))) return fail('bad_signature', index, index);
      previous = params.sig;
      if (event === 'jack-end') { if (index !== list.length - 1) return fail('frame_after_end', index, index + 1); endSeen = true; }
    }
    return { ok: list.length > 0 && endSeen, reason: list.length && endSeen ? 'verified' : 'missing_end', frames: list.length, verified: list.length, endSeen };
  } catch { return fail('malformed_evidence'); }
}
