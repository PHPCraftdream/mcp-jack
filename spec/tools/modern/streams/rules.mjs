// spec/tools/modern/streams/rules.mjs
// The client case table and the numbered rule map (spec 05 sections 1-6), with
// the coverage check that every rule is either mapped or exempt.
import { openVectors } from './vectors/vectors-open.mjs';
import { frameVectors } from './vectors/vectors-frames.mjs';
import { CLIENT_CODES } from './reference.mjs';

export const CLIENT_COUNT = 80;

// The client cases in file order; 4.6 takes the first case per code from here.
export const CASES = [...openVectors, ...frameVectors];

// Every numbered rule of sections 1-6, in spec order. A rule is either mapped in
// REQUIREMENTS or in the spec's Exemptions table (EXEMPT), never both.
export const RULES = [
  '1.1', '1.2', '1.3', '1.4',
  '2.1', '2.2', '2.3', '2.4', '2.5', '2.6', '2.7', '2.8', '2.9',
  '2.10', '2.11', '2.12', '2.13', '2.14', '2.15', '2.16', '2.17', '2.18',
  '3.1', '3.2', '3.3', '3.4', '3.5', '3.6', '3.7', '3.8',
  '4.1', '4.2', '4.3', '4.4', '4.5', '4.6', '4.7',
  '5.1', '5.2', '5.3',
  '6.1', '6.2', '6.3',
];

// The spec's Exemptions table, in its order: the rules no stream vector can test
// and an SDK-level test carries instead.
export const EXEMPT = [
  '1.1', '1.2', '1.4',
  '3.1', '3.3', '3.4', '3.5', '3.6', '3.7', '3.8',
  '4.1', '5.1', '6.1',
];

// 4.6: the first client case, in file order, whose terminal code is `code`.
const codeVector = (code) => {
  const hit = CASES.find((c) => c.expect.terminal.code === code);
  if (hit === undefined) throw new Error(`no client case ends in ${code}`);
  return hit.id;
};

// Rule id -> the vectors that cover it (positives included) and one line of what
// the rule requires. The thirteen exempt rules are deliberately absent.
export const REQUIREMENTS = {
  '1.3': {
    vectors: ['stream-open-splice'],
    requirement: 'v1 bytes unchanged; the open binds the request sig',
  },
  '2.1': {
    vectors: ['stream-open-missing-auth', 'stream-open-duplicate-auth'],
    requirement: 'the open header is present exactly once',
  },
  '2.2': {
    vectors: ['stream-open-extra-param', 'stream-open-bad-sid'],
    requirement: 'open parameter set and encodings',
  },
  '2.3': {
    vectors: ['stream-open-scheme-s2', 'stream-open-scheme-v1'],
    requirement: 'scheme precedence on the raw value',
  },
  '2.4': {
    vectors: ['stream-open-bad-sid', 'stream-frame-wrong-sid'],
    requirement: 'sid is 16 bytes and names the stream',
  },
  '2.5': {
    vectors: ['stream-open-bad-signature', 'stream-open-splice', 'build-open'],
    requirement: 'open signing string, six lines',
  },
  '2.6': {
    vectors: ['stream-ok-single', 'stream-ok-many', 'stream-ok-no-event-field', 'build-three-frames'],
    requirement: 'one JSON-RPC message per frame; event defaults to message',
  },
  '2.7': {
    vectors: ['stream-frame-extra-jack-param', 'stream-frame-double-jack'],
    requirement: 'jack field grammar, exactly one jack line',
  },
  '2.8': {
    vectors: ['stream-frame-unknown-event'],
    requirement: 'event value is message or jack-end',
  },
  '2.9': {
    vectors: ['stream-frame-end-with-data', 'stream-frame-message-empty-data'],
    requirement: 'frame kind follows the emptiness of the data',
  },
  '2.10': {
    vectors: [
      'stream-ok-multiline-data',
      'stream-ok-unicode',
      'stream-frame-invalid-utf8',
      'build-multiline',
      'build-unicode',
    ],
    requirement: 'data lines join with LF and are UTF-8',
  },
  '2.11': {
    vectors: ['stream-frame-id-field', 'stream-frame-retry-field'],
    requirement: 'id and retry are forbidden',
  },
  '2.12': {
    vectors: ['stream-ok-comments'],
    requirement: 'comments are ignored and unsigned',
  },
  '2.13': {
    vectors: ['stream-ok-unknown-field'],
    requirement: 'unknown fields are ignored',
  },
  '2.14': {
    vectors: ['stream-ok-crlf', 'stream-truncated-mid-frame'],
    requirement: 'line endings and one leading BOM',
  },
  '2.15': {
    vectors: [
      'build-single-frame',
      'build-three-frames',
      'build-long-ts',
      'stream-frame-bad-signature',
      'stream-frame-wrong-sid',
      'stream-frame-tampered-data',
    ],
    requirement: 'frame signing string, hash chain and data hash',
  },
  '2.16': {
    vectors: ['build-only-end', 'stream-ok-only-end', 'stream-frame-after-end', 'stream-truncated-no-end'],
    requirement: 'the end frame and nothing after it',
  },
  '2.17': {
    vectors: ['stream-ok-frame-max-boundary', 'stream-frame-oversize', 'stream-frame-oversize-late'],
    requirement: 'frame size is counted from the first field line',
  },
  '2.18': {
    vectors: [
      'stream-signal-too-large',
      'stream-ok-signal-lookalike-method',
      'stream-ok-signal-lookalike-extra',
      'stream-ok-signal-lookalike-code',
      'stream-ok-signal-lookalike-limit',
      'stream-signal-limit-zero',
      'stream-ok-signal-lookalike-limit-exp',
      'stream-ok-signal-lookalike-limit-decimal',
      'stream-ok-signal-lookalike-limit-leading-zero',
      'stream-ok-signal-lookalike-whitespace',
      'stream-ok-signal-lookalike-code-type',
      'build-oversize-error-frame',
    ],
    requirement: 'a verified transport signal ends the stream undelivered',
  },
  '3.2': {
    vectors: ['build-oversize-error-frame', 'stream-frame-oversize'],
    requirement: 'the oversize notification becomes a signed transport error frame',
  },
  '4.2': {
    vectors: [
      'stream-open-missing-auth', 'stream-open-duplicate-auth', 'stream-open-extra-param',
      'stream-open-bad-sid', 'stream-open-scheme-s2', 'stream-open-scheme-v1',
      'stream-open-unknown-kid', 'stream-open-wrong-key', 'stream-open-ts-old',
      'stream-open-ts-future', 'stream-open-cutoff', 'stream-open-bad-signature',
      'stream-open-splice',
    ],
    requirement: 'open steps 1-7: presence, grammar, scheme, kid, window, cutoff, signature',
  },
  '4.3': {
    vectors: [
      'stream-frame-id-field', 'stream-frame-retry-field', 'stream-frame-extra-jack-param',
      'stream-frame-double-jack', 'stream-frame-unknown-event', 'stream-frame-end-with-data',
      'stream-frame-message-empty-data', 'stream-frame-invalid-utf8', 'stream-frame-oversize',
      'stream-frame-seq-first-not-zero', 'stream-frame-seq-gap', 'stream-frame-seq-repeat',
      'stream-frame-seq-reorder', 'stream-frame-ts-regress', 'stream-frame-ts-stale',
      'stream-frame-after-cutoff', 'stream-signal-too-large', 'stream-stdio-raw-lf',
      'stream-ok-signal-lookalike-code',
      // positives: the reassembled body and the per-frame clock of step 3
      'stream-ok-byte-split', 'stream-ok-window-boundary', 'stream-ok-long-stream',
    ],
    requirement: 'frame steps 1-6 over the reassembled body and the sampled clock',
  },
  '4.4': {
    vectors: ['stream-truncated-no-end', 'stream-truncated-empty-body', 'stream-truncated-mid-frame'],
    requirement: 'truncation and partial delivery',
  },
  '4.5': {
    vectors: [
      'stream-idle-timeout',
      'stream-idle-boundary-alive',
      'stream-idle-heartbeat',
      'stream-idle-open-silence',
      'stream-idle-bom-late-chunk',
      'stream-idle-blank-line-late-chunk',
      'stream-idle-comment-silence',
    ],
    requirement: 'idle timeout counted from the last verified frame',
  },
  // 4.6 is computed: the first client case that ends in each code of the list.
  '4.6': {
    vectors: CLIENT_CODES.map(codeVector),
    requirement: 'the closed list of thirteen client codes, each reached once',
  },
  '4.7': {
    vectors: ['stream-frame-tampered-data', 'stream-frame-bad-signature', 'stream-stdio-raw-lf'],
    requirement: 'verify a frame before parsing its JSON',
  },
  '5.2': {
    vectors: [
      'stream-open-cutoff', 'stream-frame-after-cutoff', 'stream-frame-end-after-cutoff',
      'stream-ok-cutoff-below',
    ],
    requirement: 'client cutoff rejection at or after the successor activation',
  },
  '5.3': {
    vectors: ['stream-frame-after-cutoff', 'stream-ok-cutoff-below'],
    requirement: 'no re-signing, no kid switch, no continuation',
  },
  '6.2': {
    vectors: ['stream-stdio-ok', 'stream-stdio-raw-lf', 'stream-stdio-signal'],
    requirement: 'one stdout line per verified message frame',
  },
  '6.3': {
    vectors: [
      'stream-close-with-result',
      'stream-close-without-result',
      'stream-close-lookalike-wrong-id',
      'stream-close-lookalike-no-jsonrpc',
      'stream-close-lookalike-both',
      'stream-close-lookalike-id-type',
      'stream-close-no-end-frame',
    ],
    requirement: 'the final JSON-RPC response is the last message frame',
  },
};

export function checkRequirements(clientIds, buildIds) {
  const all = new Set([...clientIds, ...buildIds]);
  if (EXEMPT.length !== 13) throw new Error(`EXEMPT must name 13 rules, got ${EXEMPT.length}`);
  const exempt = new Set();
  for (const rule of EXEMPT) {
    if (exempt.has(rule)) throw new Error(`${rule}: listed twice in EXEMPT`);
    if (!RULES.includes(rule)) throw new Error(`${rule}: exempt rule is not in RULES`);
    exempt.add(rule);
  }
  const mapped = new Set();
  for (const [rule, { vectors }] of Object.entries(REQUIREMENTS)) {
    if (!RULES.includes(rule)) throw new Error(`${rule}: mapped rule is not in RULES`);
    if (exempt.has(rule)) throw new Error(`${rule}: both mapped and exempt`);
    if (vectors.length === 0) throw new Error(`${rule}: no vector`);
    const seen = new Set();
    for (const id of vectors) {
      if (seen.has(id)) throw new Error(`${rule}: ${id} is listed twice`);
      seen.add(id);
      if (!all.has(id)) throw new Error(`${rule}: ${id} is not a case`);
    }
    mapped.add(rule);
  }
  for (const rule of RULES) {
    if (!exempt.has(rule) && !mapped.has(rule)) throw new Error(`${rule}: neither mapped nor exempt`);
  }
  const listed = new Set(Object.values(REQUIREMENTS).flatMap((r) => r.vectors));
  for (const id of all) {
    if (!listed.has(id)) throw new Error(`${id}: no rule lists it`);
  }
}
