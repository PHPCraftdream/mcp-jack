// Vectors for spec/06-webhooks.md section 5 (R5.1-R5.12), endpoint verification of a callback url.
import {
  acceptEcho,
  allowlistMatches,
  b64u,
  challengeEcho,
  checkDelivery,
  checkReceiverDocFetch,
  checkUrl,
  docCacheTtl,
  nonceOk,
  parseAllowlistEntry,
  parseReceiverDoc,
  receiverDocCovers,
  receiverDocRequest,
  sha256,
  verificationRoute,
  wellKnownUrl,
} from '../reference.mjs';

export const file = 'webhook-endpoint-verification-vectors.json';

const NONCE = b64u(sha256('challenge:1').subarray(0, 16));
const HOOK = 'https://hooks.example.test/hooks/alice';
const DOC = '{"receivers":["/hooks/"]}';
const PAIR = ['alice', HOOK];

const NONCE_SHORT = NONCE.slice(0, 21);
const NONCE_LONG = `${NONCE}A`;
const NONCE_PLUS = '+'.repeat(22);
const NONCE_OTHER = 'A'.repeat(22);
const ECHO_BODY = `{"challenge":"${NONCE}"}`;
const ECHO_BODY_OTHER = `{"challenge":"${NONCE_OTHER}"}`;
const BIG_BODY = 'x'.repeat(5000);
const DOC_EXACT = '{"receivers":["/hooks"]}';
const DOC_ROOT = '{"receivers":["/"]}';
const DOC_TOO_MANY = JSON.stringify({ receivers: Array.from({ length: 65 }, (unused, index) => `/r${index}`) });
const WELL_KNOWN = 'https://hooks.example.test/.well-known/mcp-webhook-receiver.json';
const WELL_KNOWN_PORT = 'https://hooks.example.test:8443/.well-known/mcp-webhook-receiver.json';
const ENTRY = 'https://hooks.example.test/hooks';
const WILDCARD_ENTRY = 'https://*.example.test/hooks';
// R5.9: a valid document padded with a `pad` string to an exact byte length, so the size cap is the only finding.
const paddedDoc = (bytes) => {
  const pad = bytes - Buffer.byteLength(JSON.stringify({ receivers: ['/hooks/'], pad: '' }), 'utf8');
  return JSON.stringify({ receivers: ['/hooks/'], pad: 'x'.repeat(pad) });
};
const DOC_8192 = paddedDoc(8192);
const DOC_8193 = paddedDoc(8193);

export const cases = [
  // R5.1: nothing is delivered before the pair is verified; the challenge POST itself is not a delivery.
  { id: 'ep-gate-verified-verification', rule: 'R5.1', description: 'a verified pair still sends the challenge for the verification message', kind: 'gate', input: { verified: true, message: 'verification' }, expect: { action: 'send-challenge' } },
  { id: 'ep-gate-verified-event', rule: 'R5.1', description: 'a verified pair delivers an event', kind: 'gate', input: { verified: true, message: 'event' }, expect: { action: 'deliver' } },
  { id: 'ep-gate-verified-gap', rule: 'R5.1', description: 'a verified pair delivers a gap notification', kind: 'gate', input: { verified: true, message: 'gap' }, expect: { action: 'deliver' } },
  { id: 'ep-gate-verified-terminated', rule: 'R5.1', description: 'a verified pair delivers a terminated notification', kind: 'gate', input: { verified: true, message: 'terminated' }, expect: { action: 'deliver' } },
  { id: 'ep-gate-unverified-verification', rule: 'R5.1', description: 'an unverified pair sends the challenge for the verification message', kind: 'gate', input: { verified: false, message: 'verification' }, expect: { action: 'send-challenge' } },
  { id: 'ep-gate-unverified-event', rule: 'R5.1', description: 'an unverified pair refuses an event', kind: 'gate', input: { verified: false, message: 'event' }, expect: { action: 'refuse' } },
  { id: 'ep-gate-unverified-gap', rule: 'R5.1', description: 'an unverified pair refuses a gap notification', kind: 'gate', input: { verified: false, message: 'gap' }, expect: { action: 'refuse' } },
  { id: 'ep-gate-unverified-terminated', rule: 'R5.1', description: 'an unverified pair refuses a terminated notification', kind: 'gate', input: { verified: false, message: 'terminated' }, expect: { action: 'refuse' } },

  // R5.2: cache, allowlist, out-of-band hook, well-known document, challenge; first success wins.
  { id: 'ep-route-cache-first', rule: 'R5.2', description: 'all four routes present resolves to the cache route first', kind: 'route', input: { cache: true, allowlist: { entries: [ENTRY] }, hook: true, doc: { text: DOC, path: '/hooks/alice' }, challenge: { status: 200, bodyText: ECHO_BODY, nonce: NONCE } }, expect: { result: 'accept', route: 'cache', reason: null } },
  { id: 'ep-route-allowlist-second', rule: 'R5.2', description: 'an absent cache resolves to the allowlist route', kind: 'route', input: { cache: false, allowlist: { entries: [ENTRY] }, hook: true, doc: { text: DOC, path: '/hooks/alice' }, challenge: null }, expect: { result: 'accept', route: 'allowlist', reason: null } },
  { id: 'ep-route-hook-third', rule: 'R5.2', description: 'cache and allowlist absent resolves to the out of band hook', kind: 'route', input: { cache: false, allowlist: null, hook: true, doc: { text: DOC, path: '/hooks/alice' }, challenge: null }, expect: { result: 'accept', route: 'out_of_band', reason: null } },
  { id: 'ep-route-doc-fourth', rule: 'R5.2', description: 'only the well-known document and challenge remain so the document route wins', kind: 'route', input: { cache: false, allowlist: null, hook: false, doc: { text: DOC, path: '/hooks/alice' }, challenge: { status: 200, bodyText: ECHO_BODY, nonce: NONCE } }, expect: { result: 'accept', route: 'well_known', reason: null } },
  { id: 'ep-route-nothing', rule: 'R5.2', description: 'no evidence at all is rejected as no_route', kind: 'route', input: { cache: false, allowlist: null, hook: false, doc: null, challenge: null }, expect: { result: 'reject', route: null, reason: 'no_route' } },
  { id: 'ep-route-challenge-mismatch', rule: 'R5.2', description: 'a challenge echo that does not match the nonce is a mismatch rejection', kind: 'route', input: { cache: false, allowlist: null, hook: false, doc: null, challenge: { status: 200, bodyText: ECHO_BODY_OTHER, nonce: NONCE } }, expect: { result: 'reject', route: null, reason: 'mismatch' } },

  // R5.3: 22 base64url characters from 16 bytes, 600 s lifetime, single use, bound to the pair.
  { id: 'ep-nonce-22-chars', rule: 'R5.3', description: '22 base64url characters from 16 bytes is a valid nonce', kind: 'nonce', input: { value: NONCE }, expect: { result: 'accept' } },
  { id: 'ep-nonce-21-chars', rule: 'R5.3', description: 'a 21-character nonce is rejected as one short', kind: 'nonce', input: { value: NONCE_SHORT }, expect: { result: 'reject' } },
  { id: 'ep-nonce-23-chars', rule: 'R5.3', description: 'a 23-character nonce is rejected as one long', kind: 'nonce', input: { value: NONCE_LONG }, expect: { result: 'reject' } },
  { id: 'ep-nonce-plus-char', rule: 'R5.3', description: 'a plus sign is not base64url so the nonce is rejected', kind: 'nonce', input: { value: NONCE_PLUS }, expect: { result: 'reject' } },
  { id: 'ep-accept-echo-consumed', rule: 'R5.3', description: 'a nonce already consumed is rejected as reused', kind: 'accept-echo', input: { nonce: NONCE, expected: NONCE, issuedAt: 1000, now: 1100, consumed: true, pair: PAIR, expectedPair: PAIR }, expect: { result: 'reject', code: 'challenge_failed', reason: 'reused' } },
  { id: 'ep-accept-echo-expired', rule: 'R5.3', description: 'an echo 601 s after issue is rejected as expired', kind: 'accept-echo', input: { nonce: NONCE, expected: NONCE, issuedAt: 1000, now: 1601, pair: PAIR, expectedPair: PAIR }, expect: { result: 'reject', code: 'challenge_failed', reason: 'expired' } },
  { id: 'ep-accept-echo-fresh', rule: 'R5.3', description: 'an echo exactly 600 s after issue is still inside the lifetime', kind: 'accept-echo', input: { nonce: NONCE, expected: NONCE, issuedAt: 1000, now: 1600, pair: PAIR, expectedPair: PAIR }, expect: { result: 'accept' } },
  { id: 'ep-accept-echo-pair', rule: 'R5.3', description: 'an echo bound to a different principal is rejected as pair', kind: 'accept-echo', input: { nonce: NONCE, expected: NONCE, issuedAt: 1000, now: 1100, pair: ['alice', HOOK], expectedPair: ['bob', HOOK] }, expect: { result: 'reject', code: 'challenge_failed', reason: 'pair' } },
  { id: 'ep-accept-echo-wrong-nonce', rule: 'R5.3', description: 'an echo of the wrong nonce is rejected as mismatch', kind: 'accept-echo', input: { nonce: NONCE_OTHER, expected: NONCE, issuedAt: 1000, now: 1100, pair: PAIR, expectedPair: PAIR }, expect: { result: 'reject', code: 'challenge_failed', reason: 'mismatch' } },
  { id: 'ep-accept-echo-json-pair', rule: 'R5.3', description: 'two separately written pair arrays with the same two strings are the same pair by value', kind: 'accept-echo', input: { nonce: NONCE, expected: NONCE, issuedAt: 1000, now: 1100, pair: ['alice', 'https://hooks.example.test/hooks/alice'], expectedPair: ['alice', 'https://hooks.example.test/hooks/alice'] }, expect: { result: 'accept' } },

  // R5.4: a 2xx JSON object whose challenge member equals the nonce, body at most 4096 bytes.
  { id: 'ep-echo-200', rule: 'R5.4', description: 'a 200 JSON object echoing the nonce is accepted', kind: 'echo', input: { status: 200, bodyText: ECHO_BODY, nonce: NONCE }, expect: { result: 'accept' } },
  { id: 'ep-echo-204', rule: 'R5.4', description: 'a 204 with the echoed challenge body is accepted', kind: 'echo', input: { status: 204, bodyText: ECHO_BODY, nonce: NONCE }, expect: { result: 'accept' } },
  { id: 'ep-echo-status-500', rule: 'R5.4', description: 'a 500 status is not 2xx so it is rejected as status', kind: 'echo', input: { status: 500, bodyText: ECHO_BODY, nonce: NONCE }, expect: { result: 'reject', code: 'challenge_failed', reason: 'status' } },
  { id: 'ep-echo-not-json', rule: 'R5.4', description: 'a body that is not JSON is rejected as json', kind: 'echo', input: { status: 200, bodyText: 'not json', nonce: NONCE }, expect: { result: 'reject', code: 'challenge_failed', reason: 'json' } },
  { id: 'ep-echo-array-body', rule: 'R5.4', description: 'a JSON array is not an object so it is rejected as body', kind: 'echo', input: { status: 200, bodyText: '[1]', nonce: NONCE }, expect: { result: 'reject', code: 'challenge_failed', reason: 'body' } },
  { id: 'ep-echo-missing-challenge', rule: 'R5.4', description: 'an object without a challenge member is rejected as missing', kind: 'echo', input: { status: 200, bodyText: '{}', nonce: NONCE }, expect: { result: 'reject', code: 'challenge_failed', reason: 'missing' } },
  { id: 'ep-echo-wrong-nonce', rule: 'R5.4', description: 'a body echoing another nonce is rejected as mismatch', kind: 'echo', input: { status: 200, bodyText: ECHO_BODY_OTHER, nonce: NONCE }, expect: { result: 'reject', code: 'challenge_failed', reason: 'mismatch' } },
  { id: 'ep-echo-too-large', rule: 'R5.4', description: 'a 5000-byte body exceeds the 4096-byte cap and is too_large', kind: 'echo', input: { status: 200, bodyText: BIG_BODY, nonce: NONCE }, expect: { result: 'reject', code: 'challenge_failed', reason: 'too_large' } },

  // R5.5: the handshake fails the subscribe call with challenge_failed when the echo does not match.
  { id: 'ep-challenge-only-evidence', rule: 'R5.5', description: 'the challenge echo alone is sufficient evidence and accepts', kind: 'route', input: { cache: false, allowlist: null, hook: false, doc: null, challenge: { status: 200, bodyText: ECHO_BODY, nonce: NONCE } }, expect: { result: 'accept', route: 'challenge', reason: null } },
  { id: 'ep-challenge-route-mismatch', rule: 'R5.5', description: 'a mismatched challenge echo fails the subscribe call', kind: 'route', input: { cache: false, allowlist: null, hook: false, doc: null, challenge: { status: 200, bodyText: ECHO_BODY_OTHER, nonce: NONCE } }, expect: { result: 'reject', route: null, reason: 'mismatch' } },

  // R5.7: operator allowlist entries are https prefixes with a literal or *.parent host, port and path.
  { id: 'ep-allowlist-entry-literal', rule: 'R5.7', description: 'a literal https prefix parses to host, port 443 and path', kind: 'allowlist-entry', input: { entry: ENTRY }, expect: { result: 'accept', host_pattern: 'hooks.example.test', port: 443, path: '/hooks' } },
  { id: 'ep-allowlist-entry-http', rule: 'R5.7', description: 'an http allowlist entry is rejected because https is required', kind: 'allowlist-entry', input: { entry: 'http://hooks.example.test/hooks' }, expect: { result: 'reject' } },
  { id: 'ep-allowlist-entry-wildcard', rule: 'R5.7', description: 'a wildcard parent host entry keeps the *.example.test pattern', kind: 'allowlist-entry', input: { entry: WILDCARD_ENTRY }, expect: { result: 'accept', host_pattern: '*.example.test', port: 443, path: '/hooks' } },
  { id: 'ep-allowlist-wildcard-child', rule: 'R5.7', description: 'a deeper child of the wildcard host matches the entry', kind: 'allowlist', input: { entries: [WILDCARD_ENTRY], url: 'https://a.b.example.test/hooks' }, expect: { result: 'accept', host_pattern: '*.example.test', port: 443, path: '/hooks' } },
  { id: 'ep-allowlist-wildcard-parent', rule: 'R5.7', description: 'the wildcard bare parent host does not match', kind: 'allowlist', input: { entries: [WILDCARD_ENTRY], url: 'https://example.test/hooks' }, expect: { result: 'reject' } },
  { id: 'ep-allowlist-entry-query', rule: 'R5.7', description: 'an allowlist entry carrying a query is rejected', kind: 'allowlist-entry', input: { entry: 'https://hooks.example.test/hooks?x=1' }, expect: { result: 'reject' } },
  { id: 'ep-allowlist-port-mismatch', rule: 'R5.7', description: 'a url port differing from the entry port does not match', kind: 'allowlist', input: { entries: [ENTRY], url: 'https://hooks.example.test:8443/hooks' }, expect: { result: 'reject' } },
  { id: 'ep-allowlist-path-prefix', rule: 'R5.7', description: 'a longer path under the entry prefix still matches', kind: 'allowlist', input: { entries: [ENTRY], url: 'https://hooks.example.test/hooks/a' }, expect: { result: 'accept', host_pattern: 'hooks.example.test', port: 443, path: '/hooks' } },
  { id: 'ep-allowlist-path-boundary', rule: 'R5.7', description: 'hooksx is not at a segment boundary so it does not match', kind: 'allowlist', input: { entries: [ENTRY], url: 'https://hooks.example.test/hooksx' }, expect: { result: 'reject' } },
  { id: 'ep-allowlist-path-root', rule: 'R5.7', description: 'a root entry path matches any path', kind: 'allowlist', input: { entries: ['https://hooks.example.test/'], url: 'https://hooks.example.test/anything' }, expect: { result: 'accept', host_pattern: 'hooks.example.test', port: 443, path: '/' } },

  // R5.8: the out-of-band hook, its false falls through and its null is not installed.
  { id: 'ep-route-hook-true', rule: 'R5.8', description: 'the installed out of band hook returns true and accepts', kind: 'route', input: { cache: false, allowlist: null, hook: true, doc: null, challenge: null }, expect: { result: 'accept', route: 'out_of_band', reason: null } },
  { id: 'ep-route-hook-false-doc', rule: 'R5.8', description: 'a false hook falls through to the well-known document', kind: 'route', input: { cache: false, allowlist: null, hook: false, doc: { text: DOC, path: '/hooks/alice' }, challenge: null }, expect: { result: 'accept', route: 'well_known', reason: null } },
  { id: 'ep-route-hook-null', rule: 'R5.8', description: 'a null hook is not installed so nothing routes', kind: 'route', input: { cache: false, allowlist: null, hook: null, doc: null, challenge: null }, expect: { result: 'reject', route: null, reason: 'no_route' } },

  // R5.9: the well-known document, its per-origin url and its capped cache ttl.
  { id: 'ep-doc-valid', rule: 'R5.9', description: 'a receivers array with one rooted entry is accepted', kind: 'doc', input: { text: DOC }, expect: { result: 'accept', receivers: ['/hooks/'] } },
  { id: 'ep-doc-not-json', rule: 'R5.9', description: 'a document body that is not JSON is an invalid document', kind: 'doc', input: { text: 'not json' }, expect: { result: 'reject', code: 'invalid_document', reason: 'json' } },
  { id: 'ep-doc-receivers-object', rule: 'R5.9', description: 'receivers must be an array and an object is rejected', kind: 'doc', input: { text: '{"receivers":{}}' }, expect: { result: 'reject', code: 'invalid_document', reason: 'receivers' } },
  { id: 'ep-doc-receivers-empty', rule: 'R5.9', description: 'an empty receivers array is rejected by count', kind: 'doc', input: { text: '{"receivers":[]}' }, expect: { result: 'reject', code: 'invalid_document', reason: 'count' } },
  { id: 'ep-doc-receivers-too-many', rule: 'R5.9', description: '65 receivers exceed the cap of 64 and are rejected', kind: 'doc', input: { text: DOC_TOO_MANY }, expect: { result: 'reject', code: 'invalid_document', reason: 'count' } },
  { id: 'ep-doc-entry-not-rooted', rule: 'R5.9', description: 'a receivers entry must start with a slash', kind: 'doc', input: { text: '{"receivers":["hooks/"]}' }, expect: { result: 'reject', code: 'invalid_document', reason: 'entry' } },
  { id: 'ep-doc-entry-query', rule: 'R5.9', description: 'a receivers entry may not carry a query', kind: 'doc', input: { text: '{"receivers":["/hooks?x=1"]}' }, expect: { result: 'reject', code: 'invalid_document', reason: 'entry' } },
  { id: 'ep-doc-entry-dot-segment', rule: 'R5.9', description: 'a dot segment inside a receivers entry is rejected', kind: 'doc', input: { text: '{"receivers":["/a/../b"]}' }, expect: { result: 'reject', code: 'invalid_document', reason: 'segment' } },
  { id: 'ep-doc-ttl-60', rule: 'R5.9', description: 'a max-age of 60 is kept as the ttl', kind: 'ttl', input: { maxAge: 60 }, expect: { result: 'accept', ttl: 60 } },
  { id: 'ep-doc-ttl-600', rule: 'R5.9', description: 'a max-age of 600 is capped to 300 s', kind: 'ttl', input: { maxAge: 600 }, expect: { result: 'accept', ttl: 300 } },
  { id: 'ep-doc-ttl-absent', rule: 'R5.9', description: 'an absent max-age falls back to 300 s', kind: 'ttl', input: {}, expect: { result: 'accept', ttl: 300 } },
  { id: 'ep-wellknown-url-hook', rule: 'R5.9', description: 'the well-known url is built from the hook origin', kind: 'wellknown-url', input: { url: HOOK }, expect: { result: 'accept', url: WELL_KNOWN } },
  { id: 'ep-wellknown-url-port', rule: 'R5.9', description: 'an explicit port is preserved in the well-known url', kind: 'wellknown-url', input: { url: 'https://hooks.example.test:8443/x' }, expect: { result: 'accept', url: WELL_KNOWN_PORT } },

  // R5.10: a receivers entry is a byte prefix of the path at a segment boundary, case-sensitive, undecoded.
  { id: 'ep-covers-trailing-slash-child', rule: 'R5.10', description: 'a /hooks/ entry covers the child path /hooks/a', kind: 'covers', input: { text: DOC, path: '/hooks/a' }, expect: { covered: true, entry: '/hooks/' } },
  { id: 'ep-covers-trailing-slash-root', rule: 'R5.10', description: 'a /hooks/ entry does not cover the bare /hooks path', kind: 'covers', input: { text: DOC, path: '/hooks' }, expect: { covered: false, entry: null } },
  { id: 'ep-covers-exact', rule: 'R5.10', description: 'a /hooks entry covers the identical path', kind: 'covers', input: { text: DOC_EXACT, path: '/hooks' }, expect: { covered: true, entry: '/hooks' } },
  { id: 'ep-covers-child', rule: 'R5.10', description: 'a /hooks entry covers the child path /hooks/a', kind: 'covers', input: { text: DOC_EXACT, path: '/hooks/a' }, expect: { covered: true, entry: '/hooks' } },
  { id: 'ep-covers-boundary', rule: 'R5.10', description: '/hooksx is not at a segment boundary so it is not covered', kind: 'covers', input: { text: DOC_EXACT, path: '/hooksx' }, expect: { covered: false, entry: null } },
  { id: 'ep-covers-case', rule: 'R5.10', description: 'a receivers entry match is case-sensitive', kind: 'covers', input: { text: DOC_EXACT, path: '/Hooks/a' }, expect: { covered: false, entry: null } },
  { id: 'ep-covers-percent-encoded', rule: 'R5.10', description: 'a percent-encoded slash is not decoded so it is not covered', kind: 'covers', input: { text: DOC_EXACT, path: '/hooks%2Fa' }, expect: { covered: false, entry: null } },
  { id: 'ep-covers-root-entry', rule: 'R5.10', description: 'the root entry covers any absolute path', kind: 'covers', input: { text: DOC_ROOT, path: '/anything' }, expect: { covered: true, entry: '/' } },

  // R5.11: a dot segment, raw or percent-encoded, is invalid_callback_url with reason dot_segment.
  { id: 'ep-url-dot-segment', rule: 'R5.11', description: 'a raw dot segment in the callback url is rejected', kind: 'url-check', input: { url: 'https://hooks.example.test/hooks/../admin' }, expect: { result: 'reject', code: 'invalid_callback_url', reason: 'dot_segment' } },
  { id: 'ep-url-encoded-dot-segment', rule: 'R5.11', description: 'a fully percent-encoded dot segment is still rejected', kind: 'url-check', input: { url: 'https://hooks.example.test/hooks/%2e%2e/admin' }, expect: { result: 'reject', code: 'invalid_callback_url', reason: 'dot_segment' } },
  { id: 'ep-url-mixed-case-dot-segment', rule: 'R5.11', description: 'a mixed-case percent-encoded dot segment is still rejected', kind: 'url-check', input: { url: 'https://hooks.example.test/hooks/.%2E/admin' }, expect: { result: 'reject', code: 'invalid_callback_url', reason: 'dot_segment' } },

  // R5.12: the verification POST and the well-known fetch use the hardened delivery path.
  { id: 'ep-post-private-answer', rule: 'R5.12', description: 'a verification POST resolving to a private address is blocked', kind: 'verification-post', input: { url: WELL_KNOWN, answers: ['10.0.0.5'] }, expect: { result: 'reject', code: 'blocked_address', reason: 'private_use' } },
  { id: 'ep-post-public-answer', rule: 'R5.12', description: 'a verification POST resolving to a public address connects', kind: 'verification-post', input: { url: WELL_KNOWN, answers: ['93.184.216.34'] }, expect: { result: 'accept', address: '93.184.216.34' } },
  { id: 'ep-post-redirect', rule: 'R5.12', description: 'a 302 answer on the verification POST is refused', kind: 'verification-post', input: { url: WELL_KNOWN, answers: ['93.184.216.34'], redirect: 302 }, expect: { result: 'reject', code: 'redirect_refused', reason: 'status_302' } },

  // R5.9, R5.12: one well-known document fetch, judged on its own, or behind the hardened delivery path.
  { id: 'ep-doc-fetch-200', rule: 'R5.9', description: 'a 200 fetch with a valid document is accepted with its receivers', kind: 'doc-fetch', input: { status: 200, bodyText: DOC }, expect: { result: 'accept', receivers: ['/hooks/'] } },
  { id: 'ep-doc-fetch-204', rule: 'R5.9', description: 'a 204 fetch is document_fetch_failed with reason status_204', kind: 'doc-fetch', input: { status: 204, bodyText: DOC }, expect: { result: 'reject', code: 'document_fetch_failed', reason: 'status_204' } },
  { id: 'ep-doc-fetch-404', rule: 'R5.9', description: 'a 404 fetch is document_fetch_failed with reason status_404', kind: 'doc-fetch', input: { status: 404, bodyText: DOC }, expect: { result: 'reject', code: 'document_fetch_failed', reason: 'status_404' } },
  { id: 'ep-doc-fetch-500', rule: 'R5.9', description: 'a 500 fetch is document_fetch_failed with reason status_500', kind: 'doc-fetch', input: { status: 500, bodyText: DOC }, expect: { result: 'reject', code: 'document_fetch_failed', reason: 'status_500' } },
  { id: 'ep-doc-fetch-8192', rule: 'R5.9', description: 'a document of exactly 8192 bytes is inside the body cap', kind: 'doc-fetch', input: { status: 200, bodyText: DOC_8192 }, expect: { result: 'accept', receivers: ['/hooks/'] } },
  { id: 'ep-doc-fetch-8193', rule: 'R5.9', description: 'a document of 8193 bytes is one over the body cap, so too_large', kind: 'doc-fetch', input: { status: 200, bodyText: DOC_8193 }, expect: { result: 'reject', code: 'document_fetch_failed', reason: 'too_large' } },
  { id: 'ep-doc-fetch-blocked-address', rule: 'R5.12', description: 'a well-known fetch resolving to a private address is blocked before the body is read', kind: 'doc-fetch', input: { url: WELL_KNOWN, answers: ['10.0.0.5'], status: 200, bodyText: DOC }, expect: { result: 'reject', code: 'blocked_address', reason: 'private_use' } },
];

const ECHO_KEYS = ['status', 'bodyText', 'nonce', 'maxBody'];
const ACCEPT_ECHO_KEYS = ['nonce', 'expected', 'issuedAt', 'now', 'ttl', 'consumed', 'pair', 'expectedPair'];
const POST_KEYS = ['url', 'answers', 'allowedRanges', 'recheck', 'redirect'];
const DOC_FETCH_KEYS = ['status', 'bodyText', 'maxBody'];
const DOC_REQUEST_KEYS = [...POST_KEYS, 'status', 'bodyText'];

export function run(c) {
  const input = c.input;
  switch (c.kind) {
    case 'nonce':
      return { result: nonceOk(input.value) ? 'accept' : 'reject' };
    case 'echo':
      return challengeResult(challengeEcho(only(input, ECHO_KEYS)));
    case 'accept-echo':
      return challengeResult(acceptEcho(only(input, ACCEPT_ECHO_KEYS)));
    case 'doc': {
      const parsed = parseReceiverDoc(input.text);
      return parsed.ok
        ? { result: 'accept', receivers: parsed.receivers }
        : { result: 'reject', code: 'invalid_document', reason: parsed.reason };
    }
    case 'covers': {
      const parsed = parseReceiverDoc(input.text);
      if (!parsed.ok) return { covered: false, entry: null };
      return receiverDocCovers(parsed.receivers, input.path);
    }
    case 'allowlist-entry': {
      const entry = parseAllowlistEntry(input.entry);
      if (!entry.ok) return { result: 'reject' };
      return { result: 'accept', host_pattern: entry.hostPattern, port: entry.port, path: entry.path };
    }
    case 'allowlist': {
      const hit = allowlistMatches(input.entries, input.url);
      if (!hit.matched) return { result: 'reject' };
      return { result: 'accept', host_pattern: hit.entry.hostPattern, port: hit.entry.port, path: hit.entry.path };
    }
    case 'ttl':
      return { result: 'accept', ttl: docCacheTtl(input.maxAge) };
    case 'wellknown-url': {
      const url = wellKnownUrl(input.url);
      return url === null ? { result: 'reject' } : { result: 'accept', url };
    }
    case 'route': {
      const verdict = verificationRoute(routeInput(input));
      return { result: verdict.verified ? 'accept' : 'reject', route: verdict.route, reason: verdict.reason };
    }
    case 'gate': {
      if (input.message === 'verification') return { action: 'send-challenge' };
      return { action: input.verified === true ? 'deliver' : 'refuse' };
    }
    case 'url-check': {
      const checked = checkUrl(input.url);
      return checked.ok ? { result: 'accept', canonical: checked.canonical } : refusal(checked.code, checked.reason);
    }
    case 'verification-post': {
      const checked = checkDelivery(only(input, POST_KEYS));
      if (checked.decision !== 'allow') return refusal(checked.code, checked.reason);
      return { result: 'accept', address: checked.connect.address };
    }
    case 'doc-fetch': {
      const verdict =
        input.url === undefined
          ? checkReceiverDocFetch(only(input, DOC_FETCH_KEYS))
          : receiverDocRequest(only(input, DOC_REQUEST_KEYS));
      return verdict.ok
        ? { result: 'accept', receivers: verdict.receivers }
        : { result: 'reject', code: verdict.code, reason: verdict.reason };
    }
    default:
      throw new Error(`${c.id}: unknown kind ${c.kind}`);
  }
}

const routeInput = (input) => ({
  cache: input.cache,
  allowlist: input.allowlist ? allowlistMatches(input.allowlist.entries, input.url ?? HOOK) : null,
  hook: input.hook,
  doc: input.doc ? documentOf(input.doc) : null,
  challenge: input.challenge ? challengeEcho(only(input.challenge, ECHO_KEYS)) : null,
});

const documentOf = ({ text, path }) => {
  const parsed = parseReceiverDoc(text);
  return { doc: parsed.ok ? parsed.receivers : [], path };
};

const only = (source, keys) => {
  const out = {};
  for (const key of keys) if (source[key] !== undefined) out[key] = source[key];
  return out;
};

const challengeResult = (verdict) =>
  verdict.ok ? { result: 'accept' } : { result: 'reject', code: verdict.code, reason: verdict.reason };

const refusal = (code, reason) =>
  reason === undefined ? { result: 'reject', code } : { result: 'reject', code, reason };
