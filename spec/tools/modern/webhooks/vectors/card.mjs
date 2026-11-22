// Vectors for spec/06-webhooks.md section 7 (R7.1-R7.5), Server Card key discovery.
import {
  acceptJwkSet,
  b64u,
  cardKeyForKid,
  crossCheckWebhookKey,
  fetchDecision,
  jwkOf,
  parseCidrList,
  selectRemote,
  webhookInfo,
} from '../reference.mjs';
import { K } from '../../../gen/core.mjs';

export const file = 'server-card-keys-vectors.json';

const MCP_URL = 'https://mcp.example.test/mcp';
const CARD_URL = 'https://mcp.example.test/server-card';
const EVENTS = 'io.modelcontextprotocol/events';
const EGRESS = ['203.0.113.0/24', '2001:db8::/32'];
const KEY_A = jwkOf(K.newbie);
const KEY_B = jwkOf(K.newbie2);
const KEY_C = jwkOf(K.newbie3);
const KEY_S = jwkOf(K.svc);
const info = (keys, egress) => ({ [EVENTS]: { webhooks: { ...(keys === undefined ? {} : { signingKeys: { keys } }), ...(egress === undefined ? {} : { egressIpRanges: egress }) } } });
const remote = (url, extensionsInfo) => ({ type: 'streamable-http', url, ...(extensionsInfo === undefined ? {} : { extensionsInfo }) });
const card = (...remotes) => ({ remotes });
const CARD = card(remote(MCP_URL, info([KEY_A, KEY_B], EGRESS)));
const bodyOf = (value) => b64u(Buffer.from(JSON.stringify(value), 'utf8'));
const toolResult = (keys) => ({ webhook_key: { signing_keys: { keys }, egress_ip_ranges: EGRESS } });
const bodyOfResponse = (response) => {
  if (response.card !== undefined) return bodyOf(response.card);
  if (typeof response.raw === 'string') return b64u(Buffer.from(response.raw, 'utf8'));
  if (typeof response.pad === 'number') return b64u(Buffer.from(' '.repeat(response.pad), 'utf8'));
  return '';
};

export const cases = [
  { id: 'card-info-full', rule: 'R7.1', description: 'the selected remote publishes both signing keys and both egress ranges', kind: 'info', input: { card: CARD, mcpUrl: MCP_URL }, expect: { result: 'accept', signing_keys: { keys: [KEY_A, KEY_B] }, egress: EGRESS, remote_url: MCP_URL } },
  { id: 'card-info-absent', rule: 'R7.1', description: 'a remote without extensionsInfo yields no keys and no ranges', kind: 'info', input: { card: card(remote(MCP_URL)), mcpUrl: MCP_URL }, expect: { result: 'accept', signing_keys: null, egress: [], remote_url: MCP_URL } },
  { id: 'card-info-no-signing-keys', rule: 'R7.1', description: 'an events entry without webhooks yields no keys and is not an error', kind: 'info', input: { card: card(remote(MCP_URL, { [EVENTS]: {} })), mcpUrl: MCP_URL }, expect: { result: 'accept', signing_keys: null, egress: [], remote_url: MCP_URL } },
  { id: 'card-select-exact-path', rule: 'R7.1', description: 'the exact path wins over a longer prefixed sibling listed first', kind: 'remote', input: { card: card(remote(MCP_URL + '/v2', info([KEY_B], EGRESS)), remote(MCP_URL, info([KEY_A], EGRESS))), mcpUrl: MCP_URL }, expect: { result: 'accept', url: MCP_URL } },
  { id: 'card-info-template-url', rule: 'R7.1', description: 'a templated remote url is never the endpoint, so the card has no_remote', kind: 'info', input: { card: card(remote('https://{tenant}.example.test/mcp', info([KEY_A]))), mcpUrl: MCP_URL }, expect: { result: 'reject', code: 'no_remote' } },

  { id: 'card-fetch-not-https', rule: 'R7.2', description: 'an http card url is refused as not_https', kind: 'fetch', input: { mcpUrl: MCP_URL, cardUrl: 'http://mcp.example.test/server-card', response: { status: 200, headers: {} } }, expect: { result: 'reject', code: 'not_https' } },
  { id: 'card-fetch-cross-origin', rule: 'R7.2', description: 'a card url on another origin is cross_origin', kind: 'fetch', input: { mcpUrl: MCP_URL, cardUrl: 'https://cdn.example.test/card.json', response: { status: 200, headers: {}, card: CARD } }, expect: { result: 'reject', code: 'cross_origin' } },
  { id: 'card-fetch-redirect', rule: 'R7.2', description: 'a 302 is redirect_refused even on the same origin', kind: 'fetch', input: { mcpUrl: MCP_URL, cardUrl: CARD_URL, response: { status: 302, headers: {} } }, expect: { result: 'reject', code: 'redirect_refused' } },
  { id: 'card-fetch-http-status', rule: 'R7.2', description: 'a 404 is http_status', kind: 'fetch', input: { mcpUrl: MCP_URL, cardUrl: CARD_URL, response: { status: 404, headers: {} } }, expect: { result: 'reject', code: 'http_status' } },
  { id: 'card-fetch-too-large', rule: 'R7.2', description: 'a body of 65537 bytes is one over the cap, so too_large', kind: 'fetch', input: { mcpUrl: MCP_URL, cardUrl: CARD_URL, response: { status: 200, headers: {}, pad: 65537 } }, expect: { result: 'reject', code: 'too_large' } },
  { id: 'card-fetch-bad-json', rule: 'R7.2', description: 'a body that is not json is bad_json', kind: 'fetch', input: { mcpUrl: MCP_URL, cardUrl: CARD_URL, response: { status: 200, headers: {}, raw: 'not json' } }, expect: { result: 'reject', code: 'bad_json' } },
  { id: 'card-fetch-accept-cache', rule: 'R7.2', description: 'a valid card is accepted and max-age=60 caps the cache ttl', kind: 'fetch', input: { mcpUrl: MCP_URL, cardUrl: CARD_URL, response: { status: 200, headers: { 'cache-control': 'max-age=60' }, card: CARD } }, expect: { result: 'accept', keys: [KEY_A.kid, KEY_B.kid], egress: EGRESS, rejected: [], cache_ttl: 60 } },
  { id: 'card-fetch-elapsed-10000', rule: 'R7.2', description: 'a card fetch of exactly 10000 ms is inside the time cap and caches 300 s without a max-age', kind: 'fetch', input: { mcpUrl: MCP_URL, cardUrl: CARD_URL, elapsed_ms: 10000, response: { status: 200, headers: {}, card: CARD } }, expect: { result: 'accept', keys: [KEY_A.kid, KEY_B.kid], egress: EGRESS, rejected: [], cache_ttl: 300 } },
  { id: 'card-fetch-elapsed-10001', rule: 'R7.2', description: 'a card fetch of 10001 ms is one over the time cap, so timeout', kind: 'fetch', input: { mcpUrl: MCP_URL, cardUrl: CARD_URL, elapsed_ms: 10001, response: { status: 200, headers: {}, card: CARD } }, expect: { result: 'reject', code: 'timeout' } },
  { id: 'card-fetch-server-key-and-dedicated', rule: 'R7.3', description: 'a card publishing the raw MCP server key next to the dedicated key yields only the dedicated key', kind: 'fetch', input: { mcpUrl: MCP_URL, cardUrl: CARD_URL, mcp_server_public_key: K.svc.public_key, response: { status: 200, headers: {}, card: card(remote(MCP_URL, info([KEY_S, KEY_A], EGRESS))) } }, expect: { result: 'accept', keys: [KEY_A.kid], egress: EGRESS, rejected: [{ kid: KEY_S.kid, reason: 'mcp_server_key' }], cache_ttl: 300 } },

  { id: 'card-jwk-valid', rule: 'R7.3', description: 'two well formed JWKs are both accepted', kind: 'jwk-set', input: { signing_keys: [KEY_A, KEY_B] }, expect: { accepted: [KEY_A.kid, KEY_B.kid], rejected: [] } },
  { id: 'card-jwk-kty', rule: 'R7.3', description: 'a non OKP kty is rejected as kty', kind: 'jwk-set', input: { signing_keys: [{ ...KEY_A, kty: 'RSA' }] }, expect: { accepted: [], rejected: [{ kid: KEY_A.kid, reason: 'kty' }] } },
  { id: 'card-jwk-crv', rule: 'R7.3', description: 'a non Ed25519 crv is rejected as crv', kind: 'jwk-set', input: { signing_keys: [{ ...KEY_A, crv: 'P-256' }] }, expect: { accepted: [], rejected: [{ kid: KEY_A.kid, reason: 'crv' }] } },
  { id: 'card-jwk-x-encoding', rule: 'R7.3', description: 'a padded x is not canonical base64url and is x_encoding', kind: 'jwk-set', input: { signing_keys: [{ ...KEY_A, x: KEY_A.x + '=' }] }, expect: { accepted: [], rejected: [{ kid: KEY_A.kid, reason: 'x_encoding' }] } },
  { id: 'card-jwk-x-key', rule: 'R7.3', description: 'x decoding to 32 zero bytes is not a valid Ed25519 key, so x_key', kind: 'jwk-set', input: { signing_keys: [{ ...KEY_A, x: b64u(Buffer.alloc(32)) }] }, expect: { accepted: [], rejected: [{ kid: KEY_A.kid, reason: 'x_key' }] } },
  { id: 'card-jwk-kid-missing', rule: 'R7.3', description: 'a JWK without kid is rejected as kid_missing', kind: 'jwk-set', input: { signing_keys: [{ kty: 'OKP', crv: 'Ed25519', x: KEY_A.x }] }, expect: { accepted: [], rejected: [{ kid: null, reason: 'kid_missing' }] } },
  { id: 'card-jwk-kid-mismatch', rule: 'R7.3', description: 'a kid that is not base64url(SHA-256(x)) is kid_mismatch', kind: 'jwk-set', input: { signing_keys: [{ ...KEY_A, kid: 'A'.repeat(43) }] }, expect: { accepted: [], rejected: [{ kid: 'A'.repeat(43), reason: 'kid_mismatch' }] } },
  { id: 'card-jwk-duplicate-kid', rule: 'R7.3', description: 'a repeated kid moves every key with that kid out as duplicate_kid', kind: 'jwk-set', input: { signing_keys: [KEY_A, { ...KEY_A }] }, expect: { accepted: [], rejected: [{ kid: KEY_A.kid, reason: 'duplicate_kid' }, { kid: KEY_A.kid, reason: 'duplicate_kid' }] } },
  { id: 'card-jwk-server-key', rule: 'R7.3', description: 'the configured MCP server key is moved out as mcp_server_key and the webhook key stays', kind: 'jwk-set', input: { signing_keys: [KEY_A, KEY_S], mcp_server_kid: K.svc.kid }, expect: { accepted: [KEY_A.kid], rejected: [{ kid: KEY_S.kid, reason: 'mcp_server_key' }] } },
  { id: 'card-jwk-server-key-raw', rule: 'R7.3', description: 'the configured raw server public key drops the server key even though its kid is not named', kind: 'jwk-set', input: { signing_keys: [KEY_A, KEY_S], mcp_server_public_key: K.svc.public_key }, expect: { accepted: [KEY_A.kid], rejected: [{ kid: KEY_S.kid, reason: 'mcp_server_key' }] } },

  { id: 'card-rotation-both-trusted', rule: 'R7.4', description: 'the old and the new key published together are both accepted', kind: 'jwk-set', input: { signing_keys: [KEY_B, KEY_C] }, expect: { accepted: [KEY_B.kid, KEY_C.kid], rejected: [] } },
  { id: 'card-rotation-old-removed', rule: 'R7.4', description: 'a kid no longer in the card is unknown_webhook_key', kind: 'kid', input: { keys: ['newbie'], kid: K.newbie2.kid }, expect: { result: 'reject', code: 'unknown_webhook_key' } },
  { id: 'card-rotation-both-known', rule: 'R7.4', description: 'a delivery signed with either published key resolves', kind: 'kid', input: { keys: ['newbie', 'newbie2'], kid: K.newbie2.kid }, expect: { result: 'accept' } },

  { id: 'card-egress-valid', rule: 'R7.5', description: 'an IPv4 and an IPv6 egress range both parse', kind: 'cidr-list', input: { values: EGRESS }, expect: { accepted: [{ cidr: '203.0.113.0/24', family: 'ipv4', prefix: 24 }, { cidr: '2001:db8::/32', family: 'ipv6', prefix: 32 }], rejected: [] } },
  { id: 'card-egress-malformed', rule: 'R7.5', description: 'host bits set and an out of range octet are both malformed_cidr', kind: 'cidr-list', input: { values: ['10.0.0.1/8', '300.0.0.0/24'] }, expect: { accepted: [], rejected: [{ value: '10.0.0.1/8', reason: 'malformed_cidr' }, { value: '300.0.0.0/24', reason: 'malformed_cidr' }] } },
  { id: 'card-jwk-x-length', rule: 'R7.3', description: 'an x of 31 bytes is not a 32-byte key and is x_length', kind: 'jwk-set', input: { signing_keys: [{ ...KEY_A, x: b64u(Buffer.alloc(31, 1)) }] }, expect: { accepted: [], rejected: [{ kid: KEY_A.kid, reason: 'x_length' }] } },
  { id: 'card-jwk-alg', rule: 'R7.3', description: 'a non EdDSA alg is rejected as alg', kind: 'jwk-set', input: { signing_keys: [{ ...KEY_A, alg: 'RS256' }] }, expect: { accepted: [], rejected: [{ kid: KEY_A.kid, reason: 'alg' }] } },
  { id: 'card-jwk-use', rule: 'R7.3', description: 'a non sig use is rejected as use', kind: 'jwk-set', input: { signing_keys: [{ ...KEY_A, use: 'enc' }] }, expect: { accepted: [], rejected: [{ kid: KEY_A.kid, reason: 'use' }] } },

  // R7.6: the optional cross-check of the card key set against the jack.server.webhook_key tool result.
  { id: 'card-webhook-key-agree', rule: 'R7.6', description: 'a tool result publishing the same key set agrees with the card', kind: 'webhook-key-check', input: { keys: ['newbie'], toolResult: toolResult([jwkOf(K.newbie)]), require: true }, expect: { result: 'accept' } },
  { id: 'card-webhook-key-differ', rule: 'R7.6', description: 'a tool result publishing a different key is webhook_key_mismatch', kind: 'webhook-key-check', input: { keys: ['newbie'], toolResult: toolResult([jwkOf(K.newbie2)]), require: true }, expect: { result: 'reject', code: 'webhook_key_mismatch' } },
  { id: 'card-webhook-key-missing', rule: 'R7.6', description: 'a required check with no tool result is webhook_key_missing', kind: 'webhook-key-check', input: { keys: ['newbie'], toolResult: null, require: true }, expect: { result: 'reject', code: 'webhook_key_missing' } },
  { id: 'card-webhook-key-not-required', rule: 'R7.6', description: 'a receiver that does not require the check ignores the absent tool result', kind: 'webhook-key-check', input: { keys: ['newbie'], toolResult: null, require: false }, expect: { result: 'accept' } },
  { id: 'card-webhook-key-agree-discovery', rule: 'R7.6', description: 'a tool result publishing both keys discovery accepted agrees with the card', kind: 'webhook-key-discovery', input: { mcpUrl: MCP_URL, cardUrl: CARD_URL, response: { status: 200, headers: {}, card: CARD }, toolResult: toolResult([jwkOf(K.newbie), jwkOf(K.newbie2)]) }, expect: { result: 'accept' } },
  { id: 'card-webhook-key-mismatch-discovery', rule: 'R7.6', description: 'a tool result narrowing the card set to one of its two keys is webhook_key_mismatch', kind: 'webhook-key-discovery', input: { mcpUrl: MCP_URL, cardUrl: CARD_URL, response: { status: 200, headers: {}, card: CARD }, toolResult: toolResult([jwkOf(K.newbie2)]) }, expect: { result: 'reject', code: 'webhook_key_mismatch' } },
];

export function run(c) {
  const input = c.input;
  switch (c.kind) {
    case 'remote': {
      const verdict = selectRemote(input.card, { mcpUrl: input.mcpUrl });
      return verdict.ok ? { result: 'accept', url: verdict.remote.url } : { result: 'reject', code: verdict.code };
    }
    case 'info': {
      const verdict = webhookInfo(input.card, { mcpUrl: input.mcpUrl });
      if (!verdict.ok) return { result: 'reject', code: verdict.code };
      return { result: 'accept', signing_keys: verdict.signingKeys, egress: verdict.egressIpRanges, remote_url: verdict.remote_url };
    }
    case 'jwk-set': {
      const options = {
        ...(input.mcp_server_kid === undefined ? {} : { mcpServerKid: input.mcp_server_kid }),
        ...(input.mcp_server_public_key === undefined ? {} : { mcpServerPublicKey: input.mcp_server_public_key }),
      };
      const verdict = acceptJwkSet({ keys: input.signing_keys }, options);
      return { accepted: verdict.accepted.map((key) => key.kid), rejected: verdict.rejected };
    }
    case 'cidr-list': {
      const verdict = parseCidrList(input.values);
      return { accepted: verdict.accepted, rejected: verdict.rejected };
    }
    case 'fetch': {
      const answer = input.response;
      const verdict = fetchDecision({
        mcpUrl: input.mcpUrl,
        cardUrl: input.cardUrl,
        elapsed_ms: input.elapsed_ms,
        ...(input.mcp_server_kid === undefined ? {} : { mcpServerKid: input.mcp_server_kid }),
        ...(input.mcp_server_public_key === undefined ? {} : { mcpServerPublicKey: input.mcp_server_public_key }),
        response: { status: answer.status, headers: answer.headers ?? {}, body_b64u: bodyOfResponse(answer) },
      });
      if (!verdict.ok) return { result: 'reject', code: verdict.code };
      return {
        result: 'accept',
        keys: verdict.keys.map((key) => key.kid),
        egress: verdict.egressIpRanges.map((entry) => entry.cidr),
        rejected: verdict.rejected_keys,
        cache_ttl: verdict.cache_ttl,
      };
    }
    case 'kid': {
      const verdict = cardKeyForKid(input.keys.map((name) => K[name]), input.kid);
      return verdict.ok ? { result: 'accept' } : { result: 'reject', code: verdict.code };
    }
    case 'webhook-key-check': {
      const verdict = crossCheckWebhookKey({
        keys: input.keys.map((name) => jwkOf(K[name])),
        toolResult: input.toolResult,
        require: input.require,
      });
      return verdict.ok ? { result: 'accept' } : { result: 'reject', code: verdict.code };
    }
    case 'webhook-key-discovery': {
      const response = input.response;
      const verdict = fetchDecision({
        mcpUrl: input.mcpUrl,
        cardUrl: input.cardUrl,
        response: { status: response.status, headers: response.headers ?? {}, body_b64u: bodyOfResponse(response) },
      });
      if (!verdict.ok) return { result: 'reject', code: verdict.code };
      const check = crossCheckWebhookKey({ keys: verdict.keys, toolResult: input.toolResult, require: true });
      return check.ok ? { result: 'accept' } : { result: 'reject', code: check.code };
    }
    default:
      throw new Error(`${c.id}: unknown kind ${c.kind}`);
  }
}
