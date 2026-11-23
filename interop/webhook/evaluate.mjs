// Verification of one webhook matrix scenario (contract section 7): the driver
// rebuilds every view from the executables' own lines and re-verifies the
// signatures itself, so neither executable's verdict is trusted.
import * as D from './derive.mjs';
import * as S from './support.mjs';

const ID_RE = /^[A-Za-z0-9_-]{8,128}$/;
const TIMESTAMP_RE = /^(0|[1-9][0-9]{0,11})$/;
const NONCE_RE = /^[A-Za-z0-9_-]{22}$/;

const isObject = (value) => Boolean(value) && typeof value === 'object' && !Array.isArray(value);

// Compact rendering for diagnostics: a raw JSON dump can be huge.
export function truncateJson(value) {
  const text = JSON.stringify(value) ?? String(value);
  return text.length > 1200 ? text.slice(0, 1200) + '...' : text;
}

function parseJsonBody(bytes) {
  try {
    const value = JSON.parse(Buffer.from(bytes).toString('utf8'));
    return isObject(value) ? value : null;
  } catch {
    return null;
  }
}

// The id prefix a reported message kind must carry; null when nothing applies.
export function kindPrefixOf(kind) {
  if (kind === 'gap' || kind === 'terminated' || kind === 'verification') return `msg_${kind}_`;
  if (kind === 'event') return 'msg_';
  return null;
}

// The sender prints exactly two lines, its ready line and its result line
// (contract section 4.2). Any other line is a contract violation: the wire
// evidence lives on the receiving side, never in a sender log.
export function splitSenderLines(lines) {
  const reasons = [];
  const ready = lines.length > 0 && lines[0].ready === true ? lines[0] : null;
  if (ready === null) reasons.push('the sender printed no ready line');
  const last = lines.length > 0 ? lines[lines.length - 1] : null;
  const result = last !== null && last.event === 'result' ? last : null;
  if (result === null) reasons.push('the sender printed no result line as its last line');
  for (const line of lines.slice(1, Math.max(1, lines.length - 1))) {
    reasons.push(`the sender printed a line between its ready line and its result line: ${truncateJson(line)}`);
  }
  if (lines.length > 2) reasons.push(`the sender printed ${lines.length} lines, contract section 4.2 allows exactly 2`);
  return { ready, result, reasons };
}

// One delivered request as the driver judges it: pinned signature checks, the
// R1.4/R1.5 grammars, the body name and the duplicate relation.
export function buildDeliveryViews(lines, ctx) {
  const views = [];
  let previousId = null;
  for (let index = 0; index < lines.length; index++) {
    const line = lines[index];
    const headers = Array.isArray(line.headers)
      ? line.headers.map((pair) => [String(pair[0]), String(pair[1])])
      : [];
    const body = Buffer.from(String(line.body_b64u ?? ''), 'base64url');
    const webhookId = String(line.webhook_id ?? '');
    const timestamp = String(line.webhook_timestamp ?? '');
    const subscriptionId = String(line.subscription_id ?? '');
    const emissionValues = S.headerValues(headers, 'webhook-signature');
    const entries = emissionValues.length === 1 ? D.parseEmission(emissionValues[0]) : null;
    const schemes = entries === null ? [] : entries.map((entry) => entry.scheme);
    const emission = D.verifyEmission({
      entries,
      secret: ctx.secret,
      keys: ctx.cardKeys,
      subscriptionId,
      webhookId,
      timestamp,
      body,
    });
    const jackValues = S.headerValues(headers, 'jack-webhook-auth');
    const w1 = D.verifyW1({
      value: jackValues.length === 1 ? jackValues[0] : null,
      keys: ctx.cardKeys,
      parts: { aud: D.AUD, subscriptionId, webhookId, timestamp, callbackUrl: ctx.url, body },
    });
    const challenge = line.challenge === undefined || line.challenge === null ? null : String(line.challenge);
    const bodyJson = parseJsonBody(body);
    const prefix = D.idPrefix(webhookId);
    views.push({
      seq: line.seq,
      status: line.status,
      code: line.code === undefined ? null : line.code,
      body_status: line.body_status === undefined ? null : line.body_status,
      kind: line.kind === undefined ? null : line.kind,
      webhook_id: webhookId,
      webhook_id_prefix: prefix,
      webhook_id_chars: webhookId.length - prefix.length,
      webhook_id_grammar: ID_RE.test(webhookId),
      subscription_id: subscriptionId,
      timestamp,
      timestamp_grammar: TIMESTAMP_RE.test(timestamp),
      challenge,
      challenge_grammar: challenge !== null && NONCE_RE.test(challenge),
      duplicate_of_previous: index > 0 && webhookId !== '' && webhookId === previousId,
      signature_header_instances: emissionValues.length,
      signatures: { v1: emission.v1, v1a: emission.v1a, v2a: emission.v2a, w1 },
      body_equals: D.bodyName(body),
      body_json: bodyJson,
      challenge_matches_body: challenge !== null && bodyJson !== null && bodyJson.challenge === challenge,
      signature_schemes: schemes,
      enqueued: Number.isInteger(line.enqueued) ? line.enqueued : null,
      enqueued_reported: Number.isInteger(line.enqueued),
      forwarded: (Array.isArray(line.forwarded) ? line.forwarded : []).map((value) => D.jsonBodyName(Buffer.from(String(value), 'base64url'))),
      forwarded_reported: Array.isArray(line.forwarded),
      forwarded_count: Array.isArray(line.forwarded) ? line.forwarded.length : 0,
      body_len: body.length,
    });
    previousId = webhookId;
  }
  return views;
}

// One request the relay recorded, judged the way a delivery is: the relay sees
// the bytes the sender signed, which is the attempt evidence of a scenario
// without a receiver and the cross-check of a scenario with one.
export function buildRelayAttemptViews(observations, ctx) {
  const views = [];
  for (const record of Array.isArray(observations) ? observations : []) {
    const webhookId = String(record.webhook_id ?? '');
    const timestamp = String(record.webhook_timestamp ?? '');
    const body = Buffer.from(String(record.body_b64u ?? ''), 'base64url');
    const entries = D.parseEmission(String(record.signature ?? ''));
    const emission = D.verifyEmission({
      entries,
      secret: ctx.secret,
      keys: ctx.cardKeys,
      subscriptionId: ctx.effectiveSubscriptionId,
      webhookId,
      timestamp,
      body,
    });
    views.push({
      seq: record.seq,
      webhook_id: webhookId,
      webhook_id_prefix: D.idPrefix(webhookId),
      webhook_timestamp: timestamp,
      http_status: record.status === undefined ? null : record.status,
      same_webhook_id_as_previous: views.length > 0 && webhookId !== '' && webhookId === views[views.length - 1].webhook_id,
      signature_schemes: entries === null ? [] : entries.map((entry) => entry.scheme),
      signatures: { v1: emission.v1 },
    });
  }
  return views;
}

// Grammar and shape checks that hold for every scenario, before any table row
// is matched: ids, timestamps, the effective subscription id and the prefixes.
function checkDeliveries(deliveries, ctx, push) {
  let previousEnqueued = 0;
  for (const view of deliveries) {
    if (!view.webhook_id_grammar) {
      push(`delivery ${view.seq}: webhook-id ${JSON.stringify(view.webhook_id)} is outside the R1.4 grammar`);
    }
    if (!view.timestamp_grammar) {
      push(`delivery ${view.seq}: webhook-timestamp ${JSON.stringify(view.timestamp)} is outside the R1.5 grammar`);
    }
    if (view.subscription_id !== ctx.effectiveSubscriptionId) {
      push(`delivery ${view.seq}: subscription id ${JSON.stringify(view.subscription_id)}, expected ${JSON.stringify(ctx.effectiveSubscriptionId)}`);
    }
    if (view.signature_header_instances > 1) {
      push(`delivery ${view.seq}: webhook-signature appears ${view.signature_header_instances} times`);
    }
    const prefix = kindPrefixOf(view.kind);
    if (prefix !== null && view.webhook_id_prefix !== prefix) {
      push(`delivery ${view.seq}: kind ${view.kind} requires the id prefix ${prefix}, got ${JSON.stringify(view.webhook_id)}`);
    }
    if (typeof view.status !== 'number') {
      push(`delivery ${view.seq}: status is not a number`);
    }
    // R1.10 and R3.16 are judged from the enqueue evidence alone, so missing
    // evidence is a failure and never a zero.
    if (!view.enqueued_reported) push(`delivery ${view.seq}: carries no integer 'enqueued' count`);
    if (!view.forwarded_reported) push(`delivery ${view.seq}: carries no 'forwarded' array`);
    if (view.forwarded_count > 1) {
      push(`delivery ${view.seq}: forwarded ${view.forwarded_count} messages, one delivery forwards at most one`);
    }
    for (const name of view.forwarded) {
      if (name !== view.body_equals) {
        push(`delivery ${view.seq}: forwarded payload ${JSON.stringify(name)} is not the received body ${JSON.stringify(view.body_equals)}`);
      }
    }
    const accepted = typeof view.status === 'number' && view.status >= 200 && view.status <= 299;
    if (!accepted && view.forwarded_count > 0) {
      push(`delivery ${view.seq}: a ${JSON.stringify(view.status)} refusal forwarded ${view.forwarded_count} message(s)`);
    }
    if (accepted && view.body_status !== 'duplicate' && view.body_status !== 'challenge' && view.forwarded_count !== 1) {
      push(`delivery ${view.seq}: a 2xx that is not a duplicate or a challenge must forward exactly one message (R1.10)`);
    }
    if (view.enqueued_reported && view.forwarded_reported && view.enqueued !== previousEnqueued + view.forwarded_count) {
      push(`delivery ${view.seq}: enqueued ${view.enqueued} does not grow by its ${view.forwarded_count} forwarded message(s) from ${previousEnqueued}`);
    }
    if (Number.isInteger(view.enqueued)) previousEnqueued = view.enqueued;
  }
}

// The sender's own report must agree with the driver's own derivations.
function checkSenderReport(ready, result, ctx, push) {
  if (ready === null) push('the sender printed no ready line');
  else {
    if (ready.role !== 'sender') push(`ready line role ${JSON.stringify(ready.role)}, expected "sender"`);
    if (ready.callback_url !== ctx.url) {
      push(`ready line callback_url ${JSON.stringify(ready.callback_url)}, expected ${JSON.stringify(ctx.url)}`);
    }
    if (ready.derived_subscription_id !== ctx.subscriptionId) {
      push(`ready line derived_subscription_id ${JSON.stringify(ready.derived_subscription_id)}, the driver derives ${JSON.stringify(ctx.subscriptionId)}`);
    }
  }
  if (result === null) push('the sender printed no result line');
  else {
    if (result.scenario !== ctx.scenario) push(`result line scenario ${JSON.stringify(result.scenario)}, expected ${JSON.stringify(ctx.scenario)}`);
    if (result.role !== 'sender') push(`result line role ${JSON.stringify(result.role)}, expected "sender"`);
    if (result.callback_url !== ctx.url) {
      push(`result line callback_url ${JSON.stringify(result.callback_url)}, expected ${JSON.stringify(ctx.url)}`);
    }
    if (result.derived_subscription_id !== ctx.subscriptionId) {
      push(`result line derived_subscription_id ${JSON.stringify(result.derived_subscription_id)}, the driver derives ${JSON.stringify(ctx.subscriptionId)}`);
    }
    if (!Array.isArray(result.results)) push('result line has no results array');
    else if (result.results.length !== ctx.messages.length) {
      push(`result line reports ${result.results.length} results, expected ${ctx.messages.length}`);
    }
  }
}

// Every field the table names must exist in the observed view: a field that is
// absent fails by name instead of matching as a subset.
function missingFields(expected, actual, path, out) {
  if (Array.isArray(expected)) {
    if (!Array.isArray(actual)) {
      out.push(path);
      return;
    }
    for (let i = 0; i < Math.min(expected.length, actual.length); i++) {
      missingFields(expected[i], actual[i], `${path}[${i}]`, out);
    }
    return;
  }
  if (expected !== null && typeof expected === 'object') {
    if (actual === null || typeof actual !== 'object' || Array.isArray(actual)) {
      out.push(path);
      return;
    }
    for (const [key, value] of Object.entries(expected)) {
      if (!Object.hasOwn(actual, key)) out.push(`${path}.${key}`);
      else missingFields(value, actual[key], `${path}.${key}`, out);
    }
  }
}

// Positional matching of a table array against a driver view array: a missing
// field fails by name, then the values are compared.
function matchArray(expectedList, actualList, labelPlural, labelOne, push) {
  const expected = Array.isArray(expectedList) ? expectedList : [];
  if (actualList.length !== expected.length) push(`${labelPlural} ${actualList.length}, expected ${expected.length}`);
  const shared = Math.min(actualList.length, expected.length);
  for (let i = 0; i < shared; i++) {
    const missing = [];
    missingFields(expected[i], actualList[i], `${labelOne} ${i}`, missing);
    for (const path of missing) push(`${path} is missing from the observed ${labelOne} ${i}`);
    if (!S.subsetMatches(expected[i], actualList[i])) {
      push(`${labelOne} ${i} mismatch: expected ${truncateJson(expected[i])}, actual ${truncateJson(actualList[i])}`);
    }
  }
}

// The relay's record of a request and the delivery the receiver logged must
// describe the same POST, unless the preset rewrote a header after signing.
function crossCheckAttempts(attempts, deliveries, push) {
  const shared = Math.min(attempts.length, deliveries.length);
  for (let i = 0; i < shared; i++) {
    const attempt = attempts[i];
    const delivery = deliveries[i];
    if (attempt.webhook_id !== delivery.webhook_id) {
      push(`relay request ${i} carried webhook-id ${JSON.stringify(attempt.webhook_id)}, delivery ${delivery.seq} received ${JSON.stringify(delivery.webhook_id)}`);
    }
    if (attempt.webhook_timestamp !== delivery.timestamp) {
      push(`relay request ${i} carried webhook-timestamp ${JSON.stringify(attempt.webhook_timestamp)}, delivery ${delivery.seq} received ${JSON.stringify(delivery.timestamp)}`);
    }
    if (attempt.http_status !== delivery.status) {
      push(`relay request ${i} answered ${JSON.stringify(attempt.http_status)}, delivery ${delivery.seq} answered ${JSON.stringify(delivery.status)}`);
    }
  }
}

// One scenario: shape and grammar invariants first, then the table row.
export function evaluateScenario({ expected, ctx, ready, result, attempts, deliveries, shadowConnections = 0, shadowBytes = 0, crossCheck = true }) {
  const reasons = [];
  const push = (text) => reasons.push(text);
  checkSenderReport(ready, result, ctx, push);
  checkDeliveries(deliveries, ctx, push);
  if (Array.isArray(expected.attempts)) matchArray(expected.attempts, attempts, 'attempt records', 'attempt record', push);
  matchArray(expected.deliveries, deliveries, 'deliveries', 'delivery', push);
  if (expected.shadow_connections !== undefined) {
    if (shadowConnections !== expected.shadow_connections) {
      push(`the shadow listener accepted ${shadowConnections} connection(s), expected ${expected.shadow_connections}: a policy refusal is decided before any dial`);
    }
  }
  if (expected.shadow_bytes !== undefined && shadowBytes !== expected.shadow_bytes) {
    push(`the shadow listener received ${shadowBytes} byte(s), expected ${expected.shadow_bytes}: a rebinding refusal must stop before any TLS or request byte`);
  }
  if (isObject(expected.sender)) {
    if (result === null) push('no result line to match expected.sender');
    else {
      const view = {};
      for (const [key, value] of Object.entries(result)) {
        if (key !== 'event') view[key] = value;
      }
      if (!S.subsetMatches(expected.sender, view)) {
        push(`sender result mismatch: expected ${truncateJson(expected.sender)}, actual ${truncateJson(view)}`);
      }
    }
  }
  if (crossCheck && attempts.length > 0 && deliveries.length > 0) crossCheckAttempts(attempts, deliveries, push);
  return {
    reasons,
    actual: {
      shadow_connections: shadowConnections,
      shadow_bytes: shadowBytes,
      attempts: attempts.map((view) => ({
        seq: view.seq,
        webhook_timestamp: view.webhook_timestamp,
        http_status: view.http_status,
        same_webhook_id_as_previous: view.same_webhook_id_as_previous,
        signature_schemes: view.signature_schemes,
        signatures: view.signatures,
      })),
      deliveries: deliveries.map((view) => ({
        seq: view.seq,
        status: view.status,
        code: view.code,
        kind: view.kind,
        body_status: view.body_status,
        body_equals: view.body_equals,
        signatures: view.signatures,
        enqueued: view.enqueued,
        forwarded: view.forwarded,
        signature_schemes: view.signature_schemes,
      })),
    },
  };
}
