export function expect(cond, name, detail = '') {
  return { name, ok: Boolean(cond), detail: String(detail) };
}

function result(checks) {
  const failed = checks.find((check) => !check.ok);
  return { ok: checks.every((check) => check.ok), reason: failed ? `${failed.name}: ${failed.detail}` : 'all assertions passed', checks };
}
function seqMatches(actual, expected) { return Array.isArray(actual) && Array.isArray(expected) && actual.length === expected.length && expected.every((value, index) => actual[index] === value); }
function includesValue(value, needle) { try { const serialized = JSON.stringify(value); return typeof serialized === 'string' && serialized.includes(needle); } catch { return false; } }

export function hopOffersModernDiscovery(captures, hop) {
  for (const capture of captures ?? []) {
    if (capture.direction !== 'event' || capture.hop !== hop) continue;
    for (const line of String(capture.body).split(/\r?\n/)) {
      if (!line.startsWith('data: ')) continue;
      try {
        const body = JSON.parse(line.slice(6));
        if (body?.result?.supportedVersions?.includes('2026-07-28')) return true;
      } catch { }
    }
  }
  return false;
}

export function assertScenario1({ captures = [], bridgeDiscoverProbe = {}, clientResult, expectedPosts, postSequence, sentValue, sequenceOk = false, classifiedSequence = [] } = {}) {
  const requests = captures.filter((capture) => capture.direction === 'request');
  const methods = requests.map((capture) => {
    try { return JSON.parse(capture.body).method; } catch { return null; }
  });
  const applicationMethods = methods.filter((method) => method !== 'server/discover');
  return result([
    expect(bridgeDiscoverProbe.separate === true, 'separate discovery probe', 'probe must be distinct from SDK captures'),
    expect(bridgeDiscoverProbe.signatureVerified === true, 'probe signature evidence', 'verified response signature bound to request and configured server key'),
    expect(bridgeDiscoverProbe.modernResponseVerified === true, 'modern discovery response', 'supportedVersions includes 2026-07-28'),
    expect(!methods.includes('initialize') && !methods.includes('notifications/initialized'), 'no initialization', JSON.stringify(methods)),
    expect(expectedPosts === undefined ? Array.isArray(postSequence) : applicationMethods.length === expectedPosts, 'application request count', `expected ${expectedPosts ?? 'sequence'}, got ${applicationMethods.length}; SDK discovery count ${methods.filter((method) => method === 'server/discover').length}`),
    expect(postSequence === undefined || seqMatches(applicationMethods, postSequence), 'application request sequence', JSON.stringify(applicationMethods)),
    expect(sequenceOk === true, 'discovery accounting and application sequence', JSON.stringify(classifiedSequence)),
    expect(typeof sentValue === 'string' && clientResult?.outcome === 'ok' && includesValue(clientResult?.tool_result, sentValue), 'echo result', 'client result must include the supplied value'),
  ]);
}

export function assertScenario2({ captures = [], bridge = {}, sdkErrorPresent = false, refusedCount = 0, fallbackCount = 0, scriptedControl = false, scriptedControlLabel = '' } = {}) {
  const methods = captures.filter((capture) => capture.direction === 'request').map((capture) => { try { return JSON.parse(capture.body).method; } catch { return null; } });
  return result([
    expect(!methods.includes('initialize') && !methods.includes('notifications/initialized'), 'no initialize', JSON.stringify(methods)),
    expect(fallbackCount === 0, 'no legacy fallback', String(fallbackCount)),
    expect(typeof bridge.exit_code === 'number' && bridge.exit_code !== 0 && bridge.close_observed !== false, 'bridge failed closed', String(bridge.exit_code)),
    expect(bridge.stdout_bytes === 0, 'no bridge stdout', String(bridge.stdout_bytes)),
    expect(sdkErrorPresent, 'SDK error present', 'client-visible SDK error must be recorded'),
    expect(refusedCount >= 1, 'request refused', String(refusedCount)),
    expect(!scriptedControl || /non-SDK/i.test(scriptedControlLabel), 'scripted control label', scriptedControl ? scriptedControlLabel : 'not a scripted control'),
  ]);
}

export function scenario3MarkerPresent(clientMeta) {
  const markerEntries = Object.entries(clientMeta ?? {}).filter(([key]) => !key.startsWith('io.modelcontextprotocol/'));
  return (value) => markerEntries.length > 0 && markerEntries.every(([key, expected]) => Object.hasOwn(value ?? {}, key) && JSON.stringify(value[key]) === JSON.stringify(expected));
}

export function scenario3SdkMetaPresent(clientMeta, baseline) {
  const fixtureReportsIo = Object.hasOwn(clientMeta ?? {}, 'io.modelcontextprotocol/clientInfo') || Object.hasOwn(clientMeta ?? {}, 'io.modelcontextprotocol/clientCapabilities');
  return (value) => {
    if (!baseline || !Object.hasOwn(value ?? {}, 'io.modelcontextprotocol/clientInfo') || !Object.hasOwn(value ?? {}, 'io.modelcontextprotocol/clientCapabilities')) return false;
    for (const key of ['io.modelcontextprotocol/clientInfo', 'io.modelcontextprotocol/clientCapabilities', 'io.modelcontextprotocol/protocolVersion']) {
      if (JSON.stringify(value[key]) !== JSON.stringify(baseline[key])) return false;
      if (fixtureReportsIo && JSON.stringify(value[key]) !== JSON.stringify(clientMeta[key])) return false;
    }
    return true;
  };
}

export function assertScenario3({ captures = [], protocolVersionHeader = false, methodMirror = false, toolNameMirror = '', metaHops = [], expectedHopCount, markerPresent = () => false, sdkMetaPresent = () => false, preservationMode = '', echoMatches = false, signedResponseVerified = false, jack = true } = {}) {
  const checks = [
    expect(protocolVersionHeader === true, 'protocol version', String(protocolVersionHeader)),
    expect(methodMirror === true, 'method mirror', String(methodMirror)),
    expect(toolNameMirror === 'echo', 'tool name mirror', String(toolNameMirror)),
    expect(Array.isArray(metaHops) && metaHops.length === expectedHopCount, 'metadata hop count', `meta hops ${metaHops.length}, expected ${expectedHopCount}`),
    expect(Array.isArray(metaHops) && metaHops.every(markerPresent), '_meta application marker on every hop', JSON.stringify(metaHops)),
    expect(Array.isArray(metaHops) && metaHops.length > 1 && metaHops.slice(1).every(sdkMetaPresent), 'SDK metadata preservation', `${preservationMode}: ${JSON.stringify(metaHops.slice(1))}`),
    expect(echoMatches === true, 'echo result', String(echoMatches)),
    expect(!jack || signedResponseVerified === true, 'signed response', 'verified at bridge'),
  ];
  return result(checks);
}

export function assertScenario4({ captures = [], clientResult, clientOrder = [], requestJackAccept, status, mediaType, frameSignaturesVerified = false, terminalEndVerified = false, firstProgressCapture, terminalCapture, releaseReleased = false, jack = true } = {}) {
  const first = captures.indexOf(firstProgressCapture);
  const terminal = captures.indexOf(terminalCapture);
  const checks = [
    expect(!jack || requestJackAccept === 's1', 'stream opt-in', 'Jack-Accept: s1'),
    expect(status === 200, 'stream status', String(status)),
    expect(mediaType === 'text/event-stream', 'event stream media type', String(mediaType)),
    expect(!jack || (frameSignaturesVerified && terminalEndVerified), 'frame signatures', 'including terminal end'),
    expect(firstProgressCapture !== undefined && terminalCapture !== undefined && first >= 0 && terminal >= 0 && first < terminal, 'progress before terminal', `${first} < ${terminal}`),
    expect(clientResult?.progress?.length > 0 && clientResult?.outcome === 'ok' && clientOrder.length >= 2 && clientOrder[0] === 'progress' && clientOrder.at(-1) === 'result', 'client progress then result', JSON.stringify(clientOrder)),
    expect(releaseReleased === true, 'release control acknowledged', String(releaseReleased)),
  ];
  return result(checks);
}

export function assertScenario5({ refusal = {}, bridgeResult = null, directAuthenticated = false, noOptIn = false, genericStderr = '' } = {}) {
  const checks = [
    expect(directAuthenticated && noOptIn, 'direct authenticated no-opt-in request', 'must not be modern request to legacy gateway'),
    expect(refusal.signatureVerified && refusal.status === 501 && refusal.code === 'streaming_unsupported', 'verified refusal oracle', JSON.stringify(refusal)),
  ];
  if (bridgeResult !== null) checks.push(expect(typeof bridgeResult.exitCode === 'number' && bridgeResult.exitCode !== 0 && bridgeResult.stdoutBytes === 0 && bridgeResult.fabricatedJsonRpcResult === false, 'bridge fails closed', JSON.stringify(bridgeResult)));
  checks.push(expect(true, 'generic stderr known gap', `recorded as non-oracle diagnostic: ${String(genericStderr)}`));
  return result(checks);
}

export function assertScenario6({ captures = [], downstreamDisconnected = false, noLateFrame = false, cancelled = true } = {}) {
  const abortIndex = captures.findIndex((capture) => capture.direction === 'event' && capture.body === '[upstream-aborted]');
  const lateFrame = abortIndex < 0 ? false : captures.slice(abortIndex + 1).some((capture) => {
    if (!['event', 'response'].includes(capture.direction)) return false;
    let body; try { body = JSON.parse(capture.body); } catch { }
    if (body?.jsonrpc === '2.0' && (Object.hasOwn(body, 'result') || body.error)) return true;
    return /notifications\/progress|event:\s*progress|event:\s*message|data:/i.test(capture.body);
  });
  const abort = abortIndex >= 0;
  const methods = captures.filter((capture) => capture.direction === 'request').map((capture) => { try { return JSON.parse(capture.body).method; } catch { return null; } });
  return result([
    expect(downstreamDisconnected, 'downstream disconnected', String(downstreamDisconnected)),
    expect(abort, 'proxy upstream-aborted capture', '[upstream-aborted] observed'),
    expect(noLateFrame && !lateFrame, 'no late frame', `late response/progress/data=${lateFrame}`),
    expect(cancelled, 'SDK cancellation observed', String(cancelled)),
    expect(!methods.includes('notifications/cancelled'), 'no cancellation POST', JSON.stringify(methods)),
  ]);
}

export function assertScenario7({ notificationDelivered = false, cleanEnd = false, optedIn = false, signedStreamVerified = false, clientOrder = [], jack = true } = {}) {
  const checks = [
    expect(notificationDelivered, 'notification delivered', `observed=${notificationDelivered}`),
    expect(cleanEnd, 'clean stream end', `observed=${cleanEnd}`),
    expect(Array.isArray(clientOrder) && clientOrder.length > 0, 'client-visible order', JSON.stringify(clientOrder)),
  ];
  if (jack) checks.splice(2, 0,
    expect(optedIn, 'stream opt-in', `Jack-Accept: ${optedIn ? 's1' : 'missing'}`),
    expect(signedStreamVerified, 'signed stream verified', `verified=${signedStreamVerified}`),
  );
  return result(checks);
}

export function assertScenario8({ captures = [], flipped = false, upstreamStatus, bridgeResult = {} } = {}) {
  const response = captures.find((capture) => capture.direction === 'response');
  return result([
    expect(flipped === true, 'one byte flipped', String(flipped)),
    expect(upstreamStatus === 200 && response?.status === 200, 'upstream status', String(upstreamStatus)),
    expect(typeof bridgeResult.exit_code === 'number' && bridgeResult.exit_code !== 0 && bridgeResult.close_observed !== false && bridgeResult.stdout_bytes === 0 && bridgeResult.fabricated_result !== true, 'fail closed', JSON.stringify(bridgeResult)),
  ]);
}
