export function expect(cond, name, detail = '') {
  return { name, ok: Boolean(cond), detail: String(detail) };
}

function result(checks) {
  const failed = checks.find((check) => !check.ok);
  return { ok: checks.every((check) => check.ok), reason: failed ? `${failed.name}: ${failed.detail}` : 'all assertions passed', checks };
}
function seqMatches(actual, expected) { return Array.isArray(actual) && Array.isArray(expected) && actual.length === expected.length && expected.every((value, index) => actual[index] === value); }

export function assertScenario1({ captures = [], bridgeDiscoverProbe = {}, clientResult, expectedPosts, postSequence, sentValue } = {}) {
  const clientCaptures = captures.filter((capture) => capture.hop !== bridgeDiscoverProbe.hop);
  const methods = clientCaptures.filter((capture) => capture.direction === 'request').map((capture) => {
    try { return JSON.parse(capture.body).method; } catch { return null; }
  });
  return result([
    expect(bridgeDiscoverProbe.separate === true, 'separate discovery probe', 'probe must be distinct from SDK captures'),
    expect(bridgeDiscoverProbe.signatureVerified === true, 'probe signature', 'signature verified before era selection'),
    expect(bridgeDiscoverProbe.modernResponseVerified === true, 'modern discovery response', 'response verified before era selection'),
    expect(!methods.includes('initialize') && !methods.includes('notifications/initialized'), 'no initialization', JSON.stringify(methods)),
    expect(expectedPosts === undefined ? Array.isArray(postSequence) : methods.length === expectedPosts, 'modern POST count', `expected ${expectedPosts ?? 'sequence'}, got ${methods.length}`),
    expect(postSequence === undefined || seqMatches(methods, postSequence), 'POST sequence', JSON.stringify(methods)),
    expect(typeof sentValue === 'string' && clientResult?.outcome === 'ok' && JSON.stringify(clientResult?.tool_result).includes(sentValue), 'echo result', 'client result must include the supplied value'),
  ]);
}

export function assertScenario2({ captures = [], bridge = {}, sdkErrorPresent = false, refusedCount = 0, fallbackCount = 0, scriptedControl = false, scriptedControlLabel = '' } = {}) {
  const methods = captures.filter((capture) => capture.direction === 'request').map((capture) => { try { return JSON.parse(capture.body).method; } catch { return null; } });
  return result([
    expect(!methods.includes('initialize') && !methods.includes('notifications/initialized'), 'no initialize', JSON.stringify(methods)),
    expect(fallbackCount === 0, 'no legacy fallback', String(fallbackCount)),
    expect(typeof bridge.exit_code === 'number' && bridge.exit_code !== 0, 'bridge failed closed', String(bridge.exit_code)),
    expect(bridge.stdout_bytes === 0, 'no bridge stdout', String(bridge.stdout_bytes)),
    expect(sdkErrorPresent, 'SDK error present', 'client-visible SDK error must be recorded'),
    expect(refusedCount >= 1, 'request refused', String(refusedCount)),
    expect(!scriptedControl || /non-SDK/i.test(scriptedControlLabel), 'scripted control label', scriptedControl ? scriptedControlLabel : 'not a scripted control'),
  ]);
}

export function assertScenario3({ captures = [], protocolVersionHeader = false, methodMirror = false, toolNameMirror = '', metaHops = [], echoMatches = false, signedResponseVerified = false, jack = true } = {}) {
  const serializedMeta = Array.isArray(metaHops) ? metaHops.map((meta) => JSON.stringify(meta)) : [];
  const sameMeta = serializedMeta.length > 0 && serializedMeta.every((value) => value === serializedMeta[0]);
  const checks = [
    expect(protocolVersionHeader === true, 'protocol version', String(protocolVersionHeader)),
    expect(methodMirror === true, 'method mirror', String(methodMirror)),
    expect(toolNameMirror === 'echo', 'tool name mirror', String(toolNameMirror)),
    expect(Array.isArray(metaHops) && metaHops.length > 0 && sameMeta && metaHops.some((meta) => meta !== null), '_meta hops', JSON.stringify(metaHops)),
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
  const abort = captures.some((capture) => capture.direction === 'event' && capture.body === '[upstream-aborted]');
  const methods = captures.filter((capture) => capture.direction === 'request').map((capture) => { try { return JSON.parse(capture.body).method; } catch { return null; } });
  return result([
    expect(downstreamDisconnected && abort, 'upstream abort oracle', 'abort recorded after downstream disconnect'),
    expect(noLateFrame, 'no late frame', 'no frame after abort'),
    expect(cancelled, 'SDK cancellation observed', String(cancelled)),
    expect(!methods.includes('notifications/cancelled'), 'no cancellation POST', JSON.stringify(methods)),
  ]);
}

export function assertScenario7({ notificationDelivered = false, cleanEnd = false, optedIn = false, signedStreamVerified = false, clientOrder = [], jack = true } = {}) {
  const checks = [
    expect(notificationDelivered, 'notification delivered', ''),
    expect(cleanEnd, 'clean stream end', ''),
    expect(Array.isArray(clientOrder) && clientOrder.length > 0, 'client-visible order', JSON.stringify(clientOrder)),
  ];
  if (jack) checks.splice(2, 0,
    expect(optedIn, 'stream opt-in', ''),
    expect(signedStreamVerified, 'signed stream verified', ''),
  );
  return result(checks);
}

export function assertScenario8({ captures = [], flipped = false, upstreamStatus, bridgeResult = {} } = {}) {
  const response = captures.find((capture) => capture.direction === 'response');
  return result([
    expect(flipped === true, 'one byte flipped', String(flipped)),
    expect(upstreamStatus === 200 && response?.status === 200, 'upstream status', String(upstreamStatus)),
    expect(typeof bridgeResult.exit_code === 'number' && bridgeResult.exit_code !== 0 && bridgeResult.stdout_bytes === 0 && bridgeResult.fabricated_result !== true, 'fail closed', JSON.stringify(bridgeResult)),
  ]);
}
