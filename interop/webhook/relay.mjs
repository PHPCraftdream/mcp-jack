// Tamper relay for the webhook matrix (contract section 8): a loopback TLS
// relay that is the sender's endpoint and rewrites a delivery after signing.
import { readFileSync } from 'node:fs';
import tls from 'node:tls';

export const RELAY_PRESETS = Object.freeze(['pass', 'tamper-body', 'tamper-header', 'inflate-length', 'repeat', 'answer-503', 'drop']);

// The declared length the size scenario announces (spec 06 R1.2 cap plus one).
export const INFLATED_LENGTH = 262145;

const HEAD_END = Buffer.from('\r\n\r\n', 'latin1');
const MAX_HEAD_BYTES = 64 * 1024;
const MAX_BODY_BYTES = 1024 * 1024;
const UPSTREAM_TIMEOUT_MS = 15000;
const MARKER = Buffer.from('incident.created', 'latin1');
const REPLACEMENT = Buffer.from('incident.createX', 'latin1');
const ANSWER_503 = Buffer.from('{"error":{"code":"enqueue_failed","message":"enqueue failed"}}', 'utf8');
const STATUS_503_HEAD = Buffer.from(
  `HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: ${ANSWER_503.length}\r\nConnection: close\r\n\r\n`,
  'latin1',
);

// The declared Content-Length of a raw head, or -1 when absent or not decimal.
function declaredLength(headText) {
  let length = -1;
  for (const line of headText.split('\r\n').slice(1)) {
    const colon = line.indexOf(':');
    if (colon === -1) continue;
    if (line.slice(0, colon).trim().toLowerCase() !== 'content-length') continue;
    const value = line.slice(colon + 1).trim();
    if (!/^[0-9]+$/.test(value)) return -1;
    length = Number.parseInt(value, 10);
  }
  return length;
}

// The first value of a raw header line, or '' when the header is absent.
function rawHeader(headText, name) {
  const lower = name.toLowerCase();
  for (const line of headText.split('\r\n').slice(1)) {
    const colon = line.indexOf(':');
    if (colon === -1) continue;
    if (line.slice(0, colon).trim().toLowerCase() === lower) return line.slice(colon + 1).trim();
  }
  return '';
}

// The header lines of a raw head, without the request line or the terminator.
function headerLines(headText) {
  return headText.slice(0, -HEAD_END.length).split('\r\n');
}

// Lowercased header name of a raw header line; '' for a line without a colon.
function headerName(line) {
  const colon = line.indexOf(':');
  return colon === -1 ? '' : line.slice(0, colon).trim().toLowerCase();
}

// Replace (or append) the Content-Length of a raw head, keeping every other line.
function withLength(headText, length) {
  const lines = headerLines(headText);
  const index = lines.findIndex((line, i) => i > 0 && headerName(line) === 'content-length');
  if (index === -1) lines.push(`Content-Length: ${length}`);
  else lines[index] = `Content-Length: ${length}`;
  return lines.join('\r\n') + HEAD_END.toString('latin1');
}

// The next character inside the class of `last`, so the grammar still holds.
function nextInClass(last) {
  if (/[0-9]/.test(last)) return last === '9' ? '0' : String(Number(last) + 1);
  if (/[a-z]/.test(last)) return last === 'z' ? 'a' : String.fromCharCode(last.charCodeAt(0) + 1);
  if (/[A-Z]/.test(last)) return last === 'Z' ? 'A' : String.fromCharCode(last.charCodeAt(0) + 1);
  return null;
}

// Replace the last character of the webhook-id value with another character of
// the same class, so the header grammar still holds but the HMAC cannot.
function tamperHeader(headText) {
  const lines = headerLines(headText);
  const index = lines.findIndex((line, i) => i > 0 && headerName(line) === 'webhook-id');
  if (index === -1) return headText;
  const colon = lines[index].indexOf(':');
  const raw = lines[index].slice(colon + 1);
  const value = raw.trim();
  if (value.length < 2) return headText;
  const replacement = nextInClass(value.slice(-1));
  if (replacement === null) return headText;
  const at = raw.lastIndexOf(value.slice(-1));
  lines[index] = lines[index].slice(0, colon + 1) + raw.slice(0, at) + replacement + raw.slice(at + 1);
  return lines.join('\r\n') + HEAD_END.toString('latin1');
}

// Pure head rewrite of one preset; the unit checks in the self-test call this.
export function transformHead(headText, preset) {
  if (!RELAY_PRESETS.includes(preset)) throw new Error(`unknown relay preset '${preset}'`);
  if (preset !== 'tamper-header' && preset !== 'inflate-length') return headText;
  if (!headText.endsWith(HEAD_END.toString('latin1'))) return headText;
  if (preset === 'tamper-header') return tamperHeader(headText);
  return withLength(headText, INFLATED_LENGTH);
}

// Pure body rewrite of one preset; keeps the length identical when it changes bytes.
export function transformBody(body, preset) {
  if (!RELAY_PRESETS.includes(preset)) throw new Error(`unknown relay preset '${preset}'`);
  const bytes = Buffer.from(body);
  if (preset !== 'tamper-body') return bytes;
  const at = bytes.indexOf(MARKER);
  if (at === -1) return bytes;
  REPLACEMENT.copy(bytes, at);
  return bytes;
}

// The first response head and body of a raw byte stream, or null while incomplete.
function splitResponse(buffered) {
  const end = buffered.indexOf(HEAD_END);
  if (end === -1) return null;
  const headText = buffered.subarray(0, end + HEAD_END.length).toString('latin1');
  const declared = declaredLength(headText);
  if (declared < 0) return null;
  const bodyStart = end + HEAD_END.length;
  if (buffered.length < bodyStart + declared) return null;
  const match = /^HTTP\/1\.[01] (\d{3})/.exec(headText);
  return {
    head: Buffer.from(buffered.subarray(0, end + HEAD_END.length)),
    body: Buffer.from(buffered.subarray(bodyStart, bodyStart + declared)),
    status: match === null ? null : Number.parseInt(match[1], 10),
  };
}

// Start the relay on 127.0.0.1:0 and resolve once it listens. `exchanges()`
// reports every upstream response the relay read, `requests()` how many
// requests it accepted, and `close()` destroys every socket.
// `upstreamPort` is a number, `null`, or a function returning one: the driver
// binds the relay before the receiver exists, because the callback URL carries
// the relay's own port, and hands it the receiver's port once the receiver has
// reported it.
export function startRelay({ upstreamPort = null, preset = 'pass', certPem, keyPem, caPem }) {
  if (!RELAY_PRESETS.includes(preset)) return Promise.reject(new Error(`unknown relay preset '${preset}'`));
  if (typeof upstreamPort !== 'function' && upstreamPort !== null && !Number.isInteger(upstreamPort)) {
    return Promise.reject(new Error(`relay preset '${preset}' has an invalid upstream port`));
  }
  const upstream = () => {
    const port = typeof upstreamPort === 'function' ? upstreamPort() : upstreamPort;
    return Number.isInteger(port) ? port : null;
  };
  let certificate = null;
  let key = null;
  let authority;
  try {
    certificate = readFileSync(certPem);
    key = readFileSync(keyPem);
    authority = caPem === undefined || caPem === null ? undefined : readFileSync(caPem);
  } catch (error) {
    return Promise.reject(error);
  }

  const sockets = new Set();
  const pending = new Set();
  const exchanges = [];
  const observations = [];
  let requests = 0;

  const track = (socket) => {
    sockets.add(socket);
    socket.on('error', () => {});
    socket.on('close', () => sockets.delete(socket));
  };

  // One request upstream: write the whole request at once, read one response.
  const roundTrip = (head, body) => new Promise((resolve) => {
    const request = Buffer.concat([head, body]);
    const port = upstream();
    if (port === null) {
      resolve(null);
      return;
    }
    let settled = false;
    let timer = null;
    const socket = tls.connect({
      host: '127.0.0.1',
      port,
      servername: 'hooks.example.test',
      ...(authority === undefined ? {} : { ca: authority }),
    });
    const finish = (value) => {
      if (settled) return;
      settled = true;
      if (timer !== null) clearTimeout(timer);
      socket.destroy();
      resolve(value);
    };
    track(socket);
    socket.on('secureConnect', () => socket.write(request));
    socket.on('error', () => finish(null));
    socket.on('close', () => finish(null));
    let buffered = Buffer.alloc(0);
    socket.on('data', (chunk) => {
      buffered = Buffer.concat([buffered, chunk]);
      const response = splitResponse(buffered);
      if (response !== null) finish(response);
    });
    // A receiver that never answers must not hold the client open forever.
    timer = setTimeout(() => finish(null), UPSTREAM_TIMEOUT_MS);
  });

  const serve = async (client, headText, rawBody) => {
    const head = Buffer.from(transformHead(headText, preset), 'latin1');
    const body = transformBody(rawBody, preset);
    // The record is pushed before the preset acts, so a phase that answers or
    // drops the request is still evidence for the driver.
    const record = {
      seq: observations.length,
      webhook_id: rawHeader(headText, 'webhook-id'),
      webhook_timestamp: rawHeader(headText, 'webhook-timestamp'),
      signature: rawHeader(headText, 'webhook-signature'),
      body_b64u: Buffer.from(rawBody).toString('base64url'),
      status: null,
    };
    observations.push(record);
    if (preset === 'drop') {
      // R1.9: a dropped connection is a transport failure for the sender.
      client.destroy();
      return;
    }
    if (preset === 'answer-503') {
      record.status = 503;
      client.write(Buffer.concat([STATUS_503_HEAD, ANSWER_503]));
      client.end();
      return;
    }
    const first = await roundTrip(head, body);
    if (first !== null) {
      record.status = first.status;
      exchanges.push({ status: first.status, body_b64u: first.body.toString('base64url') });
      client.write(first.head);
      client.write(first.body);
    }
    // The replay is recorded for the driver but must never reach the sender.
    if (preset === 'repeat') {
      const second = await roundTrip(head, body);
      if (second !== null) {
        exchanges.push({ status: second.status, body_b64u: second.body.toString('base64url') });
        observations.push({ ...record, seq: observations.length, status: second.status });
      }
    }
    client.end();
  };

  // Buffer one request to its declared end, then hand it to the preset.
  const handleClient = (client) => {
    track(client);
    let buffered = Buffer.alloc(0);
    let handled = false;

    const fail = () => {
      client.removeListener('data', onData);
      client.destroy();
    };

    const onData = (chunk) => {
      if (handled) return;
      buffered = buffered.length === 0 ? chunk : Buffer.concat([buffered, chunk]);
      const end = buffered.indexOf(HEAD_END);
      if (end === -1) {
        // A head this large is a harness failure, not something to forward.
        if (buffered.length > MAX_HEAD_BYTES) fail();
        return;
      }
      if (end + HEAD_END.length > MAX_HEAD_BYTES) return fail();
      const headText = buffered.subarray(0, end + HEAD_END.length).toString('latin1');
      const declared = declaredLength(headText);
      if (declared < 0 || declared > MAX_BODY_BYTES) return fail();
      const bodyStart = end + HEAD_END.length;
      if (buffered.length < bodyStart + declared) return;
      handled = true;
      client.removeListener('data', onData);
      const body = Buffer.from(buffered.subarray(bodyStart, bodyStart + declared));
      buffered = Buffer.alloc(0);
      requests++;
      const task = serve(client, headText, body).catch(() => client.destroy());
      pending.add(task);
      task.finally(() => pending.delete(task));
    };

    client.on('data', onData);
    client.on('end', () => { if (!handled) fail(); });
  };

  const server = tls.createServer({ cert: certificate, key }, handleClient);
  server.on('tlsClientError', () => {});

  const close = () => new Promise((resolveClose) => {
    const settle = Promise.allSettled([...pending]);
    const bounded = Promise.race([settle, new Promise((resolveWait) => setTimeout(resolveWait, 10000))]);
    bounded.then(() => {
      for (const socket of sockets) socket.destroy();
      sockets.clear();
      if (!server.listening) {
        resolveClose();
        return;
      }
      server.close(() => resolveClose());
    });
  });

  return new Promise((resolveStart, rejectStart) => {
    server.once('error', rejectStart);
    server.listen(0, '127.0.0.1', () => {
      server.removeListener('error', rejectStart);
      // A post-start listener error has no caller to surface it to and must
      // not take the whole driver down.
      server.on('error', () => {});
      resolveStart({ port: server.address().port, requests: () => requests, exchanges: () => exchanges.slice(), observations: () => observations.map((entry) => ({ ...entry })), close });
    });
  });
}
