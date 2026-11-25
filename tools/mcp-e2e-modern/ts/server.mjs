import { createRequire } from 'node:module';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { dirname, join } from 'node:path';
import { toNodeHandler, toWebRequest } from '@modelcontextprotocol/node';
import { createMcpHandler, fromJsonSchema, isLegacyRequest, McpServer } from '@modelcontextprotocol/server';

const args = process.argv.slice(2);
function option(name, fallback) {
  const i = args.indexOf(name);
  return i < 0 ? fallback : args[i + 1];
}
function addressOf(server) {
  const a = server.address();
  return `http://127.0.0.1:${a.port}`;
}
async function sdkIdentity() {
  const require = createRequire(import.meta.url);
  let path;
  try { path = require.resolve('@modelcontextprotocol/server/package.json'); }
  catch { path = require.resolve('@modelcontextprotocol/server'); }
  let dir = path;
  if (!path.endsWith('package.json')) dir = join(dirname(path), '..', 'package.json');
  const pkg = JSON.parse(await readFile(dir, 'utf8'));
  return { name: pkg.name, version: pkg.version };
}

const held = new Map();
const cancelled = new Set();
const cap = (id, status, evidence) => ({ id, status, evidence });
const capabilities = [
  cap('stdio_client', 'supported', 'client uses StdioClientTransport({command,args,stderr:"pipe"}) in client.mjs'),
  cap('streamable_http_server', 'supported', 'createMcpHandler and toNodeHandler in server.mjs'),
  cap('stateless', 'supported', 'createMcpHandler legacy:"stateless" per-request fallback'),
  cap('progress', 'supported', 'ctx.mcpReq.notify({method:"notifications/progress"}) in server.mjs'),
  cap('cancellation', 'supported', 'ctx.mcpReq.signal and client callTool RequestOptions.signal'),
  cap('subscriptions_listen', 'supported', 'createMcpHandler handler.notify and Client.listen(filter)'),
  cap('server_discover', 'supported', 'createMcpHandler modern leg installs server/discover'),
  cap('protocol_2026_07_28', 'supported', 'createMcpHandler serves per-request modern 2026-07-28 envelopes; --legacy-only refuses every SDK-classified modern request via isLegacyRequest(toWebRequest(req)) before dispatch (covers envelope-only and header-only traffic)'),
];
const factory = () => {
  const mcp = new McpServer({ name: 'mcp-e2e-modern-ts', version: '1' });
  mcp.registerTool('echo', { description: 'Return value unchanged', inputSchema: fromJsonSchema({ type: 'object', properties: { value: {} }, required: ['value'], additionalProperties: false }) }, async ({ value }) => ({
    content: [{ type: 'text', text: JSON.stringify(value) }],
  }));
  mcp.registerTool('progress', { description: 'Emit progress updates', inputSchema: fromJsonSchema({ type: 'object', properties: { count: { type: 'number' }, hold: { type: 'boolean' }, call_id: { type: 'string' } }, required: ['count'], additionalProperties: false }) }, async ({ count, hold, call_id }, ctx) => {
    const token = ctx.mcpReq._meta?.progressToken;
    let release;
    let onAbort;
    let heldPromise;
    if (hold && call_id) {
      cancelled.delete(call_id);
      heldPromise = new Promise((resolve) => { release = resolve; });
      onAbort = () => { cancelled.add(call_id); held.delete(call_id); release(); };
      held.set(call_id, { resolve: release, signal: ctx.mcpReq.signal });
      if (ctx.mcpReq.signal.aborted) onAbort();
      else ctx.mcpReq.signal.addEventListener('abort', onAbort, { once: true });
    }
    for (let n = 1; n <= count; n++) {
      if (token !== undefined) await ctx.mcpReq.notify({ method: 'notifications/progress', params: { progressToken: token, progress: n, total: count } });
    }
    if (heldPromise) {
      await heldPromise;
      ctx.mcpReq.signal.removeEventListener('abort', onAbort);
    }
    return { content: [{ type: 'text', text: `progress:${count}:${call_id ?? ''}` }], structuredContent: { count, call_id: call_id ?? null } };
  });
  return mcp;
};
const legacyOnly = args.includes('--legacy-only');
const handler = createMcpHandler(factory, { responseMode: 'auto', legacy: 'stateless' });
const mcpNodeHandler = toNodeHandler(handler);
setInterval(() => handler.notify.toolsChanged(), 1000).unref();
const mainServer = createServer((req, res) => {
  void (async () => {
    if (legacyOnly) {
      const legacy = await isLegacyRequest(toWebRequest(req)).catch(() => false);
      if (!legacy) {
        res.writeHead(400, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32600, message: 'legacy-only fixture rejects modern protocol' } }));
        return;
      }
    }
    await mcpNodeHandler(req, res);
  })().catch((error) => {
    process.stderr.write(`MCP handler error: ${String(error)}\n`);
    if (!res.headersSent) { res.statusCode = 500; res.end(); }
  });
});
const controlServer = createServer((req, res) => {
  const send = (status, data) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(data)); };
  if (req.method === 'POST' && req.url === '/v1/release') {
    let text = '';
    req.on('data', (chunk) => { text += chunk; });
    req.on('end', () => {
      let id;
      try { id = JSON.parse(text).call_id; } catch { }
      const entry = held.get(id);
      if (entry) { held.delete(id); entry.resolve(); }
      process.stderr.write(`control release ${String(id)} ${Boolean(entry)}\n`);
      send(entry ? 200 : 404, { released: Boolean(entry), call_id: id ?? null });
    });
  } else if (req.method === 'GET' && new URL(req.url, 'http://127.0.0.1').pathname === '/v1/cancelled') {
    const id = new URL(req.url, 'http://127.0.0.1').searchParams.get('call_id') ?? '';
    send(200, { call_id: id, cancelled: cancelled.has(id) });
  } else send(404, { error: 'not found' });
});
let sdk;
try {
  sdk = await sdkIdentity();
  const listen = (server, value) => new Promise((resolve, reject) => {
    const [host, portText] = value.split(':');
    server.once('error', reject);
    server.listen(Number(portText), host, () => { server.removeListener('error', reject); resolve(); });
  });
  await listen(mainServer, option('--listen', '127.0.0.1:0'));
  await listen(controlServer, option('--control-listen', '127.0.0.1:0'));
  process.stdout.write(`${JSON.stringify({ address: addressOf(mainServer), control_address: addressOf(controlServer), sdk, capabilities })}\n`);
} catch (error) {
  process.stderr.write(`server startup failed: ${String(error)}\n`);
  process.exitCode = 1;
}
async function shutdown() {
  await handler.close().catch(() => {});
  await Promise.all([mainServer, controlServer].map((server) => new Promise((resolve) => server.close(resolve))));
}
process.once('SIGTERM', () => { void shutdown(); });
process.once('SIGINT', () => { void shutdown(); });
