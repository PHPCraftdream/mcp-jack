// Official MCP SDK server for tools/mcp-e2e: one echo tool over Streamable
// HTTP (JSON responses) served on a Unix socket for the jack gateway.
import { appendFileSync, chmodSync } from 'node:fs';
import { createServer } from 'node:http';
import { toNodeHandler } from '@modelcontextprotocol/node';
import { createMcpHandler, McpServer } from '@modelcontextprotocol/server';

const socketPath = process.argv[2];
if (!socketPath) {
  console.error('usage: node server.mjs SOCKET_PATH');
  process.exit(2);
}

const logPath = process.env.E2E_SERVER_LOG;

function logEvent(record) {
  if (!logPath) return;
  try {
    appendFileSync(logPath, JSON.stringify(record) + '\n');
  } catch {
    // logging must never break serving
  }
}

const factory = () => {
  const server = new McpServer({ name: 'e2e-ts-server', version: '0.0.1' });
  server.registerTool(
    'echo',
    { description: 'Echo the text argument back to the caller' },
    async (args) => {
      const text = typeof args?.text === 'string' ? args.text : '';
      return { content: [{ type: 'text', text }] };
    },
  );
  return server;
};

const handler = createMcpHandler(factory, { responseMode: 'json' });
const nodeHandler = toNodeHandler(handler);

const server = createServer((req, res) => {
  logEvent({
    kind: 'request',
    method: req.method,
    path: req.url,
    accept: req.headers.accept ?? null,
    content_type: req.headers['content-type'] ?? null,
    mcp_protocol_version: req.headers['mcp-protocol-version'] ?? null,
  });
  void nodeHandler(req, res).catch((err) => {
    logEvent({ kind: 'handler_error', message: String(err) });
    if (!res.headersSent) {
      res.statusCode = 500;
      res.end();
    }
  });
  res.on('finish', () => {
    logEvent({ kind: 'response', status: res.statusCode });
  });
});

server.listen(socketPath, () => {
  chmodSync(socketPath, 0o600);
  logEvent({ kind: 'listening', path: socketPath });
});

function shutdown() {
  server.close(() => process.exit(0));
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
