// Official MCP SDK client for tools/mcp-e2e: spawns the jack bridge over the
// real stdio transport, lists tools, calls echo, prints one JSON summary.
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';

const [jackBin, configPath, marker] = process.argv.slice(2);
if (!jackBin || !configPath || !marker) {
  console.error('usage: node client.mjs JACK_BIN CONFIG_PATH MARKER');
  process.exit(2);
}

const transport = new StdioClientTransport({
  command: jackBin,
  args: ['bridge', '--config', configPath],
  stderr: 'pipe',
});

const client = new Client(
  { name: 'e2e-ts-client', version: '0.0.1' },
  { versionNegotiation: { mode: 'legacy' }, supportedProtocolVersions: ['2025-11-25'] },
);

try {
  await client.connect(transport);

  let stderrBytes = null;
  const stderrStream = transport.stderr ?? null;
  if (stderrStream) {
    stderrBytes = 0;
    void (async () => {
      try {
        for await (const chunk of stderrStream) stderrBytes += chunk.length;
      } catch {
        // closed while draining; the count stays partial
      }
    })();
  }

  const tools = await client.listTools();
  if (!Array.isArray(tools.tools) || !tools.tools.some((tool) => tool.name === 'echo')) {
    throw new Error('tools/list: echo tool missing');
  }

  const result = await client.callTool({ name: 'echo', arguments: { text: marker } });
  if (result.isError || !JSON.stringify(result).includes(marker)) {
    throw new Error('tools/call: echo marker missing');
  }

  console.log(JSON.stringify({ ok: true, client: 'ts', echo_listed: true, marker_found: true, bridge_stderr_bytes: stderrBytes }));
  process.exit(0);
} catch (err) {
  console.error(String(err));
  process.exit(1);
} finally {
  try {
    await client.close();
  } catch {
    // close errors must not mask the exit path
  }
}
