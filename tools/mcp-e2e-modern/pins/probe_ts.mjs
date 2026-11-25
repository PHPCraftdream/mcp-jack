const capabilities = [
  'protocol_2026_07_28', 'client_stdio_transport', 'server_streamable_http_transport',
  'stateless_server_mode', 'progress_notifications_tool_call', 'client_cancellation_api',
  'subscriptions_listen', 'server_discover',
];
const results = [];
const emit = (capability, ok, detail) => results.push({ capability, ok, detail });
try {
  const client = await import('@modelcontextprotocol/client/stdio');
  emit('client_stdio_transport', typeof client.StdioClientTransport === 'function', 'client/stdio.StdioClientTransport');
} catch {
  emit('client_stdio_transport', false, 'no_probe');
}
for (const capability of capabilities) {
  if (capability !== 'client_stdio_transport') emit(capability, false, 'no_probe');
}
for (const result of results) console.log(JSON.stringify(result));
