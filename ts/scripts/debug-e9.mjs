import { createServer, request } from "node:http";
import { serveNode } from "../dist/server/node.js";

const log = (...a) => console.log(new Date().toISOString().slice(17, 23), ...a);
const server = createServer((req, res) => {
  log("server: request", req.method, JSON.stringify(req.headers));
  req.on("data", (c) => log("server: data", c.length));
  req.on("end", () => log("server: end"));
  res.on("finish", () => log("server: res finish"));
  serveNode(async () => new Response("x"))(req, res);
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const port = server.address().port;
const req = request({ host: "127.0.0.1", port, method: "POST", path: "/mcp", headers: {}, signal: AbortSignal.timeout(3000) });
req.on("response", (res) => {
  log("client: response", res.statusCode);
  res.on("data", (c) => log("client: res data", c.length));
  res.on("end", () => log("client: res end"));
});
req.on("error", (e) => log("client: error", e.code ?? e.name));
req.on("finish", () => log("client: req finish"));
req.write(Buffer.alloc((1 << 20) + 1, 120));
req.end();
setTimeout(() => { log("done"); process.exit(0); }, 3500);
