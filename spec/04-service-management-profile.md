# 04. Service-management profile

Status: draft v0.1, optional and informative. This profile is not part of the transport.

mcp-jack protects any MCP server. One common use is operating a service: observing it, changing its settings and restarting it. This document names a small set of ordinary MCP tools for that purpose and a policy that scopes them. Services are free to expose other tools or different names; nothing in 01-03 depends on this profile.

The `svc.` prefix is used instead of `jack.` because the `jack.` prefix is reserved for protocol-native tools (see [03-user-management.md](03-user-management.md)).

## 1. Tools

| Tool | Purpose | Suggested scope |
|---|---|---|
| `svc.status` | State, version, uptime and health of the service. | `read` |
| `svc.logs.query` | Bounded, paginated log query with optional filters. Output is untrusted data. | `read` |
| `svc.metrics.get` | Current metrics; formats follow Prometheus or OpenTelemetry. | `read` |
| `svc.config.get` | Current configuration with secret values masked. | `read` |
| `svc.config.validate` | Validate a proposed configuration and return a diff, without applying it. | `read` |
| `svc.config.set` | Apply a configuration; SHOULD require a prior successful `svc.config.validate` of the same content. | `config:write` |
| `svc.reload` | Reload configuration without dropping the process. Idempotent. | `lifecycle` |
| `svc.restart` | Restart the service. Rate-limited. | `lifecycle` |

Argument and result schemas are defined in a later revision of this profile.

## 2. Suggested policy

```json
{
  "version": 1,
  "rules": [
    { "match": { "method": "ping" }, "scope": null },
    { "match": { "method": "tools/list" }, "scope": null },
    { "match": { "method": "notifications/*" }, "scope": null },
    { "match": { "method": "tools/call", "tool": "svc.config.set" }, "scope": "config:write" },
    { "match": { "method": "tools/call", "tool": "svc.reload" }, "scope": "lifecycle" },
    { "match": { "method": "tools/call", "tool": "svc.restart" }, "scope": "lifecycle" },
    { "match": { "method": "tools/call", "tool": "svc.*" }, "scope": "read" }
  ]
}
```

The specific `svc.config.set`, `svc.reload` and `svc.restart` rules come before the `svc.*` rule, so first-match evaluation gives the tighter scope to the dangerous tools and `read` to the rest.

## 3. Guidance

- **Secrets are write-only.** No tool returns a secret value; configuration views mask them.
- **Logs are untrusted input.** A log line can contain instructions aimed at an agent. Agents that read logs SHOULD hold only `read`, never `config:write`, `lifecycle` or `admin`.
- **Destructive operations** (`svc.restart`, `svc.config.set`) SHOULD be idempotent where possible, rate-limited, and recorded in the audit log with the caller's key.
