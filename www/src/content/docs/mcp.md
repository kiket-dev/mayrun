---
title: MCP & proxy
description: Run mayrun as an MCP server, or put mcp-proxy in front of a high-risk upstream.
order: 12
section: guide
---

## mayrun as MCP server

```bash
mayrun setup cursor
# or mayrun mcp
```

Tools include `mayrun_run`, `mayrun_check`, `mayrun_status`, plus policy suggest/tighten (proposal only).

Prefer agent instructions: *Use mayrun_run / mayrun_check instead of unrestricted shell for side effects.*

## mcp-proxy — gate an upstream

```bash
mayrun mcp-proxy --server-name filesystem -- \
  npx -y @modelcontextprotocol/server-filesystem "$PWD"
```

Intercepts stdio JSON-RPC `tools/call`, evaluates `mcp` matchers (pack [`mcp-safe`](/packs/mcp-safe)), and appends receipts.

| Command | Role |
| --- | --- |
| `mayrun mcp` | mayrun **is** the MCP server |
| `mayrun mcp-proxy -- <upstream…>` | mayrun sits **in front of** another MCP |

Approval for `require_approval`: TTY or `--approve-file` (tool name per line). Fail closed.

## Matcher boundary

- **MCP matchers** apply to `mcp-proxy` tool calls only — they never match shell `run` / `check`.
- **Shell argv/capability matchers** never match MCP calls.
- Extend `mcp-safe` alongside shell packs — it does not weaken `dangerous-defaults`.

See [Policy](/docs/policy) · [Use case: gate MCP](/use-cases/gate-mcp-upstreams)
