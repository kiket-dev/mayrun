---
title: Gate high-risk MCP upstreams
description: Put mcp-proxy in front of filesystem or shell MCPs and evaluate tools/call.
audience: Teams wiring third-party MCP servers
pack: mcp-safe
order: 6
---

When the agent already speaks to a third-party MCP, wrap it:

```bash
mayrun mcp-proxy --server-name filesystem -- \
  npx -y @modelcontextprotocol/server-filesystem "$PWD"
```

[`mcp-safe`](/packs/mcp-safe) denies sensitive writes, approves shell-like tools, and allows common reads. Receipts still append. See [MCP docs](/docs/mcp).
