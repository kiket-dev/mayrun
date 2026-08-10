---
title: mcp-safe
description: MCP tool matchers for mcp-proxy — deny sensitive write, approve shell tools, allow read.
effect: mixed
packId: mcp-safe
order: 4
---

For `mayrun mcp-proxy` only. Deny delete / sensitive path writes; approve shell-like tools; allow common list/read. Extend alongside shell packs — does not weaken `dangerous-defaults`.
