---
title: Architecture
description: Decide → prove → confine. Local write-path gate for coding agents — not a dashboard.
order: 10
section: guide
---

mayrun is a **local shell gate for coding agents**. It sits on the write path: evaluate a command against deterministic YAML policy, execute only when allowed (or after human `--approve`), and append a hash-chained receipt.

## Decide → prove → confine

| Stage | What | Where |
| --- | --- | --- |
| **Decide** | Policy packs + rules (`deny` → `require_approval` → `allow` → default deny) | `mayrun.policy.yaml`, built-in packs |
| **Prove** | Hash-chained JSONL receipts (`rule_id`, `reason`, redacted command) | `.mayrun/receipts.jsonl` |
| **Confine** | Optional local OS sandbox (bubblewrap / Seatbelt) under an Allow | `mayrun run --sandbox` |

**Invariant:** only deterministic rules and a human `--approve` / MCP `approved=true` can **Allow**. AI draft/tighten tools propose YAML only — they never grant runtime Allow.

## Versus vendor permissions alone

Cursor/Claude/OpenCode permission prompts are host-specific. mayrun is **agent-agnostic**: same packs and receipts whether the agent is Cursor, Claude Code, or a raw shell. Overlap with vendor allowlists is **defense in depth**.

## Complementary to org platforms

Products like Cloudflare OS Gatekeepers target org-wide browser agent workspaces. mayrun does **not** compete there. It gates **local** coding-agent side effects (`rm`, `curl|sh`, `git push`) on the developer laptop.

## Surfaces

| Surface | When |
| --- | --- |
| `shell-hook` / `shell-wrap` | Primary stranger path — gate the interactive shell |
| `mayrun mcp` | Agent uses mayrun tools (`mayrun_run`, `mayrun_check`, …) |
| `mayrun mcp-proxy` | Gate an upstream MCP `tools/call` |
| `mayrun-ci` | Free policy compile; Pro receipt gate on PRs |

## Scoreboard

Pinned fixtures drive `mayrun scoreboard`: recall on unsafe cases and false-positive rate on safe cases. CI fails pack PRs that regress recall. No live LLM in the Allow path.

## Honest non-goals

- Enterprise SSO / hosted multi-tenant control plane
- Org agent workspace or Gatekeeper-style service mesh
- Live-LLM Allow decisions
- Full agent APM
- Windows-perfect sandbox v1
- Competing with hosted sandbox SDKs for cloud agents

See also: [Policy](/docs/policy) · [MCP](/docs/mcp) · [CI](/docs/ci)
