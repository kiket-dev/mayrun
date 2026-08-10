# Architecture

mayrun is a **local shell gate for coding agents**. It sits on the write path: evaluate a command against deterministic YAML policy, execute only when allowed (or after human `--approve`), and append a hash-chained receipt.

## Decide → prove → confine

| Stage | What | Where |
| --- | --- | --- |
| **Decide** | Policy packs + rules (`deny` → `require_approval` → `allow` → default deny) | `mayrun.policy.yaml`, built-in `packs/` |
| **Prove** | Hash-chained JSONL receipts (`rule_id`, `reason`, redacted command) | `.mayrun/receipts.jsonl` |
| **Confine** | Optional local OS sandbox (bubblewrap / Seatbelt) under an Allow | `mayrun run --sandbox` |

**Invariant:** only deterministic rules and a human `--approve` / MCP `approved=true` can **Allow**. AI draft/tighten tools propose YAML only — they never grant runtime Allow.

## 60-second path (shell-hook)

```bash
cargo install --git https://github.com/kiket-dev/mayrun --locked   # or release binary
cd your-repo && mayrun init --detect
eval "$(mayrun shell-hook)"    # zsh/bash; fish: mayrun shell-hook | source
rm -rf /                       # denied with rule_id — fail closed
```

Agent shells that spawn `bash -lc '…'` can use `mayrun shell-wrap -- bash -lc '…'` so the command is gated, executed, and receipted in one step.

MCP (`mayrun mcp` / `mayrun setup cursor`) remains supported; shell-hook is the primary install path for strangers.

## Versus vendor permissions alone

Cursor/Claude/OpenCode permission prompts are host-specific and incomplete for portable shell mediate. mayrun is **agent-agnostic**: same packs and receipts whether the agent is Cursor, Claude Code, or a raw shell. Overlap with vendor allowlists is **defense in depth**, not duplication of a full harness profile.

## Complementary to org platforms

Products like Cloudflare OS Gatekeepers target org-wide browser agent workspaces and systems-of-record access. mayrun does **not** compete there. It gates **local** coding-agent side effects (`rm`, `curl|sh`, `git push`) on the developer laptop — the layer those platforms do not replace for everyday IDE agents.

## Scoreboard methodology

Pinned fixtures under `tests/corpus.yaml` (+ optional `corpus/` pins) drive `mayrun scoreboard`: recall on unsafe cases and false-positive rate on safe cases. CI fails pack PRs that regress recall. No live LLM; no unbounded network fetch in PR CI. See [policy.md](./policy.md).

## Honest non-goals

- Enterprise SSO / hosted multi-tenant control plane
- Org agent workspace or Gatekeeper-style service mesh
- Live-LLM Allow decisions
- Full agent APM (use `mayrun metrics` for offline local receipt stats only)
- Windows-perfect sandbox v1
- Competing with hosted sandbox SDKs for cloud agents
- mTLS MCP mesh / marketplace scanning

## MCP proxy

`mayrun mcp-proxy -- <upstream mcp…>` intercepts stdio JSON-RPC `tools/call`, evaluates `mcp` matchers (pack `mcp-safe`), and appends receipts. Prefer this when an agent talks to a high-risk upstream MCP (filesystem write, shell). Prefer `mayrun mcp` when you want mayrun’s own tools (`mayrun_run` / `mayrun_check`) instead of wrapping another server.

## CI Pro

`mayrun ci` + [mayrun-ci Action](./examples/mayrun-ci.md): Free validates policy; Pro (signed license) requires receipt evidence. See [license.md](./license.md).

## Related docs

- [install.md](./install.md) — install, setup, verify
- [policy.md](./policy.md) — packs, matchers, capabilities
- [license.md](./license.md) — Pro CI license + Stripe runbook
- [site.md](./site.md) — mayrun.dev
