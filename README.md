# mayrun

**Agents don’t run dangerous commands until mayrun says they may.**

mayrun is a **policy gate for coding-agent side effects**: evaluate a shell command against a YAML policy (allow / deny / require approval), execute only when allowed, and append a **hash-chained receipt**.

- Site: [https://mayrun.dev](https://mayrun.dev) — source [`www/`](www/), setup [docs/site.md](docs/site.md)
- Repo: [kiket-dev/mayrun](https://github.com/kiket-dev/mayrun)
- Stack: Rust · MCP stdio · CLI
- Sibling: [attestack](https://github.com/kiket-dev/attestack) (proof of AI work). mayrun is the **runtime gate**; Attestack is the optional evidence layer later.

## Quick start

```bash
cargo install --git https://github.com/kiket-dev/mayrun
cd your-repo
mayrun init
mayrun check 'rm -rf /'          # Deny
mayrun run 'git status'          # Allow → execute
mayrun run 'git push'            # Require approval
mayrun run 'git push' --approve  # After you confirm
mayrun status
```

### Cursor MCP

```json
{
  "mcpServers": {
    "mayrun": {
      "command": "mayrun",
      "args": ["mcp"]
    }
  }
}
```

Run `mayrun init` in the workspace so `mayrun.policy.yaml` exists. Tools:

| Tool | Purpose |
| --- | --- |
| `mayrun_check` | Decision + rule_id / reason / capabilities |
| `mayrun_run` | Decision + execute (`approved=true` after human OK) |
| `mayrun_status` | Policy + recent receipts |
| `mayrun_policy_suggest` | Draft YAML from intent (proposal only) |
| `mayrun_policy_tighten` | Propose rules from receipts (proposal only) |

## Policy

See [docs/policy.md](docs/policy.md) and [examples/policy.yaml](examples/policy.yaml).

- Compose **packs** (`dangerous-defaults`, `secrets-safe`, `exec-escapes`, `git-safe`, `rust-dev`, `read-only`, …) via `extends`
- Structured **rules** with `id`, `effect`, `match` (regex / argv / capabilities), `reason`
- Order: **deny → require_approval → allow → default** (default is deny); pipelines take the **worst** stage
- **Invariant:** only deterministic rules can Allow; AI authoring never auto-applies
- Runs **alongside** agent permission systems — overlap is defense in depth

```bash
mayrun policy packs
mayrun policy draft "allow local cargo and git; approve push"
mayrun policy tighten
```

Receipts land in `.mayrun/receipts.jsonl` (gitignored locally; CI Pro later).

## Testing / e2e

```bash
cargo test                          # unit + pack corpus + MCP protocol e2e
./e2e/agents/run-opencode.sh        # opt-in real agent (needs opencode + model auth)
./e2e/agents/run-cursor-agent.sh    # best-effort; SKIP if MCP tools not injected
```

See [e2e/agents/README.md](e2e/agents/README.md). Agent e2e is weekly/`workflow_dispatch`, not PR-blocking.

## Why this exists

Seat SaaS and “AI governance dashboards” don’t stop an agent from `rm -rf` or `DROP TABLE`. mayrun sits on the **write path**: MCP/CLI choke point, local-first, single binary.

Kiket commercial product work is **frozen**; this is the monetization wedge (free local → paid CI gate later). See [docs/plans/strategy.md](docs/plans/strategy.md).

## Development

```bash
cargo test
cargo run -- init
cargo run -- check 'cargo test'
cargo run -- mcp
```

## License

MIT
