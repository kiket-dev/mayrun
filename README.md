# mayrun

**Agents don’t run dangerous commands until mayrun says they may.**

mayrun is a **local shell gate for coding agents**: evaluate a command against YAML policy (allow / deny / require approval), execute only when allowed, and append a **hash-chained receipt**.

- **Architecture:** [docs/architecture.md](docs/architecture.md) — decide → prove → confine
- Site: [https://mayrun.dev](https://mayrun.dev) — source [`www/`](www/), setup [docs/site.md](docs/site.md)
- Repo: [kiket-dev/mayrun](https://github.com/kiket-dev/mayrun)
- Stack: Rust · CLI shell-hook · MCP stdio
- Sibling: [attestack](https://github.com/kiket-dev/attestack) (proof of AI work). mayrun is the **runtime gate**; Attestack is the optional evidence layer later.

## Quick start (60s — shell-hook)

```bash
cargo install --git https://github.com/kiket-dev/mayrun --locked
# Or download a release binary from GitHub Releases (cargo-dist).
cd your-repo
mayrun init --detect
eval "$(mayrun shell-hook)"          # zsh/bash; fish: mayrun shell-hook | source
rm -rf /                             # Deny + rule_id (fail closed)
mayrun run 'git status'              # Allow → execute + receipt
mayrun run 'git push'                # Require approval
mayrun run 'git push' --approve      # After you confirm
mayrun status
mayrun metrics --since 7d
```

Demo (deny `rm -rf` with `rule_id`):

![mayrun shell-hook denies rm -rf](docs/assets/shell-hook-demo.gif)

([VHS tape](docs/assets/shell-hook-demo.tape) — regenerate with `vhs docs/assets/shell-hook-demo.tape`)

`mayrun shell-wrap -- bash -lc '…'` gates agent `bash -c` shells (policy + execute + receipt).

Coexists with Cursor/Claude native permissions — overlap is defense in depth.

### Agent setup (MCP)

```bash
mayrun setup cursor          # print JSON snippet
mayrun setup claude --write  # merge into .mcp.json (.bak backup)
mayrun setup opencode
```

| Tool | Purpose |
| --- | --- |
| `mayrun_check` | Decision + rule_id / reason / capabilities |
| `mayrun_run` | Decision + execute (`approved=true` after human OK) |
| `mayrun_status` | Policy + recent receipts |
| `mayrun_policy_suggest` | Draft YAML from intent (proposal only) |
| `mayrun_policy_tighten` | Propose rules from receipts (proposal only) |

## Policy

See [docs/policy.md](docs/policy.md) and [examples/policy.yaml](examples/policy.yaml).

- Compose **packs** (`dangerous-defaults`, `secrets-safe`, `exec-escapes`, `network-exfil`, `mcp-safe`, `git-safe`, …) via `extends`
- Structured **rules** with `id`, `effect`, `match` (regex / argv / capabilities / `mcp`), `reason`
- Order: **deny → require_approval → allow → default** (default is deny); pipelines take the **worst** stage
- **Invariant:** only deterministic rules can Allow; AI authoring never auto-applies
- Optional `--sandbox` / `--sandbox=required` (bubblewrap / Seatbelt) after Allow
- **MCP proxy:** `mayrun mcp-proxy -- <upstream…>` gates `tools/call` with receipts
- **CI:** `mayrun ci` / [mayrun-ci Action](docs/examples/mayrun-ci.md) — Free advisory, Pro receipt gate ([license.md](docs/license.md))

```bash
mayrun policy packs
mayrun policy draft "allow local cargo and git; approve push"
mayrun policy tighten
mayrun scoreboard                 # recall / FP on pinned corpus
mayrun ci                         # local CI gate
```

Receipts land in `.mayrun/receipts.jsonl` (commands redacted for secrets; gitignored locally).

## Testing / e2e

```bash
cargo test                          # unit + pack corpus + MCP protocol + mcp-proxy e2e
mayrun scoreboard --corpus tests/corpus.yaml
./e2e/agents/run-opencode.sh        # opt-in real agent (needs opencode + model auth)
./e2e/agents/run-cursor-agent.sh    # best-effort; SKIP if MCP tools not injected
```

See [e2e/agents/README.md](e2e/agents/README.md). Agent e2e is weekly/`workflow_dispatch`, not PR-blocking.

## Why this exists

Seat SaaS and “AI governance dashboards” don’t stop an agent from `rm -rf` or `DROP TABLE`. mayrun sits on the **write path**: shell-hook / MCP / CLI choke point, local-first, single binary — complementary to vendor permissions and org platforms (e.g. Cloudflare OS), not a substitute org OS.

Free local gate → paid CI Pro license. See [docs/plans/strategy.md](docs/plans/strategy.md) and [mayrun.dev/#pricing](https://mayrun.dev/#pricing).

## Development

```bash
cargo test
cargo run -- init --detect
cargo run -- check 'cargo test'
cargo run -- shell-hook
cargo run -- mcp
```

## License

MIT
