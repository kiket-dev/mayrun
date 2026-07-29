# mayrun

**Agents don’t run dangerous commands until mayrun says they may.**

mayrun is a **policy gate for coding-agent side effects**: evaluate a shell command against a YAML policy (allow / deny / require approval), execute only when allowed, and append a **hash-chained receipt**.

- Site: [https://mayrun.dev](https://mayrun.dev) (registering)
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
| `mayrun_check` | Decision only |
| `mayrun_run` | Decision + execute (`approved=true` after human OK) |
| `mayrun_status` | Policy + recent receipts |

## Policy

See [examples/policy.yaml](examples/policy.yaml). Order: **deny → require_approval → allow → default** (default is deny). Patterns are Rust regexes.

Receipts land in `.mayrun/receipts.jsonl` (gitignored locally; CI Pro later).

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
