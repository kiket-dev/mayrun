# Install mayrun

## Release binaries (cargo-dist)

Download from [GitHub Releases](https://github.com/kiket-dev/mayrun/releases) (macOS / Linux; Windows best-effort). Installers and archives are produced by [cargo-dist](https://opensource.axo.dev/cargo-dist/) on version tags.

```bash
# Example after a release exists:
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/kiket-dev/mayrun/releases/latest/download/mayrun-installer.sh | sh
```

## From source

```bash
cargo install --git https://github.com/kiket-dev/mayrun --locked
```

Requires Rust 1.85+ (edition 2024 toolchain).

## 60s path — shell-hook (recommended)

```bash
cd your-repo
mayrun init --detect          # packs from project signals; --force to overwrite
eval "$(mayrun shell-hook)"   # zsh/bash; fish: mayrun shell-hook | source
```

The hook fail-closes on **deny** / **require_approval** (prints `rule_id` + next steps). It coexists with Cursor/Claude native permissions.

For agent shells that spawn `bash -lc`:

```bash
mayrun shell-wrap -- bash -lc 'cargo test'
```

## Agent MCP setup

```bash
mayrun setup cursor              # print snippet
mayrun setup claude --write      # merge + .bak
mayrun setup opencode --write
```

Or paste manually — Cursor example:

```json
{
  "mcpServers": {
    "mayrun": {
      "command": "mayrun",
      "args": ["mcp"],
      "env": {}
    }
  }
}
```

Prefer agent instructions: *Use mayrun_run / mayrun_check instead of unrestricted shell for side effects.* Working directory should contain `mayrun.policy.yaml`.

### MCP proxy (gate an upstream server)

```bash
# Intercept tools/call; deny/approve/allow via policy (pack mcp-safe)
mayrun mcp-proxy --server-name filesystem -- \
  npx -y @modelcontextprotocol/server-filesystem "$PWD"
```

Use the proxy when the agent already speaks to a third-party MCP. Use `mayrun mcp` when you want mayrun’s own tools. See [policy.md](./policy.md).

## CI Action

```yaml
- uses: kiket-dev/mayrun/.github/actions/mayrun-ci@main
  with:
    license: ${{ secrets.MAYRUN_LICENSE }}  # optional Pro
```

Free: policy compile + advisory. Pro: receipt gate. Docs: [examples/mayrun-ci.md](./examples/mayrun-ci.md), [license.md](./license.md).

## Verify

```bash
mayrun check 'echo hi'    # Allow under default example policy (JSON: decision, rule_id, reason)
mayrun check 'rm -rf /'   # Deny (prints rule_id + reason + how to adjust policy)
mayrun run 'git push'     # Require approval → copy-paste: mayrun run 'git push' --approve
mayrun status             # Recent receipts with rule_id / reason first-class
mayrun metrics --since 7d
mayrun ci                 # Free CI gate locally
mayrun policy packs
```

**Errors:** missing policy, bad YAML, and unknown `extends` packs print the path and a concrete fix. Deny never suggests bypassing Allow via AI — only edit policy or use human `--approve` for `require_approval`.

Optional sandbox (after Allow): `mayrun run 'cargo test' --sandbox` (soft) or `--sandbox=required`.

Policy language: [policy.md](./policy.md). Architecture: [architecture.md](./architecture.md).
