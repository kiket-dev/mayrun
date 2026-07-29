# Install mayrun

## From source (today)

```bash
cargo install --git https://github.com/kiket-dev/mayrun --locked
```

Requires Rust 1.85+ (edition 2024 toolchain).

## Releases (planned)

GitHub Releases with cargo-dist binaries for linux/macOS — see execution plan.

## Cursor

1. Install the `mayrun` binary on `PATH`.
2. In the project root: `mayrun init` (or copy `examples/policy.yaml`).
3. Add MCP server config:

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

4. Prefer agent instructions: *Use mayrun_run / mayrun_check instead of unrestricted shell for side effects.*

## Claude Code / other MCP hosts

Same stdio command: `mayrun mcp`. Working directory should be the repo that contains `mayrun.policy.yaml`.

## Verify

```bash
mayrun check 'echo hi'    # Allow under default example policy
mayrun check 'rm -rf /'   # Deny
mayrun status
```
