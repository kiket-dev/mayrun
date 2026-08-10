---
title: Install
description: Install the mayrun binary, enable shell-hook in 60 seconds, and wire Cursor, Claude, or OpenCode.
order: 1
section: start
---

## Release binaries

Download from [GitHub Releases](https://github.com/kiket-dev/mayrun/releases) (macOS / Linux; Windows best-effort). Installers are produced by cargo-dist on version tags.

```bash
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/kiket-dev/mayrun/releases/latest/download/mayrun-installer.sh | sh
```

## From source

```bash
cargo install --git https://github.com/kiket-dev/mayrun --locked
```

Requires Rust 1.85+ (edition 2024 toolchain).

## 60s path — shell-hook (recommended)

```bash
cd your-repo
mayrun init --detect
eval "$(mayrun shell-hook)"   # fish: mayrun shell-hook | source
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

## Verify

```bash
mayrun check 'echo hi'    # Allow
mayrun check 'rm -rf /'   # Deny
mayrun run 'git push'     # Require approval → --approve
mayrun status
mayrun metrics --since 7d
mayrun policy packs
```

Next: [Quickstart](/docs/quickstart) · [Policy](/docs/policy) · [Architecture](/docs/architecture)
