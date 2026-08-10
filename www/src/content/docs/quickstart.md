---
title: Quickstart
description: From zero to a fail-closed shell gate — init, hook, deny, approve, and read a receipt.
order: 2
section: start
---

## 1. Install and init

```bash
cargo install --git https://github.com/kiket-dev/mayrun --locked
cd your-repo
mayrun init --detect
```

`init --detect` writes `mayrun.policy.yaml` with packs chosen from project signals (Rust, Node, git, …).

## 2. Turn on the shell-hook

```bash
eval "$(mayrun shell-hook)"
```

Every interactive shell command now goes through mayrun before it runs.

## 3. Prove deny

```bash
rm -rf /
# Deny · dangerous-defaults · prints rule_id
```

## 4. Prove allow + receipt

```bash
mayrun run 'git status'
mayrun status
```

Receipts land in `.mayrun/receipts.jsonl` — hash-chained, secrets redacted.

## 5. Human approval when needed

```bash
mayrun run 'git push'
# Require approval →
mayrun run 'git push' --approve
```

## 6. Optional: MCP for Cursor / Claude

```bash
mayrun setup cursor
# or: mayrun setup claude --write
```

Same packs. Same receipts. Agent-agnostic.

## What you just got

| Stage | Result |
| --- | --- |
| **Decide** | YAML packs + rules, fail closed |
| **Prove** | Local receipts with `rule_id` / reason |
| **Confine** | Optional `--sandbox` under Allow |

Deep dive: [Architecture](/docs/architecture) · Compose packs: [Policy](/docs/policy)
