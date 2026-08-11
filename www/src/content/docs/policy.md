---
title: Policy
description: YAML packs and structured rules. Deny → require approval → allow → default deny.
order: 11
section: guide
---

mayrun policies are YAML. Evaluation is deterministic and offline:

**deny → require_approval → allow → default** (default is deny).

Only deterministic rules (and a human `--approve`) can produce **Allow**. AI helpers (`mayrun policy draft` / `tighten`) emit **proposed YAML** for human review — they never grant runtime Allow.

Pipeline awareness: top-level `|`, `|&`, `&&`, `||`, and `;` stages are evaluated separately; the **worst** decision wins. Capabilities are unioned across stages.

## Minimal pack-based policy

```yaml
apiVersion: mayrun.dev/v1
default: deny
extends:
  - pack: dangerous-defaults
  - pack: shell-basics
  - pack: secrets-safe
  - pack: exec-escapes
  - pack: git-safe
  - pack: rust-dev
```

Browse the catalog: [Packs](/packs). Language packs (`python-dev`, `go-dev`, `java-dev`, `dotnet-dev`, `cpp-dev`, `php-dev`, `ruby-dev`, `kotlin-dev`, plus `rust-dev` / `node-dev`) compose with [`shell-basics`](/packs/shell-basics) for everyday unix/mayrun allows.

## Structured rules

```yaml
rules:
  - id: local.allow-just
    effect: allow
    reason: "Project just recipes"
    match:
      argv: { binary: just }
```

Matchers (OR via `any:`):

| Matcher | Example |
| --- | --- |
| `regex` | `{ regex: 'rm\\s+-rf' }` |
| `argv` | `{ argv: { binary: git, args_prefix: [push] } }` |
| `capability_any` | `{ capability_any: [scm.publish, infra.destroy] }` |
| `mcp` | `{ mcp: { server: filesystem, tool: write_file } }` |

`argv` matching peels common wrappers (`bash -c`, `env`, `sudo`, …) before comparing.

## Capabilities

Deterministic tags inferred from the peeled command, including:

`fs.read`, `fs.write`, `fs.destroy`, `net.egress`, `scm.read`, `scm.write`, `scm.publish`,
`build.local`, `pkg.install`, `pkg.publish`, `cluster.read`, `cluster.mutate`,
`priv.escalate`, `secrets.exfil`, `container.mutate`, `infra.apply`, `infra.destroy`.

## Authoring

```bash
mayrun policy draft "allow local cargo and git; approve push"
mayrun policy tighten --min-count 2
mayrun policy packs
mayrun scoreboard --corpus tests/corpus.yaml
```

Never auto-apply AI proposals — humans write `mayrun.policy.yaml`.

## Receipts and redaction

Stored `command` (and previews) are redacted for bearer tokens, `*SECRET*=` / `API_KEY=` assignments, and private-key blocks. Treat shared receipt logs as sensitive.

More: [Architecture](/docs/architecture) · [Sandbox](/docs/sandbox)
