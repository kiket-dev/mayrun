# Policy language

mayrun policies are YAML. Evaluation is deterministic and offline:

**deny → require_approval → allow → default** (default is deny).

Only deterministic rules (and a human `--approve`) can produce **Allow**.
AI helpers (`mayrun policy draft` / `tighten`, MCP suggest tools) emit **proposed YAML** for human review — they never grant runtime Allow.

Pipeline / composition awareness: top-level `|`, `|&`, `&&`, `||`, and `;` stages are evaluated separately; the **worst** decision wins (deny > require_approval > allow). Capabilities are unioned across stages. Regex matchers still see the full command string.

## Minimal pack-based policy

```yaml
apiVersion: mayrun.dev/v1
default: deny
extends:
  - pack: dangerous-defaults
  - pack: secrets-safe
  - pack: exec-escapes
  - pack: git-safe
  - pack: rust-dev
```

## Built-in packs

| Pack | Focus | Default effect |
| --- | --- | --- |
| `dangerous-defaults` | Destructive shell / disk / force-push / sudo / rc writes / curl\|sh | mostly **deny** |
| `secrets-safe` | Credential path exfil; project `.env*` | **deny** exfil / **require_approval** `.env` |
| `network-exfil` | IMDS `169.254.169.254`, pipe-to-shell, obvious secret egress | **deny** |
| `mcp-safe` | MCP tool names/args for `mcp-proxy` (deny delete / sensitive write; approve shell tools; allow read) | mixed |
| `exec-escapes` | GTFOBins-style escapes (`find -exec`, `xargs`, interpreter `-c`/`-e`, …) | **require_approval** |
| `git-safe` | Git read allow; push / commit / `reset --hard` | **allow** read / **require_approval** write |
| `rust-dev` | Local cargo + unix read utils | **allow** / **require_approval** publish/install |
| `node-dev` | Local npm/pnpm/yarn/bun scripts | **allow** / **require_approval** publish/install |
| `ops-approve` | terraform apply, kubectl apply, docker push | **require_approval** |
| `read-only` | Plan-mode inspection only (`ls`/`cat`/`rg`/`git` read, …) | **allow** inspect |

List with `mayrun policy packs`.

**Coexistence:** mayrun runs **alongside** agent permission systems (Cursor/Claude allowlists, harness rulepacks). Overlap is defense in depth — packs stay thin and own the shell choke point (destructive patterns, secret-path exfil, escape abuse, receipts). They do not replicate full harness profiles.

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
| `argv` | `{ argv: { binary: git, args_prefix: [push], flags_any: ["--force"] } }` |
| `capability_any` | `{ capability_any: [scm.publish, infra.destroy] }` |
| `mcp` | `{ mcp: { server: filesystem, tool: write_file, args: { path: "/etc*" } } }` |

`argv` matching peels common wrappers (`bash -c`, `env`, `sudo`, …) before comparing.

**MCP matchers** (`mcp.server` / `mcp.tool` / arg key globs) apply to `mayrun mcp-proxy` tool calls only — they never match shell `mayrun run` / `check`. Shell argv/capability matchers never match MCP calls. Regex may match the synthetic `mcp:server/tool …` string. Pack: `mcp-safe`.

## MCP proxy vs MCP server

| Command | Role |
| --- | --- |
| `mayrun mcp` | mayrun **is** the MCP server (tools: `mayrun_run`, `mayrun_check`, …) |
| `mayrun mcp-proxy -- <upstream…>` | mayrun sits **in front of** another MCP; intercepts `tools/call`, evaluates policy, writes receipts |

```bash
mayrun mcp-proxy --policy mayrun.policy.yaml --server-name filesystem -- \
  npx -y @modelcontextprotocol/server-filesystem /tmp
```

Approval for `require_approval`: TTY (`/dev/tty`) or `--approve-file` (tool name per line). Fail closed.

## Capabilities

Deterministic tags inferred from the peeled command, including:

`fs.read`, `fs.write`, `fs.destroy`, `net.egress`, `scm.read`, `scm.write`, `scm.publish`,
`build.local`, `pkg.install`, `pkg.publish`, `cluster.read`, `cluster.mutate`,
`priv.escalate`, `secrets.exfil`, `container.mutate`, `infra.apply`, `infra.destroy`.

`secrets.exfil` is tagged when read/copy binaries (`cat`, `head`, `cp`, `tar`, `scp`, …) touch
ssh/aws/gnupg/kube/history/cookie/key paths. Project-local `.env*` is handled by `secrets-safe`
as require_approval rather than exfil.

`mayrun check 'git push'` prints `capabilities` alongside `decision` / `rule_id` / `reason`.

## Legacy flat lists

Still supported and compiled into synthetic rules:

```yaml
deny: ["rm\\s+-rf"]
require_approval: ["^git push"]
allow: ["^cargo test"]
```

## Authoring

```bash
mayrun policy draft "allow local cargo and git; approve push"
mayrun policy tighten --min-count 2
```

CLI draft uses deterministic pack selection from keywords. For richer AI drafts, call
`mayrun_policy_suggest` from an MCP host (the host model refines the proposal). Never
auto-apply — human writes `mayrun.policy.yaml`.

MCP: `mayrun_policy_suggest`, `mayrun_policy_tighten` (proposal only).

## Scoreboard

```bash
mayrun scoreboard --corpus tests/corpus.yaml
mayrun scoreboard --corpus corpus/pins/network-exfil.yaml --json
```

Recall on unsafe cases must stay at 100% in CI (see `.github/workflows/ci.yml`). Tighten packs from misses with stable `id` / `reason` — never weaken `dangerous-defaults` to chase green.

## Receipts and redaction

Stored `command` (and previews) are redacted for bearer tokens, `*SECRET*=` / `API_KEY=` assignments, and private-key blocks. Residual risk remains for novel secret formats — treat shared receipt logs as sensitive.

## Sandbox

`mayrun run '<cmd>' --sandbox` (soft) or `--sandbox=required` runs Allow/approved commands inside bubblewrap (Linux) or `sandbox-exec` (macOS). Deny never sandboxes. Network is deny-by-default unless capabilities include `net.egress`. Workspace is writable; secret home paths are best-effort denied for read. Defense in depth under policy — not a hosted sandbox platform.

## Metrics

`mayrun metrics [--since 7d] [--json]` summarizes local receipts only (decision mix, top `rule_id`s, approval friction, sandbox rate). Offline — not agent APM; no network telemetry.
