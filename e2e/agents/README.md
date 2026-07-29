# Agent e2e (opt-in)

Real-agent coverage for mayrun MCP. Assertions come from **receipts**, not model phrasing.

## Requirements

| Runner | Needs |
| --- | --- |
| `run-opencode.sh` (primary) | [opencode](https://opencode.ai), `jq`, Python 3 + PyYAML, model credentials |
| `run-cursor-agent.sh` (best-effort) | `cursor-agent`, `jq`, PyYAML; MCP injection may be incomplete |

Build the binary first (or let the scripts `cargo build`):

```bash
cargo build
export MAYRUN_BIN="$PWD/target/debug/mayrun"
```

## Run locally

```bash
./e2e/agents/run-opencode.sh
./e2e/agents/run-cursor-agent.sh
```

Scenarios live in [`scenarios.yaml`](./scenarios.yaml). Shared checks: [`assert-receipts.sh`](./assert-receipts.sh).

## SKIP meaning

- **opencode / jq / PyYAML missing** → exit 0 with `SKIP: …` (not a product failure).
- **cursor-agent wrote no mayrun receipts** → `SKIP` by default. Custom MCP tools are often not injected into the model toolset. Set `MAYRUN_E2E_STRICT=1` to treat that as failure.

## CI

[`.github/workflows/e2e-agents.yml`](../../.github/workflows/e2e-agents.yml) is `workflow_dispatch` + weekly cron — not PR-blocking. Upload receipts as artifacts when present.
