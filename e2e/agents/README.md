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

## Result meanings (PASS / SKIP / FAIL)

| Result | Exit | When |
| --- | --- | --- |
| **PASS** | `0` | Scenarios ran and receipt assertions matched |
| **SKIP** | `0` + stdout `SKIP: …` | Missing opencode, jq, PyYAML, or (for cursor) no mayrun receipts without `MAYRUN_E2E_STRICT` — **not** a product failure |
| **FAIL** | non-zero | Agent ran but receipts/assertions failed |

### SKIP rules (detail)

- **opencode / jq / PyYAML missing** → exit 0 with `SKIP: …`.
- **No model credentials** may also yield SKIP or FAIL depending on the agent CLI; prefer configuring optional secrets only for scheduled/dispatch runs.
- **cursor-agent wrote no mayrun receipts** → `SKIP` by default. Custom MCP tools are often not injected into the model toolset. Set `MAYRUN_E2E_STRICT=1` to treat that as failure.

No new secrets are required for the SKIP path. Optional repo secrets (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `OPENCODE_API_KEY`) only enable a real PASS/FAIL run.

## CI

[`.github/workflows/e2e-agents.yml`](../../.github/workflows/e2e-agents.yml) is `workflow_dispatch` + weekly cron — **not PR-blocking**.

- Job summary annotates **PASS / SKIP / FAIL**.
- On **FAIL**, open an issue with: workflow run URL, scenario id(s), the `opencode-receipts` artifact (if present), and whether model secrets were configured. Suggested label: `e2e-agents`.
- Receipts upload as artifacts when present (`if-no-files-found: ignore`).
