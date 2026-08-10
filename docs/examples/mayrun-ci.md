# Example: mayrun-ci GitHub Action

Free tier validates that `mayrun.policy.yaml` compiles and prints an advisory
scoreboard. Pro (license secret) also enforces a receipt evidence gate.

```yaml
name: mayrun

on:
  pull_request:
  push:
    branches: [main]

jobs:
  mayrun-ci:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Free: policy compile + advisory scoreboard annotations
      - name: mayrun ci (free)
        uses: kiket-dev/mayrun/.github/actions/mayrun-ci@main
        with:
          policy: mayrun.policy.yaml
          receipts: .mayrun/receipts.jsonl
          corpus: tests/corpus.yaml

      # Pro: set repo/org secret MAYRUN_LICENSE (signed mr1.… key)
      # - name: mayrun ci (pro)
      #   uses: kiket-dev/mayrun/.github/actions/mayrun-ci@main
      #   with:
      #     pro: "true"
      #     license: ${{ secrets.MAYRUN_LICENSE }}
```

## Failure modes

| Condition | Free | Pro |
| --- | --- | --- |
| Missing / invalid policy | fail | fail |
| Scoreboard misses | advisory annotation | advisory annotation |
| Missing receipts file | notice | **fail** |
| Broken receipt hash chain | fail | fail |
| Missing / invalid license when `pro: true` | n/a | fail |

See [docs/license.md](../license.md) for minting and Stripe runbook.
