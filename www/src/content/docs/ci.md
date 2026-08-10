---
title: CI Action
description: Free policy compile and advisory scoreboard; Pro enforces receipt evidence on PRs.
order: 13
section: guide
---

Free tier validates that `mayrun.policy.yaml` compiles and prints an advisory scoreboard. Pro (license secret) also enforces a receipt evidence gate.

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

      - name: mayrun ci (free)
        uses: kiket-dev/mayrun/.github/actions/mayrun-ci@main
        with:
          policy: mayrun.policy.yaml
          receipts: .mayrun/receipts.jsonl
          corpus: tests/corpus.yaml

      # Pro: set MAYRUN_LICENSE secret
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
| Scoreboard misses | advisory | advisory |
| Missing receipts file | notice | **fail** |
| Broken receipt hash chain | fail | fail |
| Missing / invalid license when `pro: true` | n/a | fail |

Local smoke:

```bash
mayrun ci
mayrun ci --pro --license "$MAYRUN_LICENSE"
```

License setup: [Pro license](/docs/license) · Pricing: [/pricing](/pricing)
