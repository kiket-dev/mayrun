---
title: CI evidence on pull requests
description: Free advisory policy compile; Pro fails the PR when receipt evidence is missing.
audience: Small teams that want proof agents stayed inside policy
order: 7
---

Local gate is free. Teams that want **proof on PRs** add `mayrun-ci`.

- **Free:** policy must compile; scoreboard advisory annotations
- **Pro:** signed `mr1.…` license → fail when receipts / license are missing

```yaml
- uses: kiket-dev/mayrun/.github/actions/mayrun-ci@main
  with:
    pro: "true"
    license: ${{ secrets.MAYRUN_LICENSE }}
```

Details: [CI docs](/docs/ci) · [Pricing](/pricing)
