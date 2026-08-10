---
title: Human gate for push and publish
description: Require a human --approve before git push, cargo publish, or npm publish.
audience: Solo builders and small teams
pack: git-safe
order: 2
---

Agents love to “finish the job.” Publishing is often where that job becomes irreversible.

```yaml
extends:
  - pack: git-safe
  - pack: rust-dev   # or node-dev
```

```bash
mayrun run 'git push'
# Require approval →
mayrun run 'git push' --approve
```

Same pattern for `cargo publish` / `npm publish` via [`rust-dev`](/packs/rust-dev) and [`node-dev`](/packs/node-dev).
