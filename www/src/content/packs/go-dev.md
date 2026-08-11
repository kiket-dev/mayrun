---
title: go-dev
description: Local go test/build/run without go get/install by default.
effect: allow local / approve install
packId: go-dev
order: 12
---

```yaml
extends:
  - pack: shell-basics
  - pack: go-dev
```

Detect via `mayrun init --detect` when project signals are present. Source: [`packs/go-dev.yaml`](https://github.com/kiket-dev/mayrun/blob/main/packs/go-dev.yaml).
