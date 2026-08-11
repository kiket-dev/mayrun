---
title: kotlin-dev
description: Gradle Kotlin/Android local build without publish by default.
effect: allow local / approve publish
packId: kotlin-dev
order: 18
---

```yaml
extends:
  - pack: shell-basics
  - pack: kotlin-dev
```

Detect via `mayrun init --detect` when project signals are present. Source: [`packs/kotlin-dev.yaml`](https://github.com/kiket-dev/mayrun/blob/main/packs/kotlin-dev.yaml).
