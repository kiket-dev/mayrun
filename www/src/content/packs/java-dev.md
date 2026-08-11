---
title: java-dev
description: Maven/Gradle local build/test without deploy/publish by default.
effect: allow local / approve publish
packId: java-dev
order: 13
---

```yaml
extends:
  - pack: shell-basics
  - pack: java-dev
```

Detect via `mayrun init --detect` when project signals are present. Source: [`packs/java-dev.yaml`](https://github.com/kiket-dev/mayrun/blob/main/packs/java-dev.yaml).
