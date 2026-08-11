---
title: cpp-dev
description: cmake/ninja/make/compilers without apt/brew/vcpkg install by default.
effect: allow local / approve install
packId: cpp-dev
order: 15
---

```yaml
extends:
  - pack: shell-basics
  - pack: cpp-dev
```

Detect via `mayrun init --detect` when project signals are present. Source: [`packs/cpp-dev.yaml`](https://github.com/kiket-dev/mayrun/blob/main/packs/cpp-dev.yaml).
