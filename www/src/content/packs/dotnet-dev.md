---
title: dotnet-dev
description: dotnet build/test without nuget push or package add by default.
effect: allow local / approve publish
packId: dotnet-dev
order: 14
---

```yaml
extends:
  - pack: shell-basics
  - pack: dotnet-dev
```

Detect via `mayrun init --detect` when project signals are present. Source: [`packs/dotnet-dev.yaml`](https://github.com/kiket-dev/mayrun/blob/main/packs/dotnet-dev.yaml).
