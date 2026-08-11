---
title: python-dev
description: Local pytest/ruff/mypy without pip install or twine publish by default.
effect: allow local / approve publish
packId: python-dev
order: 11
---

```yaml
extends:
  - pack: shell-basics
  - pack: python-dev
```

Detect via `mayrun init --detect` when project signals are present. Source: [`packs/python-dev.yaml`](https://github.com/kiket-dev/mayrun/blob/main/packs/python-dev.yaml).
