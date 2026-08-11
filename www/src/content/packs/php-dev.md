---
title: php-dev
description: phpunit and composer validate without require/publish by default.
effect: allow local / approve install
packId: php-dev
order: 16
---

```yaml
extends:
  - pack: shell-basics
  - pack: php-dev
```

Detect via `mayrun init --detect` when project signals are present. Source: [`packs/php-dev.yaml`](https://github.com/kiket-dev/mayrun/blob/main/packs/php-dev.yaml).
