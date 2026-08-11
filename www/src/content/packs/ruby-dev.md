---
title: ruby-dev
description: rspec/rake/rubocop without gem push or bundle install by default.
effect: allow local / approve install
packId: ruby-dev
order: 17
---

```yaml
extends:
  - pack: shell-basics
  - pack: ruby-dev
```

Detect via `mayrun init --detect` when project signals are present. Source: [`packs/ruby-dev.yaml`](https://github.com/kiket-dev/mayrun/blob/main/packs/ruby-dev.yaml).
