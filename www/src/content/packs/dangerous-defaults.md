---
title: dangerous-defaults
description: Destructive shell, disk, force-push, sudo, rc writes, curl|sh — mostly deny.
effect: mostly deny
packId: dangerous-defaults
order: 1
---

Always extend this pack (or equivalent). It is the baseline that stops agents from finishing irreversible mistakes.

Typical denials:

- `rm -rf /` and home wipes
- `mkfs`, raw disk writers
- force-push / hard resets at pack boundaries (with git-safe)
- `sudo`, profile/rc writes
- `curl|sh` style pipe-to-shell

```yaml
extends:
  - pack: dangerous-defaults
```
