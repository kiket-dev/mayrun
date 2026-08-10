---
title: Stop destructive agent shell
description: Deny rm -rf, mkfs, curl|sh, force-push, and sudo before the agent finishes the sentence.
audience: Developers after a near-miss
pack: dangerous-defaults
order: 1
---

Coding agents inherit broad shell access. Prompting “be careful” is not a control.

Extend [`dangerous-defaults`](/packs/dangerous-defaults), enable the shell-hook, and the next `rm -rf /` fails closed with a `rule_id` — before the filesystem is gone.

```bash
mayrun init --detect
eval "$(mayrun shell-hook)"
rm -rf /          # Deny
mayrun status     # receipt with rule_id + reason
```

Pairs with [`exec-escapes`](/packs/exec-escapes) for GTFOBins-style approval on `find -exec`, interpreter `-c`, and friends.
