---
title: exec-escapes
description: GTFOBins-style escapes — require approval, not blanket deny.
effect: require approval
packId: exec-escapes
order: 5
---

Agents sometimes need `find -exec`, `xargs`, or interpreter `-c`/`-e` legitimately. Humans confirm the escalation class instead of a hard deny that trains people to disable the gate.
