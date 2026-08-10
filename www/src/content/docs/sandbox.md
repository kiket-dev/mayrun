---
title: Sandbox
description: Optional bubblewrap / Seatbelt confinement after Allow — defense in depth, not a cloud sandbox.
order: 21
section: reference
---

`mayrun run '<cmd>' --sandbox` (soft) or `--sandbox=required` runs Allow/approved commands inside bubblewrap (Linux) or `sandbox-exec` (macOS).

| Rule | Behavior |
| --- | --- |
| Deny | Never sandboxes |
| Network | Deny-by-default unless capabilities include `net.egress` |
| Workspace | Writable |
| Secret home paths | Best-effort denied for read |

Defense in depth under policy — not a hosted sandbox platform, not a Windows-perfect v1.

```bash
mayrun run 'cargo test' --sandbox
mayrun run 'cargo test' --sandbox=required
```

See [Architecture](/docs/architecture) · [Policy](/docs/policy)
