---
title: Plan-mode / read-only agents
description: Inspection-only allowlist for agents that should look, not mutate.
audience: Agent builders shipping plan mode
pack: read-only
order: 4
---

When the agent is supposed to research — not change the world — start from default deny and extend [`read-only`](/packs/read-only).

Thin allow for common inspect tools (`ls`, `cat`, `rg`, git read). Everything else stays deny. Still stack `secrets-safe` so “inspect” does not mean “dump `~/.ssh`.”
