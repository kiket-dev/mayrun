---
title: secrets-safe
description: Deny credential-path exfil; require approval for project .env reads.
effect: deny exfil / approve .env
packId: secrets-safe
order: 2
---

Blocks `secrets.exfil` capabilities and redirect tricks toward ssh/aws/gnupg/kube/history/cookie/key paths. Project-local `.env*` is `require_approval` rather than silent allow.
