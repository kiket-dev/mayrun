---
title: Secret and credential hygiene
description: Deny ssh/aws/gnupg exfil paths; require approval to read project .env files.
audience: Security-minded engineers
pack: secrets-safe
order: 3
---

Agents read whatever helps the task. Credential paths should not be “helpful.”

[`secrets-safe`](/packs/secrets-safe) denies `secrets.exfil` capabilities and redirect tricks toward `.ssh`, `.aws`, `.gnupg`, history, and key material. Project-local `.env*` requires human approval.

Combine with [`network-exfil`](/packs/network-exfil) to block IMDS (`169.254.169.254`) and curl|sh-style egress.
