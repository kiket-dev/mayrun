---
title: Ops mutations need a human
description: terraform apply, kubectl apply, and docker push require approval before they run.
audience: Platform / ops adjacent developers
pack: ops-approve
order: 5
---

Infra mutations are high-blast-radius. [`ops-approve`](/packs/ops-approve) marks them `require_approval` so an agent cannot silently apply.

```bash
mayrun run 'terraform apply'
mayrun run 'kubectl apply -f deploy.yaml'
mayrun run 'docker push …'
```

Use alongside `dangerous-defaults` — ops approval does not replace destructive denials.
