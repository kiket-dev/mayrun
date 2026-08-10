---
title: network-exfil
description: IMDS, pipe-to-shell, and obvious secret egress — deny.
effect: deny
packId: network-exfil
order: 3
---

Complements `dangerous-defaults` curl|sh and `secrets-safe` path exfil. Denies cloud instance metadata (`169.254.169.254`), download-piped-to-shell, and obvious credential POST patterns.
