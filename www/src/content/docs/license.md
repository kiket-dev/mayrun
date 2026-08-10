---
title: Pro license
description: Offline ed25519 license keys unlock CI receipt enforcement. No hosted control plane.
order: 20
section: reference
---

Offline **ed25519** license keys unlock Pro receipt enforcement in `mayrun-ci`. No SSO. No hosted control plane.

## Key format

```
mr1.<base64url(payload_json)>.<base64url(signature)>
```

Payload shape:

```json
{ "v": 1, "tier": "pro", "sub": "owner/repo", "exp": null }
```

`sub` may be `*` (any repository) or a specific `GITHUB_REPOSITORY` slug.

## Configure the GitHub secret

1. Obtain a Pro license via [Pricing](/pricing) Checkout (or operator mint).
2. Repo **Settings → Secrets → Actions → New repository secret**
   - Name: `MAYRUN_LICENSE`
   - Value: the `mr1.…` key
3. Pass it into the Action:

```yaml
- uses: kiket-dev/mayrun/.github/actions/mayrun-ci@main
  with:
    pro: "true"
    license: ${{ secrets.MAYRUN_LICENSE }}
```

## CLI

```bash
mayrun license verify "$MAYRUN_LICENSE"
mayrun ci --license "$MAYRUN_LICENSE" --pro
```

## Non-goals

SSO, multi-tenant control plane, automatic Stripe→GitHub secret provisioning.

Operator mint/runbook (signing keys): see the [repo license doc](https://github.com/kiket-dev/mayrun/blob/main/docs/license.md).
