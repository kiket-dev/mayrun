# mayrun Pro license (CI)

Offline **ed25519** license keys unlock Pro receipt enforcement in `mayrun-ci`.
No Kiket billing federation; no hosted control plane.

## Key format

```
mr1.<base64url(payload_json)>.<base64url(signature)>
```

Payload:

```json
{ "v": 1, "tier": "pro", "sub": "owner/repo", "exp": null }
```

`sub` may be `*` (any repository) or a specific `GITHUB_REPOSITORY` slug.

## Configure the GitHub secret

1. Obtain a Pro license (Stripe Checkout on [mayrun.dev/#pricing](https://mayrun.dev/#pricing), or operator mint).
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

Optional override verifying key: set env `MAYRUN_LICENSE_PUBLIC_KEY` to a 32-byte hex
public key (defaults to the mayrun dogfood key embedded in the binary).

## Operator runbook (test vs live)

### Test mode (dogfood)

```bash
export MAYRUN_LICENSE_SIGNING_KEY=<dogfood-signing-key-hex>   # see below
mayrun license mint --sub 'your-org/your-repo'
mayrun license verify 'mr1.…' --repo your-org/your-repo
```

Dogfood keypair (rotate before charging money):

| Role | Hex |
| --- | --- |
| Signing (`MAYRUN_LICENSE_SIGNING_KEY`) | `8f299830a44a60a84ac7f0b1dd475d3b50b0a9822675e877a6f08e2af9cb0717` |
| Verifying (embedded default) | `2b8279b253b5bdb10ad2878064bdd1c2f6972223cf7f5f55fb1ef73e3dbd31dd` |

### Live mode (Stripe)

1. Create a Stripe **Payment Link** for mayrun Pro (placeholder price OK).
2. Point [mayrun.dev](https://mayrun.dev/#pricing) Checkout CTA at that link.
3. After payment (Dashboard / webhook / email), mint a key with the **live** signing seed
   (not the dogfood key) and email it to the customer.
4. Customer stores it as `MAYRUN_LICENSE`.
5. Rotate dogfood keys before taking real payments; set `MAYRUN_LICENSE_PUBLIC_KEY` in
   the Action if the embedded verifying key changes.

```bash
# Live mint (signing key only on operator machine / password manager)
export MAYRUN_LICENSE_SIGNING_KEY=<live-32-byte-hex>
mayrun license mint --sub 'customer-org/repo' --exp $(($(date +%s)+31536000))
```

## CLI

```bash
mayrun license verify "$MAYRUN_LICENSE"
mayrun license mint --sub '*' 
mayrun ci --license "$MAYRUN_LICENSE" --pro
```

## Non-goals

SSO, multi-tenant control plane, automatic Stripe→GitHub secret provisioning.
