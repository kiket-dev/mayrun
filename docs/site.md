# mayrun.dev site

Static landing in [`www/public/`](../www/public/). Hosted on **Cloudflare Pages** project `mayrun` (same pattern as headmark / kiket landing).

## Live

- https://mayrun.dev
- https://www.mayrun.dev
- Preview: https://mayrun.pages.dev

## Deploy (CI)

Workflow: [`.github/workflows/deploy-site.yml`](../.github/workflows/deploy-site.yml)

Triggers:

- `release` published
- push to `main` that touches `www/**`
- `workflow_dispatch`

### GitHub secrets / vars

| Name | Where | Notes |
| --- | --- | --- |
| `CLOUDFLARE_ACCOUNT_ID` | repo variable | `d65460242197dce7928f3d76b8b44510` |
| `CLOUDFLARE_API_TOKEN` | repo secret | Same Pages Edit token used by headmark (`CLOUDFLARE_PAGES_API_TOKEN`) |

Sync from a local env file (optional):

```bash
# token must allow Account → Cloudflare Pages → Edit (+ Zone DNS Edit on mayrun.dev)
printenv CLOUDFLARE_PAGES_API_TOKEN | gh secret set CLOUDFLARE_API_TOKEN -R kiket-dev/mayrun
```

## Manual deploy

```bash
export CLOUDFLARE_API_TOKEN=…   # Pages Edit token
export CLOUDFLARE_ACCOUNT_ID=d65460242197dce7928f3d76b8b44510
cd www
npx wrangler@latest pages deploy public --project-name mayrun --commit-dirty=true
```

## Layout

| Path | Role |
| --- | --- |
| `www/public/` | Static assets (HTML/CSS/JS/_headers) |
| `www/wrangler.jsonc` | Pages project name + build output dir |

## What this site is for

| Now | Later (Pro) |
| --- | --- |
| One-liner, install, MCP snippet | Pricing + Stripe Checkout |
| Link to GitHub docs | Docs for `mayrun-ci` Action |
