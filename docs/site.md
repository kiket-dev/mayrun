# mayrun.dev site

Astro static site in [`www/`](../www/). Hosted on **Cloudflare Pages** project `mayrun`.

## Live

- https://mayrun.dev
- https://www.mayrun.dev
- Preview: https://mayrun.pages.dev

## Develop

```bash
cd www
npm install
npm run dev
```

## Build

```bash
cd www
npm run build   # → www/dist
```

## Deploy (CI)

Workflow: [`.github/workflows/deploy-site.yml`](../.github/workflows/deploy-site.yml)

Triggers:

- `release` published
- push to `main` that touches `www/**`
- `workflow_dispatch`

CI runs `npm ci && npm run build`, then deploys `dist/` with Wrangler.

### GitHub secrets / vars

| Name | Where | Notes |
| --- | --- | --- |
| `CLOUDFLARE_ACCOUNT_ID` | repo variable | `d65460242197dce7928f3d76b8b44510` |
| `CLOUDFLARE_API_TOKEN` | repo secret | Pages Edit token |

## Manual deploy

```bash
export CLOUDFLARE_API_TOKEN=…
export CLOUDFLARE_ACCOUNT_ID=d65460242197dce7928f3d76b8b44510
cd www
npm ci && npm run build
npx wrangler@latest pages deploy dist --project-name mayrun --commit-dirty=true
```

## Layout

| Path | Role |
| --- | --- |
| `www/src/pages/` | Routes (home, install, pricing, use-cases, packs, docs) |
| `www/src/content/` | Markdown collections (docs, use-cases, packs) |
| `www/src/components/` | Shared UI |
| `www/public/` | Static assets (`favicon`, `og.svg`, `robots.txt`, `_headers`) |
| `www/dist/` | Build output (deployed) |

## What this site is for

Marketing + first-party docs on mayrun.dev: install, use cases, pack catalog, Decide→Prove→Confine guides, Pro pricing/CI.
