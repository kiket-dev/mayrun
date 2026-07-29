# mayrun execution plan

**Parent:** [strategy.md](./strategy.md)

## Phase 0 — Bootstrap (done when this ships)

- [x] Public repo `kiket-dev/mayrun`
- [x] Rust CLI: `init`, `check`, `run`, `status`, `mcp`
- [x] Policy engine (deny → require_approval → allow → default)
- [x] Hash-chained receipts
- [x] MCP tools: `mayrun_run`, `mayrun_check`, `mayrun_status`
- [x] Example policy + README + install docs
- [ ] Domain **mayrun.dev** registered and DNS pointed (owner)
- [x] First push to `origin/main`

## Phase 1 — Dogfood (days 1–10)

- [ ] Use mayrun MCP in Cursor on mayrun + one personal repo
- [ ] Tighten default policy from real agent attempts
- [ ] Fix UX gaps (clearer approval flow, better errors)
- [ ] `cargo test` in CI (GitHub Actions)

## Phase 2 — Release binary (days 11–18)

- [ ] cargo-dist (or equivalent) multi-OS releases
- [ ] Demo GIF/video: agent blocked on `rm -rf`
- [ ] List in MCP directories / awesome lists
- [ ] Stub landing on mayrun.dev (install + one-liner)

## Phase 3 — Paid cliff (days 19–30)

- [ ] GitHub Action `mayrun-ci` reading receipts / policy
- [ ] Stripe Checkout self-serve (license or subscription)
- [ ] Pricing section on mayrun.dev
- [ ] Show HN / relevant communities

## Phase 4 — Learn or pivot (day 90)

Kill criteria: &lt;10 stranger installs/week and 0 payers → change wedge (e.g. MCP proxy) or revisit enrichment Gate; do not build enterprise SSO.

## Explicit non-goals until Phase 3 exit

- Kiket auth/billing federation
- Attestack hard dependency
- Visual policy editor
- Hosted multi-tenant control plane
