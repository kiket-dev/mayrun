# mayrun execution plan

**Parent:** [strategy.md](./strategy.md)

## Phase 0 — Bootstrap (done when this ships)

- [x] Public repo `kiket-dev/mayrun`
- [x] Rust CLI: `init`, `check`, `run`, `status`, `mcp`
- [x] Policy engine (deny → require_approval → allow → default)
- [x] Hash-chained receipts
- [x] MCP tools: `mayrun_run`, `mayrun_check`, `mayrun_status`
- [x] Example policy + README + install docs
- [x] Domain **mayrun.dev** on Cloudflare (Cloudflare Pages project `mayrun`) — see [site.md](../site.md)
- [x] First push to `origin/main`

## Phase 1 — Dogfood (days 1–10)

### Policy expansion (done)

- [x] Policy v1 structured rules (`id` / `effect` / `match` / `reason`) + legacy flat-list compat
- [x] Receipts / CLI / MCP surface `rule_id` + `reason`
- [x] Built-in packs: `dangerous-defaults`, `git-safe`, `rust-dev`, `node-dev`, `ops-approve`
- [x] Wrapper peeling + argv matchers
- [x] Deterministic capability / risk tags
- [x] `mayrun policy draft` / `tighten` / `packs` + MCP suggest tools (proposal-only; never runtime Allow)
- [x] Docs: [policy.md](../policy.md); invariant documented in strategy

### Remaining dogfood

- [ ] Use mayrun MCP in Cursor on mayrun + one personal repo
- [ ] Tighten default / packs from real agent attempts
- [ ] Fix UX gaps (clearer approval flow, better errors)
- [x] `cargo test` in CI (GitHub Actions)
- [x] Pack gap coverage: `secrets-safe`, `exec-escapes`, `read-only` + dangerous/git extensions
- [x] Pipeline / composition stage awareness + secret-path capability tags
- [x] Pack corpus lockstep test (`tests/pack_corpus.rs`)
- [x] Deterministic MCP stdio e2e (`tests/e2e_mcp.rs`, in PR CI via `cargo test`)

### Recurring checks

- [ ] Tier-2 agent e2e (`e2e/agents/`, workflow `e2e-agents.yml`): opencode primary, cursor-agent best-effort; weekly cron + `workflow_dispatch`

## Phase 2 — Release binary (days 11–18)

- [ ] cargo-dist (or equivalent) multi-OS releases
- [ ] Demo GIF/video: agent blocked on `rm -rf`
- [ ] List in MCP directories / awesome lists
- [x] Stub landing in [`www/`](../../www/) (install + one-liner)
- [x] GitHub Actions [`deploy-site.yml`](../../.github/workflows/deploy-site.yml) on release / `www/**` push (Pages; `CLOUDFLARE_API_TOKEN`)

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
- Live LLM as Allow gate (AI may only author YAML or escalate gray-zone to require_approval)
