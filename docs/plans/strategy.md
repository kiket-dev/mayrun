# mayrun strategy

**Status:** Active — product scaffolded  
**Last updated:** 2026-07-29  
**Site:** https://mayrun.dev  
**Repo:** https://github.com/kiket-dev/mayrun

## One-liner

Agents don’t run dangerous commands until mayrun says they may.

## Problem

Coding agents inherit broad shell/cloud access. Prompt “be careful” is not a control. Teams stall production agents after incidents; solo developers need a local gate they can install in minutes.

## Product

| Layer | Choice |
| --- | --- |
| Runtime | Rust CLI + MCP stdio server |
| Policy | Repo YAML (`mayrun.policy.yaml`) |
| Evidence | Local hash-chained JSONL receipts |
| Paid cliff (later) | CI gate / license — fail PR on policy violations |
| Non-goals (30d) | IdP, MCP proxy mesh, Kiket billing, dashboards |

## ICP

Developers and agent builders (no enterprise sales team). Discover via GitHub / HN / MCP directories.

## Brand / domain

- Name: **mayrun** (coined; “may this run?”)
- Domain: **mayrun.dev** (owner registering)
- GitHub: **kiket-dev/mayrun** (org is historical; product is not Kiket)

## Relation to Kiket / Attestack / Pramen

| Project | Role |
| --- | --- |
| **mayrun** | Monetization wedge — agent side-effect gate |
| **Kiket** | Commercial twin **frozen** (no customers; opportunity cost) |
| **Attestack** | Optional later: export receipts as proof artifacts |
| **Pramen / Gate** | Parked; different ICP (data enrichment) |

Do **not** put mayrun on kiket.dev (name mismatch). Keep kiket.dev as lab/archive if needed.

## Monetization

1. Free: local MCP + CLI + receipts  
2. Pro: CI action / license that enforces receipt policy on PRs  
3. Later: team policy sync (only if CI cliff works)

## Success (90 days)

- Stranger installs (weekly actives) **or** paying Pro users  
- Kill/pivot if neither — do not add SSO
