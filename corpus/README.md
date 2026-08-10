# Pinned scoreboard corpus

Vendor-style fixtures used by `mayrun scoreboard` and CI. **No live LLM** and no unbounded network fetch in PR CI.

| Path | Source style | Role |
| --- | --- | --- |
| [`../tests/corpus.yaml`](../tests/corpus.yaml) | Pack lockstep + unsafe/safe cases | Primary scoreboard input |
| [`pins/network-exfil.yaml`](./pins/network-exfil.yaml) | IMDS / curl\|sh / secret egress | Extra network-exfil recalls |

Refresh pins offline when importing new public cases; keep commands synthetic (no real secrets).
