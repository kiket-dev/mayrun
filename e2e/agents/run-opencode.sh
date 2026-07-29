#!/usr/bin/env bash
# Primary agent e2e: opencode + mayrun MCP.
# Requires: opencode, jq, model credentials. Skips cleanly when opencode is absent.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPTS="$(cd "$(dirname "$0")" && pwd)"
MAYRUN_BIN="${MAYRUN_BIN:-$ROOT/target/debug/mayrun}"
SCENARIOS="${SCENARIOS:-$SCRIPTS/scenarios.yaml}"

if ! command -v opencode >/dev/null 2>&1; then
  echo "SKIP: opencode not installed"
  exit 0
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "SKIP: jq not installed"
  exit 0
fi
if [[ ! -x "$MAYRUN_BIN" ]]; then
  echo "Building mayrun…"
  (cd "$ROOT" && cargo build -q)
fi

POLICY_YAML='apiVersion: mayrun.dev/v1
default: deny
extends:
  - pack: dangerous-defaults
  - pack: secrets-safe
  - pack: exec-escapes
  - pack: git-safe
  - pack: rust-dev
'

fail=0
# Parse scenarios with a tiny python/yq-free approach via mayrun's serde isn't available;
# require python3 for YAML (stdlib) or fall back to embedded ids.
mapfile -t IDS < <(python3 - "$SCENARIOS" <<'PY'
import sys, yaml
doc = yaml.safe_load(open(sys.argv[1]))
for s in doc["scenarios"]:
    print(s["id"])
PY
) || {
  echo "SKIP: python3+PyYAML required to parse scenarios.yaml"
  exit 0
}

for id in "${IDS[@]}"; then
  echo "=== scenario: $id ==="
  WS=$(mktemp -d)
  trap 'rm -rf "$WS"' RETURN
  mkdir -p "$WS/.mayrun"
  printf '%s\n' "$POLICY_YAML" >"$WS/mayrun.policy.yaml"
  # Minimal git repo so `git status` / `git push` are meaningful.
  git -C "$WS" init -q
  git -C "$WS" config user.email "e2e@mayrun.test"
  git -C "$WS" config user.name "mayrun e2e"
  echo hi >"$WS/README.md"
  git -C "$WS" add README.md
  git -C "$WS" commit -q -m init

  cat >"$WS/opencode.json" <<EOF
{
  "mcp": {
    "mayrun": {
      "type": "local",
      "command": ["$MAYRUN_BIN", "mcp", "--policy", "$WS/mayrun.policy.yaml", "--receipts", "$WS/.mayrun/receipts.jsonl"]
    }
  }
}
EOF

  PROMPT=$(python3 - "$SCENARIOS" "$id" <<'PY'
import sys, yaml
doc = yaml.safe_load(open(sys.argv[1]))
sid = sys.argv[2]
for s in doc["scenarios"]:
    if s["id"] == sid:
        print(s["prompt"])
        break
PY
)
  EXPECT=$(python3 - "$SCENARIOS" "$id" <<'PY'
import sys, yaml, json
doc = yaml.safe_load(open(sys.argv[1]))
sid = sys.argv[2]
for s in doc["scenarios"]:
    if s["id"] == sid:
        print(json.dumps(s["expect"]))
        break
PY
)
  DECISION=$(echo "$EXPECT" | jq -r .decision)
  EXECUTED=$(echo "$EXPECT" | jq -r .executed)
  PREFIX=$(echo "$EXPECT" | jq -r .rule_id_prefix)

  set +e
  (cd "$WS" && opencode run "$PROMPT")
  oc_rc=$?
  set -e

  if [[ ! -f "$WS/.mayrun/receipts.jsonl" ]]; then
    echo "FAIL: opencode ran but wrote no mayrun receipts (rc=$oc_rc)"
    fail=1
    continue
  fi

  if ! MAYRUN_BIN="$MAYRUN_BIN" "$SCRIPTS/assert-receipts.sh" "$WS" "$DECISION" "$EXECUTED" "$PREFIX"; then
    fail=1
  fi
done

exit "$fail"
