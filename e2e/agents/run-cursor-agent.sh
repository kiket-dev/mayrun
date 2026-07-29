#!/usr/bin/env bash
# Best-effort agent e2e: cursor-agent + mayrun MCP.
# Known caveat: cursor-agent may not inject custom MCP tools into the model toolset.
# When no mayrun receipts are written, reports SKIP (MAYRUN_E2E_STRICT=1 → failure).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPTS="$(cd "$(dirname "$0")" && pwd)"
MAYRUN_BIN="${MAYRUN_BIN:-$ROOT/target/debug/mayrun}"
SCENARIOS="${SCENARIOS:-$SCRIPTS/scenarios.yaml}"
STRICT="${MAYRUN_E2E_STRICT:-0}"

if ! command -v cursor-agent >/dev/null 2>&1; then
  echo "SKIP: cursor-agent not installed"
  exit 0
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "SKIP: jq not installed"
  exit 0
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "SKIP: python3 required"
  exit 0
fi
if ! python3 -c 'import yaml' 2>/dev/null; then
  echo "SKIP: PyYAML required (pip install pyyaml)"
  exit 0
fi
if [[ ! -x "$MAYRUN_BIN" ]]; then
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
skipped=0

mapfile -t IDS < <(python3 - "$SCENARIOS" <<'PY'
import sys, yaml
doc = yaml.safe_load(open(sys.argv[1]))
for s in doc["scenarios"]:
    print(s["id"])
PY
)

for id in "${IDS[@]}"; do
  echo "=== scenario: $id ==="
  WS=$(mktemp -d)
  trap 'rm -rf "$WS"' RETURN
  mkdir -p "$WS/.mayrun" "$WS/.cursor"
  printf '%s\n' "$POLICY_YAML" >"$WS/mayrun.policy.yaml"
  git -C "$WS" init -q
  git -C "$WS" config user.email "e2e@mayrun.test"
  git -C "$WS" config user.name "mayrun e2e"
  echo hi >"$WS/README.md"
  git -C "$WS" add README.md
  git -C "$WS" commit -q -m init

  cat >"$WS/.cursor/mcp.json" <<EOF
{
  "mcpServers": {
    "mayrun": {
      "command": "$MAYRUN_BIN",
      "args": ["mcp", "--policy", "$WS/mayrun.policy.yaml", "--receipts", "$WS/.mayrun/receipts.jsonl"]
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
  (cd "$WS" && cursor-agent -p --approve-mcps --force --output-format json "$PROMPT")
  ca_rc=$?
  set -e

  if [[ ! -f "$WS/.mayrun/receipts.jsonl" ]] || [[ ! -s "$WS/.mayrun/receipts.jsonl" ]]; then
    msg="cursor-agent wrote no mayrun receipts (rc=$ca_rc) — custom MCP tools may not be in the model toolset"
    if [[ "$STRICT" == "1" ]]; then
      echo "FAIL: $msg"
      fail=1
    else
      echo "SKIP: $msg"
      skipped=1
    fi
    continue
  fi

  if ! MAYRUN_BIN="$MAYRUN_BIN" "$SCRIPTS/assert-receipts.sh" "$WS" "$DECISION" "$EXECUTED" "$PREFIX"; then
    fail=1
  fi
done

if [[ "$fail" -ne 0 ]]; then
  exit 1
fi
exit 0
