#!/usr/bin/env bash
# Shared receipt assertions for agent e2e runners.
# Usage: assert-receipts.sh <workspace_dir> <decision> <executed:true|false> [rule_id_prefix]
set -euo pipefail

WS="${1:?workspace}"
EXPECT_DECISION="${2:?decision}"
EXPECT_EXECUTED="${3:?executed}"
RULE_PREFIX="${4:-}"

RECEIPTS="$WS/.mayrun/receipts.jsonl"
MAYRUN_BIN="${MAYRUN_BIN:-mayrun}"

if [[ ! -f "$RECEIPTS" ]]; then
  echo "FAIL: no receipts at $RECEIPTS" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "FAIL: jq is required for receipt assertions" >&2
  exit 1
fi

# Last receipt matching the expected decision (scenarios run one command each).
LINE=$(jq -c --arg d "$EXPECT_DECISION" 'select(.decision == $d)' "$RECEIPTS" | tail -n1)
if [[ -z "$LINE" ]]; then
  echo "FAIL: no receipt with decision=$EXPECT_DECISION in $RECEIPTS" >&2
  cat "$RECEIPTS" >&2 || true
  exit 1
fi

ACTUAL_EXEC=$(echo "$LINE" | jq -r '.executed')
if [[ "$ACTUAL_EXEC" != "$EXPECT_EXECUTED" ]]; then
  echo "FAIL: executed=$ACTUAL_EXEC want=$EXPECT_EXECUTED receipt=$LINE" >&2
  exit 1
fi

if [[ -n "$RULE_PREFIX" ]]; then
  RID=$(echo "$LINE" | jq -r '.rule_id // empty')
  if [[ "$RID" != "$RULE_PREFIX"* ]]; then
    echo "FAIL: rule_id=$RID does not start with $RULE_PREFIX" >&2
    exit 1
  fi
fi

# Chain integrity via mayrun status (non-zero only on load failure).
if [[ -x "$MAYRUN_BIN" ]] || command -v "$MAYRUN_BIN" >/dev/null 2>&1; then
  "$MAYRUN_BIN" status --policy "$WS/mayrun.policy.yaml" --receipts "$RECEIPTS" --limit 5 >/dev/null
fi

# Verify prev_hash chain
PREV="genesis"
while IFS= read -r row; do
  PH=$(echo "$row" | jq -r '.prev_hash')
  H=$(echo "$row" | jq -r '.hash')
  if [[ "$PH" != "$PREV" ]]; then
    echo "FAIL: broken receipt chain (prev_hash=$PH want=$PREV)" >&2
    exit 1
  fi
  PREV="$H"
done < <(jq -c '.' "$RECEIPTS")

echo "OK: decision=$EXPECT_DECISION executed=$EXPECT_EXECUTED rule_prefix=${RULE_PREFIX:-*}"
