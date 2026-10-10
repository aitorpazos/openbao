#!/usr/bin/env bash
# verify.sh — standard gates for the compat fork: build, unit tests, spec harness.
#
# Runs in any checkout/worktree of the openbao fork:
#   1. go build ./...
#   2. go test ./internal/vault/ ./internal/vault/quotas/ -count=1   (~10 min first run, cached after)
#   3. builds bin/bao, boots an ephemeral dev server, runs the full spec harness
#
# FEATURE_ABSENT verdicts are tolerated (informational: Enterprise feature not
# implemented). FAIL or ERROR verdicts fail the run (exit 1).
#
# Usage: verify.sh [--worktree DIR] [--port N] [--skip-unit] [--skip-harness]
set -euo pipefail

REPO="${REPO:-/Volumes/External/aitor/workspace/repos/openbao}"
WT="" PORT="8299" TOKEN="compat-harness-port"
SKIP_UNIT=0 SKIP_HARNESS=0

while [ $# -gt 0 ]; do
  case "$1" in
    --repo) REPO="$2"; shift 2 ;;
    --worktree) WT="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --skip-unit) SKIP_UNIT=1; shift ;;
    --skip-harness) SKIP_HARNESS=1; shift ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done

WT="${WT:-$REPO}"
[ -d "$WT" ] || { echo "ERROR: worktree not found: $WT" >&2; exit 2; }

FAILED=0
note() { echo ""; echo "== $1 =="; }

note "build"
if ! (cd "$WT" && go build ./...); then
  echo "BUILD FAILED"; FAILED=1
fi

if [ "$SKIP_UNIT" = "0" ] && [ "$FAILED" = "0" ]; then
  note "unit tests (go test ./internal/vault/ ./internal/vault/quotas/ -count=1; ~10 min uncached)"
  if ! (cd "$WT" && go test ./internal/vault/ ./internal/vault/quotas/ -count=1 > "/tmp/openbao-unit-$PORT.log" 2>&1); then
    echo "UNIT TESTS FAILED — tail of log:"
    tail -40 "/tmp/openbao-unit-$PORT.log"
    FAILED=1
  else
    tail -2 "/tmp/openbao-unit-$PORT.log"
  fi
fi

if [ "$SKIP_HARNESS" = "0" ] && [ "$FAILED" = "0" ]; then
  note "harness (ephemeral dev server on 127.0.0.1:$PORT)"
  (cd "$WT" && go build -o bin/bao .)
  LOG="/tmp/openbao-devserver-$PORT.log"
  (cd "$WT" && exec ./bin/bao server -dev -dev-root-token-id="$TOKEN" -dev-listen-address="127.0.0.1:$PORT" > "$LOG" 2>&1) &
  SERVER_PID=$!
  trap 'kill "$SERVER_PID" 2>/dev/null || true' EXIT

  READY=0
  for _ in $(seq 1 60); do
    code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/v1/sys/health" 2>/dev/null || true)
    if [ "$code" = "200" ]; then READY=1; break; fi
    sleep 1
  done
  if [ "$READY" != "1" ]; then
    echo "dev server did not become healthy — tail of $LOG:"
    tail -20 "$LOG"
    FAILED=1
  else
    if (cd "$WT/compat/harness" && go run . --target "http://127.0.0.1:$PORT" --token "$TOKEN" --specs ../specs --format table); then
      echo "harness: no FAIL/ERROR verdicts"
    else
      echo "HARNESS FAILED (FAIL or ERROR verdicts above)"
      FAILED=1
    fi
  fi
  kill "$SERVER_PID" 2>/dev/null || true
  trap - EXIT
fi

echo ""
if [ "$FAILED" = "0" ]; then
  echo "VERDICT: PASS — all gates green"
  exit 0
fi
echo "VERDICT: FAIL — one or more gates failed"
exit 1
