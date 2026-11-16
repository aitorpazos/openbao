#!/usr/bin/env bash
# Canonical corpus runner: two passes, one merged result.
#
#   Pass 1 (admin/root token): the full corpus. Several suites pin
#   root-token behavior (events subscribe, namespaces api-lock, EGP
#   root-bypass, ...) and cannot run under a restricted token.
#   Pass 2 (SCIM actor token, from scim-fixture.sh): the scim suite,
#   whose v2 protocol routes require the run token's entity to own the
#   compat-scim-actor client (specs/scim/notes.md).
#
# The merged output replaces pass 1's scim rows with pass 2's, so the
# canonical totals are a property of (specs x target x setup). If the
# target lacks SCIM (e.g. Vault Community: no activation surface), the
# fixture setup fails cleanly and pass 1's scim rows are kept — those
# report FEATURE_ABSENT, matching an unlicensed target.
#
# Usage:
#   ./run-corpus.sh <target-url> <admin-token> [actor-token]
#
# The actor token is normally obtained by running scim-fixture.sh first;
# pass it here, or let this script invoke scim-fixture.sh itself.
# HARNESS_BIN overrides the harness command (default: `go run .` in
# compat/harness). Requires: python3, curl.
#
# Examples:
#   ACTOR=$(./scim-fixture.sh http://127.0.0.1:8200 "$ROOT") \
#     ./run-corpus.sh http://127.0.0.1:8200 "$ROOT" "$ACTOR"
#   ./run-corpus.sh http://127.0.0.1:8512 "$ROOT"   # oracle: scim stays FEATURE_ABSENT

set -euo pipefail

TARGET=${1:?target url required}
ADMIN=${2:?admin token required}
ACTOR=${3:-}
HERE=$(cd "$(dirname "$0")" && pwd)
SPECS_DIR=${SPECS_DIR:-$HERE/../specs}

run_pass() { # url token filter outfile
  local filter=${3:-}
  local -a cmd=()
  if [ -n "${HARNESS_BIN:-}" ]; then
    cmd=("$HARNESS_BIN")
  else
    cmd=(go run .)
  fi
  local rc=0
  (cd "$HERE/../harness" && "${cmd[@]}" \
    --target "$1" --token "$2" --specs "$SPECS_DIR" \
    ${filter:+--filter "feature=$filter"} \
    --format json > "$4") || rc=$?
  # 1 = FAIL/ERROR rows exist (expected while converging); treat as data.
  # >=2 = transport/usage failure — abort the run.
  if [ "$rc" -ge 2 ]; then
    echo "harness exited $rc (transport/usage failure)" >&2; exit "$rc"
  fi
}

TMPDIR_RUN=$(mktemp -d /tmp/run-corpus.XXXXXX)
trap 'rm -rf "$TMPDIR_RUN"' EXIT

run_pass "$TARGET" "$ADMIN" "" "$TMPDIR_RUN/pass1.json"

if [ -z "$ACTOR" ]; then
  if ACTOR=$(bash "$HERE/scim-fixture.sh" "$TARGET" "$ADMIN" 2>"$TMPDIR_RUN/scim-fixture.err"); then
    echo "scim fixture: ok" >&2
  else
    echo "scim fixture unavailable; keeping pass-1 scim rows (expected on unlicensed targets)" >&2
  fi
fi

if [ -n "$ACTOR" ]; then
  run_pass "$TARGET" "$ACTOR" scim "$TMPDIR_RUN/pass2.json"
else
  echo '[]' > "$TMPDIR_RUN/pass2.json"
fi

python3 - "$TMPDIR_RUN/pass1.json" "$TMPDIR_RUN/pass2.json" <<EOF
import json, os, sys
from collections import Counter
p1 = json.load(open(sys.argv[1]))
p2 = json.load(open(sys.argv[2]))
def base(r): return os.path.basename(r['file'])
# scim split: 00-activation is a pre-activation contract (no_auth) and must
# come from pass 1; 10-40 come from pass 2. When pass 2 is empty (target
# lacks SCIM, e.g. Vault Community oracle), keep ALL pass-1 scim rows so
# the suite reports FEATURE_ABSENT instead of silently vanishing.
keep_p1 = [r for r in p1 if r['feature'] != 'scim'
           or base(r) == '00-activation.yaml' or not p2]
merged = keep_p1 + [r for r in p2 if base(r) != '00-activation.yaml']
out = "${MERGED_OUT:-$PWD/corpus-results.json}"
json.dump(merged, open(out, 'w'), indent=1)
c = Counter(r['verdict'] for r in merged)
print(f"rows: {len(merged)}  " + "  ".join(f"{k}={v}" for k, v in sorted(c.items())))
print(f"merged results: {out}")
EOF
