#!/usr/bin/env bash
# port-release.sh — mechanically re-apply the compat feature stack onto a new OpenBao release.
#
# The compat-harness branch is a linear stack of feature commits on top of an
# OpenBao release tag. Porting to a new release is therefore a cherry-pick
# replay of the stack onto the new release, with PATCHES.md as the
# conflict-resolution map, followed by the standard gates (build, unit tests,
# spec harness against an ephemeral dev server).
#
# Usage:
#   port-release.sh --base <tag|sha> --target <tag|sha> [flags]
#
# Flags:
#   --repo DIR       source repo (default /Volumes/External/aitor/workspace/repos/openbao)
#   --base REF       release tag/commit the current stack is based on (required)
#   --target REF     new release tag/commit to port onto (required; tries origin/NAME too)
#   --branch NAME    port branch name (default port/<base>-to-<target>, sanitized)
#   --worktree DIR   port worktree (default /Volumes/External/aitor/worktrees/openbao-port-<target>)
#   --port N         dev-server port for the harness gate (default 8299)
#   --dry-run        print the plan (commits + ledger rows) and exit without touching anything
#   --resume         re-enter an interrupted port: skips setup, runs gates when no replay in progress
#   --skip-gates     stop after a clean replay (gates can be rerun via verify.sh)
#
# Exit codes: 0 ok; 1 conflict or gate failure; 2 usage error.
set -euo pipefail

REPO="${REPO:-/Volumes/External/aitor/workspace/repos/openbao}"
SRC_BRANCH="${SRC_BRANCH:-compat-harness}"
WTROOT="${WTROOT:-/Volumes/External/aitor/worktrees}"
PORT="8299"
TOKEN="compat-harness-port"
BASE="" TARGET="" BRANCH="" WT=""
DRY_RUN=0 RESUME=0 SKIP_GATES=0

usage() {
  sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
}

while [ $# -gt 0 ]; do
  case "$1" in
    --repo) REPO="$2"; shift 2 ;;
    --base) BASE="$2"; shift 2 ;;
    --target) TARGET="$2"; shift 2 ;;
    --branch) BRANCH="$2"; shift 2 ;;
    --worktree) WT="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --resume) RESUME=1; shift ;;
    --skip-gates) SKIP_GATES=1; shift ;;
    -h|--help) usage ;;
    *) echo "unknown flag: $1" >&2; usage ;;
  esac
done

[ -n "$BASE" ] || { echo "ERROR: --base is required" >&2; usage; }
[ -n "$TARGET" ] || { echo "ERROR: --target is required" >&2; usage; }
[ -d "$REPO" ] || { echo "ERROR: repo not found: $REPO" >&2; exit 2; }

sanitize() { echo "$1" | tr '/:' '--' | tr -c 'A-Za-z0-9._-' '-' | sed 's/-*$//' ; }

resolve_ref() {
  git -C "$REPO" rev-parse --verify --quiet "$1^{commit}" 2>/dev/null && return 0
  git -C "$REPO" rev-parse --verify --quiet "origin/$1^{commit}" 2>/dev/null && return 0
  echo "ERROR: cannot resolve ref: $1 (fetch origin if the tag is new)" >&2
  return 1
}

BASE_SHA=$(resolve_ref "$BASE")
TARGET_SHA=$(resolve_ref "$TARGET")
BRANCH="${BRANCH:-port/$(sanitize "$BASE")-to-$(sanitize "$TARGET")}"
WT="${WT:-$WTROOT/openbao-port-$(sanitize "$TARGET")}"

echo "== port plan =="
echo "repo:      $REPO"
echo "base:      $BASE ($BASE_SHA)"
echo "target:    $TARGET ($TARGET_SHA)"
echo "source:    branch $SRC_BRANCH"
echo "branch:    $BRANCH"
echo "worktree:  $WT"
echo ""
echo "== feature stack to replay ($BASE_SHA..$SRC_BRANCH) =="
git -C "$REPO" log --reverse --format='  %h %s' "$BASE_SHA..$SRC_BRANCH"
echo ""
echo "== PATCHES.md ledger seams (conflict map for core files) =="
sed -n '/^## Ledger/,/^### /p' "$REPO/PATCHES.md" | grep '^| `' | sed 's/^| `\([^`|]*\)`.*/  \1/' | sort -u

if [ "$DRY_RUN" = "1" ]; then
  echo ""
  echo "dry run only — nothing was modified"
  exit 0
fi

# ---- worktree setup -------------------------------------------------------
replay_in_progress() { # non-zero if a cherry-pick/rebase sequencer is active in $WT
  local gd
  gd=$(git -C "$WT" rev-parse --git-dir)
  [ -d "$gd/sequencer" ] || [ -d "$gd/rebase-merge" ] || [ -d "$gd/rebase-apply" ]
}

if [ "$RESUME" = "1" ]; then
  [ -d "$WT" ] || { echo "ERROR: --resume but worktree missing: $WT" >&2; exit 2; }
  git -C "$WT" fetch origin --quiet 2>/dev/null || true
else
  if [ -d "$WT" ]; then
    echo "ERROR: worktree path already exists: $WT (remove it or pass --worktree/--resume)" >&2
    exit 2
  fi
  HELD=$(git -C "$REPO" worktree list --porcelain | awk -v b="refs/heads/$BRANCH" '
    $1 == "worktree" { wt = $2 }
    $1 == "branch"   { if ($2 == b) print wt }')
  if git -C "$REPO" show-ref --verify --quiet "refs/heads/$BRANCH"; then
    if [ -n "$HELD" ]; then
      echo "ERROR: branch $BRANCH is checked out in $HELD (not the port worktree)" >&2
      exit 2
    fi
    git -C "$REPO" worktree add "$WT" "$BRANCH"
    echo "reusing existing branch $BRANCH (resetting to target)"
    git -C "$WT" reset --hard "$TARGET_SHA"
  else
    git -C "$REPO" worktree add -b "$BRANCH" "$WT" "$TARGET_SHA"
  fi
fi

if replay_in_progress; then
  echo ""
  echo "== replay already in progress in $WT =="
  echo "resolve conflicts there (the ledger rows printed above are the resolution map), then:"
  echo "  git -C $WT add <resolved files>"
  echo "  git -c core.editor=true -C $WT cherry-pick --continue"
  echo "repeat until the replay completes, then rerun this script with --resume to run the gates."
  echo "escape hatch: git -C $WT cherry-pick --abort"
  exit 1
fi

if [ "$RESUME" = "1" ]; then
  echo ""
  echo "== --resume: replay already complete, skipping to gates =="
else
  echo ""
  echo "== replaying stack onto $TARGET =="
  COMMITS=$(git -C "$REPO" log --reverse --format='%H' "$BASE_SHA..$SRC_BRANCH")
  if [ -z "$COMMITS" ]; then
    echo "ERROR: no commits between $BASE and $SRC_BRANCH — wrong --base?" >&2
    exit 2
  fi
  # shellcheck disable=SC2086
  if ! git -C "$WT" cherry-pick $COMMITS; then
    echo ""
    echo "== CONFLICTS — PATCHES.md is the resolution map =="
    for f in $(git -C "$WT" diff --name-only --diff-filter=U); do
      echo "  conflicted: $f"
      base=$(basename "$f")
      grep -n "$base" "$WT/PATCHES.md" | head -3 | sed 's/^/    ledger: /' || true
    done
    echo ""
    echo "resolve in $WT using the ledger rows, then:"
    echo "  git -C $WT add <files> && git -c core.editor=true -C $WT cherry-pick --continue"
    echo "repeat until the replay completes, then rerun with --resume (gates)."
    echo "escape hatch: git -C $WT cherry-pick --abort"
    exit 1
  fi
  echo "replay clean."
fi

git -C "$WT" log --oneline -1

if [ "$SKIP_GATES" = "1" ]; then
  echo ""
  echo "gates skipped (--skip-gates). Run later:"
  echo "  bash $(dirname "$0")/verify.sh --worktree $WT"
  exit 0
fi

# ---- gates ----------------------------------------------------------------
echo ""
echo "== gates =="
exec bash "$(dirname "$0")/verify.sh" --worktree "$WT" --port "$PORT"
