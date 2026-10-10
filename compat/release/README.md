# compat/release — porting the feature stack to a new OpenBao release

The `compat-harness` branch is a linear stack of feature commits on top of an
OpenBao release tag. This directory holds the mechanical porting flow required
by the mission: "easy to apply on top of new upstream releases".

## Pieces

| File | Purpose |
|------|---------|
| `port-release.sh` | Replays the feature stack onto a new release tag, guided by `PATCHES.md` on conflicts, then runs the gates |
| `verify.sh` | Gates only: `go build ./...`, `go test ./internal/vault/...`, full spec harness against an ephemeral dev server (port 8299) |

## Flow for a new upstream release

1. **Sync the fork.** `origin` is `github.com/aitorpazos/openbao`. Sync `main`
   with upstream `openbao/openbao` (GitHub UI → "Sync fork", or
   `gh repo sync aitorpazos/openbao --source openbao/openbao --branch main`)
   and let the release tag land on the fork.
2. **Fetch.** `git -C <repo> fetch origin --tags`
3. **Plan.** `bash compat/release/port-release.sh --base v2.7.1 --target v2.8.0 --dry-run`
   — prints the feature commits to replay and the core-file seams from the ledger.
4. **Port.** Same command without `--dry-run`. It creates
   `/Volumes/External/aitor/worktrees/openbao-port-<target>`, branches
   `port/<base>-to-<target>`, and rebases the stack.
5. **Conflicts.** On conflict the script lists each conflicted file with the
   matching `PATCHES.md` ledger rows — those rows are the resolution map
   (each row documents the diff's shape and intent). Resolve in the port
   worktree, `git -c core.editor=true rebase --continue`, rerun with `--resume`.
6. **Gates.** After a clean rebase the script runs `verify.sh`:
   build → unit tests → full spec harness against a fresh dev server.
   `FEATURE_ABSENT` verdicts are informational (Enterprise gaps); any
   `FAIL`/`ERROR` fails the port.
7. **Ship.** Push the port branch, merge to `compat-harness` (fast-forward if
   linear), tag or image as needed.

## Notes and caveats

- The dev server used by the gates is in-memory storage. Specs that require
  Integrated Storage (e.g. raft autopilot state) report `FEATURE_ABSENT`
  there — validate those separately against a Raft-backed target.
- Unit tests are `go test ./internal/vault/... -count=1` (~10 min uncached;
  cached afterwards for identical content).
- Ports are forward-only: the rebase maps one release to the next. For
  repairing an older base, redo from the current release instead of
  back-porting.
- `PATCHES.md` rows with an `Upstream PR` column entry mean the seam may be
  droppable once OpenBao accepts an equivalent hook — check before
  re-applying on a new base.
