# PATCHES.md — porting ledger

This fork carries Vault Enterprise-parity features on top of OpenBao.
Porting to a new OpenBao release must be mechanical, so every change that is
NOT an additive new package is recorded here. Additive new packages
(compat/, feature packages) port for free and are not listed.

## Rules

1. Prefer additive code: new files/packages behind narrow seams. Core files
   are only touched to install hooks, and every such hook is listed below.
2. Each row states the file, the nature of the diff, and why it exists.
   When rebasing onto a new OpenBao release, re-apply rows one by one and
   re-run `go build ./...` + `go test ./vault/... ./http/...` + the harness.
3. Rows are removed only when OpenBao upstream accepts an equivalent hook
   (record the upstream PR in the row).

## Ledger

| File | Nature | Why | Upstream PR |
|------|--------|-----|-------------|
| `internal/vault/logical_system.go` | +1 path registration line in `NewSystemBackend`; +1 field (`namedMFAMethodLock`) on `SystemBackend` | Registers step-up MFA named-method paths; per-backend mutex for atomic config writes | — |

### Step-up MFA (compat-harness branch)

New packages/files (additive, port free): `internal/vault/logical_system_mfa_methods.go`
(+ test) implement `sys/mfa/method/{totp,duo,okta,pingid}/<name>` config CRUD,
root-namespace-only, stable method IDs, documented defaults (TOTP: SHA1/6/20/30/200/1/5).
Acceptance: `compat/specs/mfa/sys-mfa-method-*.yaml` PASS on live build.
