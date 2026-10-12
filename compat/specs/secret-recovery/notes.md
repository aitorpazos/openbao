# secret-recovery family notes

Source: `https://developer.hashicorp.com/vault/docs/sysadmin/snapshots/recover-a-secret/single-cluster`
(Vault Enterprise docs, v2.x latest; feature is Enterprise-gated upstream).

## Verified surface

| Behavior | Upstream documented | This build |
|---|---|---|
| RECOVER HTTP method + `X-Vault-Recover-Snapshot-Id` header | yes | 204 on success |
| PUT/POST alias with the same header (body ignored) | yes (docs show PUT as the alias) | 204 |
| `X-Vault-Recover-Source-Path` recovers to another path on the same mount | yes | 204; new path holds the value |
| `recover` ACL capability | yes (documented in the guide's ACL section) | own capability bit; policy path rules accepted |
| Cubbyhole recovery | yes ("supports cubbyhole ... 1.20.0") | works; per-token namespace resolved, caller's own cubbyhole written |
| kv v1 recovery | yes (1.20.0) | works |
| ssh /config/ca (1.20.3) | yes | NOT implemented -> 500 version gate |
| databases static roles/creds (1.20.4) | yes | NOT implemented -> 500 version gate |
| kv v2 NOT supported | yes (guide lists only kv v1) | 500 "plugin kv at version 2 does not support snapshot recovery; only kv version 1 is documented" |
| Unauthenticated/userpass etc. | n/a | root token used throughout |
| Load/unload root-namespace only | yes (load API) | enforced by the existing snapshot-load service |
| No other snapshot loaded / 72h auto-unload | yes (guide restrictions) | single loaded-snapshot service on the core |
| mlock disabled | yes (guide restriction) | OpenBao has no mlock — inherently satisfied |
| Same cluster + same unseal keys | yes (guide restriction) | snapshot ids verified against the loaded service |

## Flow mechanics observed live

- Export: GET `/v1/sys/storage/raft/snapshot` (binary). POST
  `/v1/sys/storage/raft/snapshot-load` with the raw body; response carries
  `snapshot_id`; the load status transitions `loading` -> `ready`.
- Recover: `RECOVER /v1/kvrec/app/cred` with
  `X-Vault-Recover-Snapshot-Id: $sid` -> 204 (no body); the secret is
  written back at the target path and verifies with a plain GET.
- Error contract (all observed):
  - missing header -> 400 `X-Vault-Recover-Snapshot-Id header is required...`
  - wrong snapshot id -> 500 `snapshot %q is not the currently loaded snapshot`
  - source path not in the snapshot -> 500 `path %q not found in the loaded snapshot`
  - kv v2 mount -> 500 version gate (see table)
  - cross-mount target -> 500 `not on the same mount`
  - unload (DELETE) then RECOVER -> 500 `no snapshot is currently loaded`
  - disabled source mount -> rejected (mount entry check)
- The RECOVER request is authorized with the caller's ACL on the TARGET
  path; the `recover` capability is required on that path (a policy with
  only `read` gets permission denied).

## Implementation sketch (for reapplying on new upstream releases)

- `sdk/logical/request.go`: RecoverOperation (+ AllOperations,
  ExternalOperations), ctx keys (defined but unused by core; headers are
  read from `req.Headers` because the core derives its request context from
  `activeContext` — http context values do not flow through).
- `internal/http/logical.go`: RECOVER method mapping; POST/PUT alias when
  the snapshot-id header is present.
- `internal/vault/policy/*`: recover capability (new bit after subscribe).
- `internal/vault/logical_recover.go`: the recovery engine (mount-table
  read from the snapshot view, longest-prefix match, cubbyhole per-token
  recursive scan with CubbyholeID tiebreaker, same-mount check, plugin
  gates, synthetic write-back carrying the caller TokenEntry).
- `internal/vault/logical_system_raft_snapshot_load.go`: registers/unregisters
  the loaded-snapshot service on the core.
- `internal/vault/request_handling.go`: `doRoutingOrRecover` intercept.
