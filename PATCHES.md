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
| `internal/vault/core.go` | +9 lines in `Core.performPolicyChecks` (after root-privs check): one length check + `validateNamedMFA` call when ACL results carry `mfa_methods` | Step-up enforcement hook; zero added work when no rule requires MFA | — |
| `internal/vault/logical_system.go` | +1 line: `b.Paths = append(b.Paths, b.leaseCountPaths()...)` | Registers lease-count quota config paths | — |
| `internal/vault/quotas/quotas.go` | +7 lines: `TypeLeaseCount` in type list, `String()`, `leaseRecords` map init/reset, parse case | Adds the lease-count quota type to the existing quota manager | — |
| `internal/vault/expiration.go` | +11 lines: quota-check call at lease registration, error mapping | Enforcement: reject lease issuance when quota exhausted | — |
| `internal/vault/request_handling.go` | +17 lines: `checkBatchLeaseQuota` calls at auth/secret lease creation, error mapping to `logical.ErrLeaseCountQuotaExceeded` | Enforcement: batch/auth lease paths respect lease-count quotas | — |
| `internal/vault/core.go` | +3 lines in `configureLogicalBackends`: transform engine factory registration | Mountable `transform` engine (additive builtin) | — |
| `internal/vault/logical_system.go` | ha-status response: capitalized `Nodes` array (same entries as legacy lowercase `nodes`) gains per-node `redundancy_zone` — each node's own `autopilot_redundancy_zone` raft-storage label, learned by the active node over the echo channel; empty for unconfigured nodes and non-raft clusters | Documented Vault Enterprise /sys/ha-status shape (api-docs/system/ha-status, v2.x (latest)); lowercase `nodes` unchanged for OpenBao back-compat | — |
| `internal/vault/core.go` | +2 lines: `PeerNode.RedundancyZone` field + copy from cached echo info | Zone labels for ha-status compat nodes | — |
| `internal/vault/core.go` | +2 fields on `Core` (`sentinelStore`, `sentinelStoreLock`) + lazy init helper | Sentinel EGP/RGP store + per-core lock (fields in core.go because Core lacks an extension point) | — |
| `internal/vault/core.go` | +1 hook call in `performPolicyChecks` (after step-up MFA block, before `ret.Allowed = true`): Sentinel EGP/RGP gate; on denial appends to `ret.Error`, sets `DeniedError` | Policy enforcement hook: EGP by request path, RGP by token policy names; advisory allows with warning, soft-mandatory honors `X-Vault-Policy-Override`, hard-mandatory denies. Root bypass is upstream (existing root check precedes the hook) | — |
| `internal/vault/logical_system.go` | +1 line: `b.Paths = append(b.Paths, b.sentinelPaths()...)` | Registers `sys/policies/egp/*` + `sys/policies/rgp/*` CRUD paths | — |
| `internal/http/logical.go` | +3 lines in `buildLogicalRequest` (after MFA header parse): `req.PolicyOverride` from `X-Vault-Policy-Override` header | Soft-mandatory override per documented Enterprise semantics | — |
| `internal/vault/forwarding/request_forwarding_service.proto` (+regenerated `.pb.go`) | +1 field on EchoRequest: `raft_redundancy_zone = 12` | Echo channel carries each node's zone label so the active node can report cluster-wide zones | — |
| `internal/vault/forwarding/request_forwarding_rpc.go` | Echo server handler stores `in.RaftRedundancyZone` in cache entry + `FollowerStates.Update`; client `tick()` sets the field from the raft backend | Same as above (wire path) | — |
| `internal/physical/raft/raft.go` | +`redundancyZone` field, +`conf["autopilot_redundancy_zone"]` parse, +wiring in constructor, +`RedundancyZone()` getter | Source of a node's zone label (server config-file setting documented in Enterprise docs) | — |
| `internal/physical/raft/raft_autopilot.go` | +zone on `FollowerState`/`EchoRequestUpdate` + `FollowerStates.Zone`; autopilot state response decorated with `redundancy_zones` map, integer `optimistic_failure_tolerance`, per-server zone-aware `node_type`; promoter wired with zone resolver | Documented Enterprise autopilot-state additions (api-docs/system/storage/raftautopilot) | — |
| `internal/physical/raft/raft_autopilot_promoter.go` | `CustomPromoter` gains `zoneOf` resolver; `GetNodeTypes`/`CalculatePromotionsAndDemotions` become zone-aware (zone-voter/zone-extra-voter/zone-standby; extra zone voters demoted first) | Enterprise redundancy-zone semantics: per-zone voter promotion/failure tolerance | — |
| `internal/http/handler.go` | +1 route in `injectDataIntoTopRoutes`: `/v1/sys/storage/raft/autopilot/state` | Documented Enterprise autopilot-state sample is a top-level payload, not a `data` envelope | — |

### Redundancy zones (compat-harness branch)

New files (additive, port free): `internal/physical/raft/raft_autopilot_zones.go`
(`zonesFromAutopilotState` — zone map / optimistic failure tolerance / node-type
derivation, + tests), `internal/vault/ha_redundancy_zones.go` (per-API-address
zone lookup for ha-status), `internal/physical/raft/raft_autopilot_zones_test.go`,
`internal/physical/raft/raft_autopilot_promoter_zones_test.go`.
Semantics: per zone `FailureTolerance = len(Servers) - len(Voters)`;
`OptimisticFailureTolerance` = min across zones (0 when no zones); node types
`zone-voter` (first voter in a zone), `zone-extra-voter` (surplus voters,
demotion candidates), `zone-standby` (non-voters); unzoned servers excluded from
`node_types` and from zones. Zone labels are operator-defined strings from
`autopilot_redundancy_zone` in the raft storage stanza. Acceptance:
`compat/specs/redundancy/*` + live single-node raft server (zone `a`:
`redundancy_zones.a{servers,voters}`, `node_type: zone-voter`, top-level OFT,
ha-status `redundancy_zone: a`); multi-node failover promotion not exercised
yet (single-node fixture limitation, noted in notes.md).

### Step-up MFA (compat-harness branch)

Policy parser already carried `mfa_methods` in OpenBao upstream (no parser diff).
New packages/files (additive, port free): `internal/vault/logical_system_mfa_methods.go`
(+ test) implement `sys/mfa/method/{totp,duo,okta,pingid}/<name>` config CRUD,
root-namespace-only, stable method IDs, documented defaults (TOTP: SHA1/6/20/30/200/1/5).
`internal/vault/logical_system_mfa_totp.go` (+ test): per-entity TOTP enrollment
(self `GET .../generate`, admin `POST .../admin-generate`, admin-destroy).
`internal/vault/policy_mfa.go` (+ test): `validateNamedMFA` — X-Vault-MFA header
parsing (`name[:key[=value]]`), AND semantics, TOTP validation (algorithm/digits/
period/skew/max_validation_attempts, replay rejection), named errors.
Acceptance: `compat/specs/mfa/*` + live e2e (403 missing/invalid, 200 valid code,
403 replay). Documented deviation: step-up failure = 403 errors[] (challenge shape
undocumented in public docs).

### Sentinel EGP/RGP (compat-harness branch)

New packages/files (additive, port free): `internal/vault/sentinel/`
(policy + store + declarative document evaluator, + tests),
`internal/vault/logical_system_sentinel.go` (+ test), `internal/vault/core_sentinel.go`,
`compat/specs/sentinel/*`, harness token-capture/`contains` support.
Surface: `sys/policies/egp/<name>` and `sys/policies/rgp/<name>` CRUD
(`policy`, `enforcement_level` ∈ advisory/soft-mandatory/hard-mandatory, `paths`
for EGP as string or array; RGP rejects `paths`; list returns `keys` +
`name_path_map`; base64 `policy` stored decoded so reads return the document).
Enforcement: EGPs evaluated by request path (exact + prefix via trailing glob),
RGPs by token policy names; evaluation order unauth → EGP, authed → ACL grant →
RGP (token) → EGP (path); root bypass is upstream behavior. Advisory = allow with
server warning; soft-mandatory = deny unless `X-Vault-Policy-Override: true`
header; hard-mandatory = deny.
**Documented deviation:** policy documents use a declarative condition subset of
Sentinel (subjects: request.path/operation/data.*, token.policies/metadata.*;
operators equals/not_equals/matches/in/contains/exists/numeric comparisons;
combinators all/any/not), not the full Sentinel rule language — clean-room choice
because the language itself is not part of the documented public API surface.
Acceptance: `compat/specs/sentinel/*` + live dev server (full enforcement spec
green; unauth EGP denial on a userpass login path verified manually).

### Replication phase 1: config/state machine, status surface, secondary activation (compat-harness branch)
**Status:** implemented. New `internal/vault/replication.go` (per-stream
replicationModeState persisted in barrier storage under `core/replication/{performance,dr}`
— mode/state/cluster_id/primary_cluster_addr/secondary_id/known secondaries+primary
addrs/last_start/paths_filters/secondary_public_key; atomic `c.replicationState` consts
refresh wired into CreateCore + ha.go postUnseal paths) and
`internal/vault/logical_system_replication.go` (documented `/sys/replication` surface:
combined + typed status (unauthenticated), primary enable/demote/disable,
secondary-token (JWT response-wrapping token with addr claim; duplicate id rejected),
revoke-secondary, secondary enable/promote/update-primary/disable (DR ops need
`dr_operation_token`), paths-filter CRUD (performance-only), dynamic-filter read,
merkle-check, reindex (diff/force/skip_flush), recover, generate-public-key).
Status shapes follow the REPP/REPD samples (mode/state/cluster_id/merkle_root/
last_wal family/epochs as epoch-seconds strings/secondaries[]/known_* lists).
Secondary activation: in-cluster wrapped tokens unwrap locally; JWT tokens are
parsed for the primary's `addr` and unwrapped via POST <addr>/v1/sys/wrapping/unwrap.
**Documented deviations (phase 1, see compat/specs/replication/notes.md):** no WAL
streaming (secondaries do not connect; connection_status "disconnected");
merkle_root = bounded on-demand barrier walk (undecryptable entries skipped), not an
indexed tree; corrupted_merkle_tree always false; no data wipe on secondary enable;
paths filters stored but not enforced; recover returns a warning; reindex recomputes
the walk; activation JWTs not signature-verified (pubkey verification is phase 2);
re-enabling reuses the local cluster ID.
**Live gotchas fixed:** request handlers must NOT take c.stateLock (the request
pipeline holds RLock for the whole request → self-deadlock; dedicated
`c.replicationStateMut` instead); generate-public-key must not persist state when
the stream is disabled; handler validation errors are error responses (400), not Go
errors (500).
Acceptance: `go test ./internal/vault -run TestReplication` green (unit: lifecycle,
tokens/wrapping, paths-filter, DR op-token gates, merkle-check/reindex/recover,
keypair); `compat/specs/replication/*.yaml` 57/57 PASS on a fresh dev server (harness
extended with `no_auth` case option for the documented unauthenticated status
endpoints); two-server cross-cluster activation verified manually (token from primary
activates a second server; secondary reports the primary's cluster_id).
