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
