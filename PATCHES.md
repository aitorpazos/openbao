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
| `internal/vault/logical_system.go` | +1 path registration: `b.oauthResourceServerPaths()` | Namespace-scoped OAuth resource server configuration API (configuration only; JWT authentication deferred) | — |
| `internal/vault/core.go` | +1 factory registration: `logicalBackends["agent-registry"] = c.agentRegistryFactory` | Agent registry backend at documented root-level path | — |
| `internal/vault/mount.go` | Required agent-registry mount helper call; backfill helper in mount upgrades for preexisting namespaces; protected/untunable/singleton entries | Expose `/agent-registry/` in each namespace through normal ACL-aware routing, without HTTP or request-handling rewrites | — |
| `internal/vault/logical_system.go` | +2 lines: `"activation-flags"` in the system backend's `Unauthenticated` special-paths list; `b.Paths = append(b.Paths, b.activationFlagPaths()...)` registration | Documents GET `/sys/activation-flags` as readable without auth and registers the activation-flags root (GET status + one-way PUT `enable-scim/activate`) required by the SCIM feature gate | — |
| `internal/vault/identity/store.go` | +3 narrow seams in `NewIdentityStore`: `"scim/v2/ServiceProviderConfig"` in `Unauthenticated` special paths, `iStore.SCIMCleanup(ctx)` in the periodic hook, `scimPaths(i)` in `paths()` | Registers SCIM protocol/client endpoints on the identity store; documents unauthenticated service discovery; periodic cleanup of asynchronously-deleting clients | — |
| `internal/vault/logical_system.go` | +1 line: `b.Paths = append(b.Paths, b.rotationPolicyPaths()...)` | Registers root-namespace rotation-policy POST/GET/DELETE configuration API; LDAP static-role and OS-account assignment/scheduler integration deferred | — |
| `internal/vault/logical_system.go` | +1 line: `b.Paths = append(b.Paths, b.syncPaths()...)` | Registers local Secrets Sync destination, association, GitHub-app and PATCH config APIs; provider execution deferred | — |
| `compat/harness/main.go` | PATCH default Content-Type is `application/merge-patch+json` (explicit headers still override) | Exercise OpenBao's existing merge-patch HTTP contract rather than failing before backend dispatch | — |
| `internal/vault/logical_system.go` | +1 path registration line in `NewSystemBackend`; +1 field (`namedMFAMethodLock`) on `SystemBackend` | Registers step-up MFA named-method paths; per-backend mutex for atomic config writes | — |
| `internal/vault/core.go` | +9 lines in `Core.performPolicyChecks` (after root-privs check): one length check + `validateNamedMFA` call when ACL results carry `mfa_methods` | Step-up enforcement hook; zero added work when no rule requires MFA | — |
| `internal/vault/logical_system.go` | +1 line: `b.Paths = append(b.Paths, b.leaseCountPaths()...)` | Registers lease-count quota config paths | — |
| `internal/vault/quotas/quotas.go` | +7 lines: `TypeLeaseCount` in type list, `String()`, `leaseRecords` map init/reset, parse case | Adds the lease-count quota type to the existing quota manager | — |
| `internal/vault/expiration.go` | +11 lines: quota-check call at lease registration, error mapping | Enforcement: reject lease issuance when quota exhausted | — |
| `internal/vault/request_handling.go` | +17 lines: `checkBatchLeaseQuota` calls at auth/secret lease creation, error mapping to `logical.ErrLeaseCountQuotaExceeded` | Enforcement: batch/auth lease paths respect lease-count quotas | — |
| `internal/http/handler.go` | removed `health` from `restrictedSysAPIsNonLogical` (+ docs rationale comment) | Vault docs (namespace-api-lock) cite sys/health as an exempt path that responds from within a namespace; the old block returned 400 "operation unavailable in namespaces" | — |
| `internal/http/logical_test.go` | `TestLogical_NamespaceRestrictedAPIs`: sys/health moved from the restricted list to a new exempt subtest (200 within namespace) | The test asserted the pre-parity behavior contradicted by the documented api-lock exempt paths | — |
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
| `internal/helper/identity/mfa/types.proto` | +`enable_self_enrollment` on TOTP method config (field 9) + regenerated `types.pb.go` | Login-MFA TOTP self-enrollment flag (api-docs/secret/identity/mfa/totp, v2.x (latest)) | — |
| `internal/vault/identity/store.go` | +`handleLoginMFASelfEnrollUpdate` handler + path registration for `identity/mfa/method/totp/self-enroll` (requires `mfa_request_id`+`mfa_method_id`, entity-backed token, enabled method) | Documented self-enrollment endpoint; binds enrollment to the caller's unexpired pending login without consuming it | — |
| `internal/vault/identity/mfa.go` | +`ValidateMFASelfEnrollment` (pop+re-push pending under queue lock, namespace/entity binding) + `enable_self_enrollment` on config create/read | Self-enrollment semantics: enrollment must not consume the pending login; non-entity tokens rejected | — |
| `internal/vault/login_mfa.go` | +`enable_self_enrollment` persisted on login MFA TOTP method config (create/update/read) | Operator-visible knob enabling self-enrollment per method | — |
| `internal/vault/logical_system_raft.go` | `raftStoragePaths()` prepends `b.snapshotLoadPaths()` (return append pattern) | Registers `/sys/storage/raft/snapshot-load` (POST/LIST/GET/DELETE) + `/sys/storage/raft/snapshot-auto/snapshot-load/:name` when raft storage is in use | — |
| `internal/http/handler.go` | +1 route in `alwaysRedirectPaths`: `sys/storage/raft/snapshot-load` | Binary upload must not be forwarded from standbys (mirrors snapshot/snapshot-force semantics) | — |
| `internal/http/logical.go` | +1 condition in the raw-body pass-through: `path == "sys/storage/raft/snapshot-load"` | Snapshot uploads carry binary bodies; skip JSON parsing | — |
| `internal/http/util.go` | +1 path in `isSnapshotRequest`: `/v1/sys/storage/raft/snapshot-load` | Skip request-body buffering for binary snapshot uploads | — |
| `compat/harness/spec.go` | +`BodyRaw` field (base64) on `Request` | Binary (non-JSON) request bodies for upload cases; cannot survive YAML/JSON round trips | — |
| `compat/harness/main.go` | +`body_raw` handling: base64 decode, `Content-Type: application/octet-stream` | Same as above (harness execution) | — |

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
**Follow-up fix (regression):** `computeReplicationConstsState` now reports
PerformancePrimary (active) / PerformanceStandby (standby) when the barrier holds no
performance replication config, mirroring the pre-existing in-tree semantics
(pristine ha.go hardcoded these). Reporting PerformanceDisabled on plain standbys
broke every `ForwardPerformanceStandby: true` path — notably `sys/mfa/validate`,
whose callback then executed locally on the standby, hit the read-only
`PopMFAResponseAuthByID` guard, and had its ErrReadOnly masked into a 400
"invalid request ID" instead of forwarding (flaky failure in
TestLoginMfaGenerateTOTPTestAuditIncluded, whose final phase deliberately
targets Cores[1], a standby).

### KMIP pass B: native TTLV/TLS protocol (compat-harness branch)

**Status:** implemented. Additive packages/files (port free):
`internal/vault/kmip/` (ttlv.go — OASIS KMIP 1.4 TTLV codec: all ten primitive
types + nested structures, 8-byte alignment/padding, four-MiB frame cap, depth
32; tags.go — operation/attribute/object tag table; server.go — TLS listener
with mTLS RequireAndVerifyClientCert, per-connection handlers, graceful close;
ttlv_test.go — round-trip + rejection + fuzz). `logical_kmip_listener.go`
(mTLS config from configured CAs, listener reconcile on InitializeFunc gated
against DR-secondary/perf-standby, server cert minted per listener from the
named CA with SANs from server_hostnames/server_ips).
`logical_kmip_protocol.go` (request/response batch framing, operation dispatch:
Discover Versions 1.4, Query subset, Create AES 128/192/256, Get, Get
Attributes/Get Attribute List, Locate, Destroy, Activate, Rekey; result
status/reason semantics per OASIS sections 4, 6–7).
`logical_kmip_sign.go` (Sign operation backed by pass-A role-scoped
credentials; signing keys stored separately from credential metadata so lookup
never returns them while revocation removes both).
**Modified pre-existing files (small):** `logical_kmip.go` — factory help/help
text update, `listeners` field on the backend, credential write no longer warns
"no socket was opened"; `logical_kmip_certificates.go` — persist a
`signing-key` storage entry per credential (revocation cleanup path reuses the
existing recursive removal); `logical_kmip_test.go` — listener write now
expects no warning, registers `b.Cleanup` for the native listener.
**Deferred (kmip/NOTES.md):** KMIP 2.0 operation schemas, certificates/key-pair
objects, wrapping/alternate Get formats, batch dependency chains, async, custom
cipher suites (explicit error).
Acceptance: `go test ./internal/vault/kmip/` (TTLV round-trip/reject/fuzz) +
`go test ./internal/vault -run 'KMIP'` (native TLS e2e: dial listener with
generated client cert, Discover Versions/Create/Get/Destroy; Sign; concurrent
lifecycle; HTTP control plane) green; `compat/specs/kmip/*.yaml` 38/38 PASS
unchanged on a fresh dev server.

### Raft auto-snapshots (compat-harness branch)

**Status:** implemented. Specs first (`compat/specs/raft-autosnapshot/` — config
CRUD/list/status, 19 cases derived from Vault Enterprise docs v2.x latest),
implementation (`logical_system_raft_autosnapshot.go` + scheduler + tests +
`raft_autosnapshot_notes.md` contract notes).
**Modified pre-existing file:** `logical_system.go` — +1 line inside the
existing `GetRaftBackend()` block: `b.setupAutoSnapshots()` (starts the
snapshot worker; paths registered via the existing `raftStoragePaths()`).
**Semantics:** config ops require sudo, root-namespace only; config in barrier
storage; `interval` required; `retain` defaults 1; `file_prefix` defaults
`vault-snapshot`; only `storage_type: local` implemented (cloud types rejected
with invalid-request); files `<file_prefix>-<UTC-nanos>.snap`, mode 0600,
atomic rename; `local_max_space` eviction of oldest matching snapshots;
in-memory node-local status; worker skipped while sealed/standby/DR-secondary;
config changes cancel in-progress matching exports.
**Deferred:** cloud storage backends, autoload, snapshot-load recovery,
multi-process directory coordination (notes.md).
Acceptance: `go test ./internal/vault -run AutoSnapshot` (config CRUD,
scheduler producing snapshots in t.TempDir with interval + local_max_space
eviction, cancel-on-delete) green; `compat/specs/raft-autosnapshot/*.yaml`
19/19 PASS live on a raft-backed server (HCL config + init/unseal, not
dev-mode: dev-mode storage lacks the raft backend, so the paths are
FEATURE_ABSENT there — same artifact as autopilot-state).

### Namespaces (compat-namespaces branch)

Additive (`compat/`): `compat/specs/namespaces/` — 5 spec files (api-lock, crud,
isolation, naming, nested), 35 harness cases, all PASS against a dev server.
Harness module gained the `absent` expectation (dotted keys that must NOT be
present; missing ancestors count as absent) for isolation checks, plus
pre-existing-but-broken `runCase` call sites in `harness_test.go` fixed (the
harness module's tests never compiled after the signature grew; they are in a
separate go.mod so main-repo test runs never saw it).

Core seams (ledger rows above):

- `internal/http/handler.go` — sys/health removed from
  `restrictedSysAPIsNonLogical`. The Vault docs (namespace-api-lock) cite
  sys/health as an exempt path that responds from within a namespace; the old
  block returned 400 "operation unavailable in namespaces" for any request
  carrying a namespace header, including from locked namespaces.
- `internal/http/logical_test.go` — `TestLogical_NamespaceRestrictedAPIs`
  moved sys/health from the restricted list to a new exempt subtest asserting
  200 within a namespace (docs-win-over-test).

Key behaviors confirmed live (dev server, port 8400):

- Namespace CRUD per the docs sample shapes; single-segment create rule
  (400 "namespace name cannot contain /" for the `a/b` form); reserved/space
  naming rejections match the docs exactly.
- Parent-child routing: create child via `X-Vault-Namespace: ns1/`; absolute
  path-prefix routing (`/v1/ns1/sys/mounts`) equivalence.
- Isolation: mounts and policies mounted in a namespace do not appear in the
  root's sys/mounts LIST or sys/policy GET responses.
- api-lock: LOCK returns `unlock_key`; locked requests fail 503 with the
  documented error string; sys/health stays exempt while locked; sudo unlock
  works without the key.
- Namespace deletion is asynchronous (DELETE → 200
  `{"status":"in-progress"}`); a parent delete may transiently 400 until a
  child's async deletion completes (specs document and tolerate this).

### Raft snapshot-load (compat-harness branch)

New files (additive, port free): `internal/vault/logical_system_raft_snapshot_load.go`
(+ tests), `internal/vault/raft_snapshot_load_notes.md`, e2e coverage in
`internal/vault/external_tests/raft/snapshot_load_test.go`
(`TestRaft_SnapshotLoad`, `TestRaft_SnapshotLoad_CrossCluster` — raft test
cluster with an HTTP handler), harness `body_raw` extension, specs
`compat/specs/snapshot-load/{00-crud,10-autoload}.yaml` (9 cases, all PASS live
on a raft-backed server).

Surface (developer.hashicorp.com/vault/api-docs/system/storage/raftsnapshotload,
v2.x (latest)): POST `/sys/storage/raft/snapshot-load` (binary body,
acknowledgement response `{cluster_id, created_at, expires_at, snapshot_id,
status: "loading"}`), LIST (empty → 404 per the common Vault LIST convention;
non-empty → 200 `data.keys`), GET `/:snapshot_id` (`status: "ready"` when
usable; `auto_config_name`/`url` present for autoload-loaded snapshots),
DELETE `/:snapshot_id?force=` (accepted; nothing to force past while
recoveries are local-only). POST
`/sys/storage/raft/snapshot-auto/snapshot-load/:name` loads by URL from an
automated-snapshot configuration; documented sample response
`{auto_config_name, cluster_id, expires_at, snapshot_id, url, status: "ready"}`.

Semantics: the load builds an isolated barrier view from the snapshot's
ciphertext (unseals with the snapshot's own keyring), verifies same-cluster +
same-unseal-keys, and NEVER touches live data; one snapshot at a time; 72h
auto-unload; active-node change invalidates the view (`status` → `error`) and
requires unload/reload; root namespace only; gzip bounds validation before
extraction; 1 GiB upload cap; fetched-URL loads use the same pipeline
(HTTP(S) fetch, bounded like uploads).

Deviations/limits (documented in `raft_snapshot_load_notes.md`):

- The "recover, read, and list individual pieces of data" operations described
  on the snapshot-load docs page are not exposed in the API reference; only
  load/list/read/unload are specced. The isolated view is an internal
  approximation.
- mlock restriction is inherently satisfied: OpenBao dropped mlock entirely
  (configutil mlockMsg).
- `snapshot-auto/snapshot-load/:name` fetches by HTTP(S) URL; cloud-native URL
  schemes and storage-side credentials are deferred (cloud storage configs are
  rejected at creation time, so only the documented negative paths are
  reachable today: unknown config, local-storage prohibition, missing `url`).
- Restoring the snapshot into live storage remains the separate, documented
  `snapshot-force` surface; not reused here (docs say snapshot-load loads
  without overwriting).
