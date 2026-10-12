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
| `internal/builtin/logical/transit/path_sign_verify.go` | Add signature_context field and per-item forwarding; dispatch sign/verify through Ed25519 variant helpers | RFC 8032 Ed25519ctx/ph with base64 context validation, keeping derivation context separate | — |
| `internal/builtin/logical/transit/ed25519_variants.go`, `internal/builtin/logical/transit/ed25519_variants_test.go` (new) | Standard-library Ed25519ctx/ph signing and verification, policy version/deletion restrictions, derived keys, known-signature and batch tests | Landed transit conformance spec's Ed25519 variants only; CMAC/CBC and additional PQC API key types are not implemented by this patch | — |
| `internal/vault/core.go` | +3 registration lines: SAML/SCEP credential factories; OS logical factory with `vault-plugin-secrets-os` alias | Configuration-only auth methods and offline OS account storage, clean-room public docs | — |
| `internal/builtin/logical/pki/backend.go` | +1 path registration: `pathConfigSCEP()` | Disabled PKI SCEP configuration round trips; protocol enrollment explicitly unavailable | — |
| `internal/vault/logical_auth_os_test.go` (new) | SAML config/role validation and CRUD, SCEP role and PKI config round trips, OS host/account lifecycle and credential retention/reset/restore | Unit coverage for the clean-room auth/OS configuration subset, including fail-closed remote-operation requests | — |
| `internal/vault/logical_auth_saml_scep.go`, `internal/vault/logical_os.go`, `internal/builtin/logical/pki/path_config_scep.go` (new) | Mount-local validated configuration, role CRUD, offline account credential versions/reset/restore | Public SAML/SCEP/OS API configuration subset; no browser login, enrollment, SSH or scheduler execution | — |
| `internal/vault/core.go` | +1 factory registration: `logicalBackends["keymgmt"] = KeyMgmtBackendFactory` | Mount-local key management backend | — |
| `internal/vault/logical_system.go` | +1 registration: `b.Paths = append(b.Paths, b.managedKeyPaths()...)` | Managed-key registry configuration CRUD | — |
| `internal/vault/logical_keymgmt.go`, `internal/vault/logical_system_managed_keys.go` (new) | Local cryptographic key lifecycle, provider configuration, managed-key configuration validation and persistence | Clean-room public API compatibility; cloud/HSM operations and allowed-managed-key mount integration deferred, configuration writes warn explicitly | — |
| `internal/vault/logical_managed_keys_test.go` (new) | Registry validation/CRUD and key management lifecycle tests | Verify local persistence, rotation, private-material redaction and deletion protection | — |
| `internal/vault/logical_system_license_usage.go` (new) | Additive license/usage handlers with namespace checks, date/input validation and barrier-backed config | License-free status and documented response shapes; activity collection/export and KV/PKI/per-auth-lease measurement remain unavailable and are explicitly warned, not represented as measured utilization | — |
| `internal/vault/logical_system_license_usage_test.go` (new) | Endpoint, invalid-input, namespace and no-op/persistence tests | Exercise license-free semantics, empty activity representation and config atomic validation/preservation | — |
| `internal/vault/logical_system.go` | +1 line: `b.Paths = append(b.Paths, b.licenseUsagePaths()...)` | License-free status, utilization snapshot and internal-counter compatibility paths; existing entities path unchanged. Billing activity collection/export unavailable and explicitly warned; empty reports are not measured utilization | — |
| `internal/vault/logical_system.go` | +1 line: `b.Paths = append(b.Paths, b.rotationOrphanPaths()...)` | Root-only GET rotation/orphans (optional trailing slash); no LDAP/OS-account scheduler exists, so orphan list is empty | — |
| `internal/vault/logical_system_quotas.go` | group_by/secondary_rate field schemas, validation helper call, assignment before storage, readback fields | Identity quota configuration round-trip; request admission remains IP-based (entity and aggregate enforcement deferred) | — |
| `internal/vault/quotas/quotas_rate_limit.go` | Persisted GroupBy/SecondaryRate fields, clone copies, legacy GroupBy default | Preserve grouping configuration across persistence and manager copies without changing existing limiter behavior | — |
| `internal/vault/audit.go` | +3 lines: validateAuditFilterOptions under auditLock before backend creation | Validate filter/fallback/exclude and atomically enforce fallback uniqueness; existing mount options supply persistence/readback. Log filtering, fallback routing and exclusion execution deferred | — |
| `internal/vault/logical_system.go` | +1 line: `b.Paths = append(b.Paths, b.enterpriseConfigPaths()...)` | Registers group-policy-application and UI custom-message/default-auth configuration APIs; namespace-local barrier storage; group policy evaluation and UI consumption are separate integrations | — |
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
| `internal/vault/policy/policy.go` | Removed "missing controlled capabilities" parse error for a control_group factor without `controlled_capabilities` | Vault Enterprise control-group docs: `controlled_capabilities` is optional — when omitted the factor applies to every operation on the path; `validateControlGroup` already treats nil as always-applicable | — |
| `internal/vault/request_handling.go` | In the approved control-group deferred-unwrap path: `deferredReq.WrapInfo = nil` before re-execution; explicit `tokenStore.UseToken` consumption after the deferred request runs | Re-executing the stored request as-is re-wrapped the response (wrap-of-the-wrap) instead of returning the original data; the early return also bypassed the normal use-count decrement, leaving the wrapping token reusable after a successful unwrap (response-wrapping tokens are single-use) | — |
| `internal/helper/random/drbg.go` (new) | HMAC-mode Hash_DRBG per NIST SP 800-90A Rev 1 (SHA-256, 256-bit strength): instantiate/update/generate with post-generate no-data update | The documented drbg option of the random API ("seeds a cryptographically secure random generator with a seed from the chosen source") had no implementation | — |
| `internal/helper/random/random_api.go` | +`drbg` parameter (auto/hmacdrbg → seed from the chosen source, generate via HMAC-DRBG); caps split per docs: 10MB for platform/DRBG, 128KB for seal/all (was a global 128KB) | Documented Generate-random-bytes contract (api-docs/system/tools, v2.x (latest)); seal/all keep the pre-existing degradation to platform sampling with the seal warning | — |
| `internal/vault/logical_system_activation_flags.go` | +`activation-flags/secrets-import/activate` route; the read lists secrets-import alongside enable-scim (activated/unactivated); the activate operation dispatches on the request path | Documented Secrets import activation (docs/import — PUT /sys/activation-flags/secrets-import/activate; Beta feature) and the WriteActivationFlags API (:feature/activate) | — |
| `internal/vault/activation_flags.go` (new) | +core-level one-time activation-flag storage (ActivationFlagActive / ActivateActivationFlag) | Same as above; activation is one-way per the docs ("Once removed, you cannot un-activate gated features") | — |
| `internal/vault/logical_system.go` | password-policy create/update: `entropy_source` parameter ("", platform, seal) — seal rejected with 400 ("entropy_source \"seal\" requires entropy augmentation which is not available"); stored on the policy and echoed by read (omitted when empty, matching the docs read sample) | Documented `entropy_source` parameter of the password-policy API (api-docs/system/policies-password, v2.x (latest)); generation itself always uses the platform source on the fork (the only honorable source) | — |
| `internal/vault/logical_system_paths.go` | +`drbg` field on the `tools/random` path schema | Same as above (the field must exist in the schema for body-form delivery) | — |
| `internal/vault/logical_system_rekey.go` (new) | Token-authenticated system-backend handlers for rekey/init, rekey/update, rekey/verify (recovery=false) and rekey-recovery-key/init, rekey-recovery-key/update, rekey-recovery-key/verify (recovery=true), mirroring the http-package rekey handlers | The rekey endpoints were only routable through the unauthenticated listener special case (`DisableUnauthedRekeyEndpoints`); token-authenticated access returned 405 ("unsupported operation") and the documented rekey-recovery-key paths returned 404 ("unsupported path"). Vault routes these through the system backend | — |
| `internal/vault/logical_system_paths.go` | Callbacks wired onto the existing rekey/init, rekey/update, rekey/verify framework paths; +the rekey-recovery-key/init, /update, /verify paths with recovery=true | Same as above; the recovery endpoints return 400 "recovery rekeying not supported" on seals without recovery-key support (dev Shamir), per the docs' "only applicable to seals that support recovery keys" | — |
| `internal/vault/policy/policy.go` | +`mfa_requirements` block parsing in ACL path stanzas (`mfa_method_names`, `any_name_to_proceed`), splitting into any/all name lists at parse time; `MFARequirement` type carried into ACLPermissions and Clone | Vault v1.11+ policies use `mfa_requirements` blocks for step-up MFA; the fork rejected the key with "invalid key" and could not express step-up requirements in the documented syntax. The fork's `mfa_methods` attr form remains supported | — |
| `internal/vault/policy/acl.go` | ACLResults gains MFARequirements; permissions merge appends requirement lists; results expose them to the core | Same as above | — |
| `internal/vault/core.go` | Step-up enforcement branch: `any_name_to_proceed` requires one validated method from the list, otherwise all listed methods must validate; errors surface as 403 like the mfa_methods form | Same as above; root tokens bypass as before | — |
| `internal/vault/logical_system_billing.go` (new) | The documented /sys/billing surfaces as a license-free compatibility contract: GET/POST /sys/billing/config (retention 13-72, default 37, the documented increase warning verbatim, decrease silent), GET /sys/billing/overview (current-month zeroed report with the eleven documented usage metrics in the documented order and type lists), GET /sys/billing/certificates (per-month YYYY-MM counts with the documented not-found error shape) | The census flagged the billing family as not covered. OpenBao does not collect usage-based-licensing activity, so the reports are schema-shaped and honest rather than fabricated: zeros/empty with an explicit warning, matching the license-usage lane's established pattern. Root namespace only per the docs' restricted-endpoint notes | — |
| `compat/harness/validate.go` | Dotted paths in exact/contains/absent/capture now resolve numeric array indices; contains keys support a "[].field" projection for asserting one field across object-array entries | Billing month reports and other schema-rich arrays could not be asserted without array-index resolution | — |
| `internal/vault/quotas/quotas.go` | +`EntityID` on the quota Request; +`Manager.EntityGroupingRateQuotas()` flag | Documented identity-based rate-limit quotas (api-docs/system/rate-limit-quotas + guide): group_by entity_then_ip/entity_then_none bucket requests by entity | — |
| `internal/vault/quotas/quotas_rate_limit.go` | +entity-grouped admission: entity buckets take `rate`, IP (entity_then_ip) / shared-none (entity_then_none) buckets take `secondary_rate` (second limiter store created at initialize) | Same as above; group_by `none` puts all requests in one bucket at the primary rate | — |
| `internal/vault/core.go` | +`HasEntityGroupingRateQuota()` and `RateLimitEntityIDForToken()` helpers | Same as above; the entity is resolved from the request token only when an entity-grouped quota exists | — |
| `internal/http/util.go` | Resolve the request token's entity before applying a rate-limit quota when entity grouping is configured (namespace-injected context; getTokenFromReq's second return means Bearer-sourced, not token-found) | Same as above; unauthenticated/entity-less requests fall to the documented IP/none groupings | — |
| `internal/vault/identity/mfa.go` | +`ValidateMFASelfEnrollment` (pop+re-push pending under queue lock, namespace/entity binding) + `enable_self_enrollment` on config create/read | Self-enrollment semantics: enrollment must not consume the pending login; non-entity tokens rejected | — |
| `internal/vault/login_mfa.go` | +`enable_self_enrollment` persisted on login MFA TOTP method config (create/update/read) | Operator-visible knob enabling self-enrollment per method | — |
| `internal/vault/logical_system_raft.go` | `raftStoragePaths()` prepends `b.snapshotLoadPaths()` (return append pattern) | Registers `/sys/storage/raft/snapshot-load` (POST/LIST/GET/DELETE) + `/sys/storage/raft/snapshot-auto/snapshot-load/:name` when raft storage is in use | — |
| `internal/http/handler.go` | +1 route in `alwaysRedirectPaths`: `sys/storage/raft/snapshot-load` | Binary upload must not be forwarded from standbys (mirrors snapshot/snapshot-force semantics) | — |
| `internal/http/logical.go` | +1 condition in the raw-body pass-through: `path == "sys/storage/raft/snapshot-load"` | Snapshot uploads carry binary bodies; skip JSON parsing | — |
| `internal/http/util.go` | +1 path in `isSnapshotRequest`: `/v1/sys/storage/raft/snapshot-load` | Skip request-body buffering for binary snapshot uploads | — |
| `compat/harness/spec.go` | +`BodyRaw` field (base64) on `Request` | Binary (non-JSON) request bodies for upload cases; cannot survive YAML/JSON round trips | — |
| `compat/harness/main.go` | +`body_raw` handling: base64 decode, `Content-Type: application/octet-stream` | Same as above (harness execution) | — |
| `internal/builtin/logical/transit/path_cmac.go` (new), `sdk/helper/keysutil/aes_compat.go` (new) | CMAC (NIST SP 800-38B) and CBC+PKCS#7 (SP 800-38A) key types with encrypt/decrypt paths following the existing AES code paths | Vault-documented transit key types per landed spec | — |
| `sdk/helper/keysutil/policy.go`, `internal/builtin/logical/transit/path_keys.go`, `path_export.go`, `backend.go` | Vault-documented key-type spellings (`ml-dsa` + `parameter_set`, `hybrid` + algorithm fields) mapped into the existing keysutil model; existing spellings kept working | Conformance with Vault's documented transit API; KEY_TYPE_COMPATIBILITY.md documents the mapping | — |
| `internal/builtin/logical/pki/path_issuance_config.go` (new) | EST/CMP config paths, external-policy config, SCEP log-level config on the PKI backend | Vault-documented issuance-protocol configuration surface | — |
| `internal/builtin/logical/pki/path_export_keys.go` (new) | Export-key management paths (generate/list/get/delete export keys) | Vault-documented export-key management surface | — |
| `internal/builtin/logical/pki/path_roles.go` | `no_store_metadata` role parameter persisted and returned on role read/update | Vault-documented PKI role metadata-storage control | — |
| `internal/vault/core.go` | +1 line in `configureLogicalBackends`: `logicalBackends["pki-external-ca"] = PKIExternalCAFactory` (factory in `internal/vault/logical_pki_external_ca.go` — kept out of the pki package to avoid a test-import cycle with `internal/http`) | Mount-type registration for the documented external-CA engine | — |
| `internal/helper/builtinplugins/registry.go` | +9 lines: ldap/aws/azure/gcp credential + logical factory registrations | Mount types for the documented LDAP/cloud engines (OpenBao ships these upstream as external plugins; config-only implementations in-tree) | — |
| `internal/vault/identity/store.go`, `internal/vault/identity/store_oidc.go` | +OIDC workload path registrations in the identity store path builders | Plugin-token and secrets-sync discovery/JWKS endpoints per landed spec | — |
| `internal/builtin/credential/ldap/backend.go` | static-migration empty-status returns an empty response instead of nil (nil renders as HTTP 404 on reads) | Conformance: documented empty migration status is 200/204 | — |
| `internal/builtin/logical/database/path_config_connection.go`, `path_roles.go` | rootless-rotation connection fields + static-role password/skip-import-rotation fields | Vault-documented database rotation config surface | — |
| `internal/vault/rekey.go`, `internal/vault/seal.go`, `internal/http/sys_rekey.go` | Invalid rekey/recovery-rekey configuration now returns 400 (was 500); `SealConfig.InitializedAt` (in-memory, JSON-omitted); `RekeyCancel(recovery, nonce)` enforces the documented ten-minute cancellation rule; the DELETE init handler parses the nonce from the request body | Public `/sys/rekey-recovery-key` + `/sys/rekey` API contract: 400 for invalid input per the documented status-code conventions, and "If the rekey was initialized within the last 10 minutes, you must provide the nonce to cancel the operation" (api-docs/system/rekey-recovery-key, v2.x latest) | — |
| `sdk/logical/event.proto`, `event.pb.go`, `events.go` (new), `sdk/framework/events.go` (new), `internal/vault/events.go`, `eventfilter.go`, `events_lease.go` (new), `internal/vault/routing/events.go` (new), `internal/http/events.go` (new), `internal/vault/expiration.go`, `internal/builtin/logical/kv/events.go` (new) + emission hooks in 7 kv files, `internal/vault/policy/policy.go`, `policy/acl.go`, `internal/http/handler.go` | Event notification system: `EventReceived` CloudEvents envelope; `/sys/events/subscribe/{eventType}` WebSocket (GET; `json=true`, `filter`, `namespaces` params); policy model gains `subscribe` capability + `subscribe_event_types` path rule; event bus fans out to subscribers with fresh per-delivery policy checks; documented filter grammar (recursive-descent, bounded); lease issued/renewed/revoked/expired and kv-v1/kv-v2 mutations emit events; JSON delivery via protojson snake_case, default delivery is protobuf binary | Vault-documented events system: concepts/events, commands/events, concepts/filtering, plugins/plugin-development-event-notifications (GA since 1.16; CloudEvents envelope with `datacontentype` typo preserved; `path` = invoked API path, `data_path` = fetchable path; read capability on subscribe path + list+subscribe on secret path with subscribe_event_types) | — |

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


### Control groups (compat-control-group branch)

Additive (`compat/`): `compat/specs/control-group/` — adds `05-config-shapes.yaml`
(live-verified readback shapes: max_ttl under `data`, Go duration formatting
"4h0m0s" vs the docs sample's "4h"; post-delete default "0s") and
`10-control-group-flow.yaml` (20-case full flow: policy with control_group
factor, wrap of a controlled request, status/authorize round trip, self-auth
denial, non-member no-op, group-member approval, approved unwrap returning the
original read data, post-unwrap single-use rejection, accessor validation).
Harness gained named `capture`/`use_captured_token` (body strings starting
with `$` substitute from captured slots; token is the default slot). The
pre-existing `00-config.yaml`/`10-request-validation.yaml` (config CRUD +
missing-accessor validation) remain as-is.

Core seams (ledger rows above):

- `policy/policy.go`: a control_group factor without `controlled_capabilities`
  no longer fails policy parsing — the docs make the field optional (factor
  applies to all operations).
- `request_handling.go` (approved deferred unwrap): strips the stored
  request's WrapInfo before re-execution (the wrap-of-the-wrap bug: unwrap
  returned a NEW wrapping token instead of the original data) and consumes the
  wrapping token's use count explicitly after the deferred request runs (the
  early return bypassed `UseToken`, leaving the token reusable).
- Confirmed live behaviors behind the specs: wrap TTL becomes the control
  group's policy TTL (14400 observed) rather than the requested 120;
  `request_data` is null for a wrapped GET; a pending unwrap attempt returns
  400 WITHOUT consuming the wrapping token (status/authorize retries safe);
  the token owner is rejected as approver ("token owner cannot be approver",
  plain 500 — status not documented); a non-group-member authorize is a
  200 no-op (approved stays false).

### Entropy augmentation: random API drbg + documented caps (compat-control-group branch)

Additive (`compat/`): `compat/specs/entropy/00-tools-random.yaml` — 20 cases
covering the documented Generate-random-bytes surface: URL and body byte
counts, hex/base64 formats, `drbg=auto`/`hmacdrbg` (200 with correct
shape/length), platform URL form, seal/all degradation to platform sampling,
the 128KB seal cap (131072 ok / 131073 rejected) and 10MB platform cap
(10485761 rejected), bytes<1, invalid source (URL form 400 with the
documented-style error; body form inert due to the framework's
path-capture override — documented in notes), invalid drbg and format.

Core seams (ledger rows above):

- `internal/helper/random/drbg.go`: HMAC-mode Hash_DRBG (NIST SP 800-90A
  Rev 1, SHA-256) — the generator behind the documented drbg option.
- `internal/helper/random/random_api.go`: drbg parameter wiring + documented
  caps split (10MB platform/DRBG vs 128KB seal/all); the seal warning and
  the "all has no warning" semantics are preserved exactly (the sibling's
  transit random specs assert them).
- `internal/vault/logical_system.go` / `logical_system_paths.go`: the documented
  password-policy `entropy_source` parameter ("", platform, seal) with an
  explicit 400 refusal for seal (entropy augmentation needs an HSM-backed
  seal); specs/entropy/10-password-policies.yaml (8 cases) covers default
  omission, platform echo, seal/invalid rejection and generation.
- Billing surfaces (compat-control-group branch): the documented
  /sys/billing/{config,overview,certificates} routes are implemented as
  honest zero/empty compatibility reports with the documented schemas,
  retention warning contract and root-namespace restriction
  (specs/billing/00-billing.yaml, 21 cases). The harness now resolves
  array indices in dotted assertions and projects contains keys through
  "[].field".
- Step-up MFA mfa_requirements (compat-control-group branch): ACL policies
  now accept the documented mfa_requirements block (any/all semantics),
  propagate through the ACL into the core, and enforce with 403 on unmet
  requirements. specs/mfa/mfa-requirements-enforcement.yaml (22 cases)
  covers policy acceptance/echo, all/any enforcement denials, the
  passcode/enrollment/credential-slot error contracts, and cleanup. The
  positive passcode path needs an enrolled entity plus a live TOTP code the
  harness cannot generate; left to operator verification.
- Recovery-key rekey (compat-control-group branch): the documented
  rekey-recovery-key API was unroutable (404) and the barrier rekey 405'd
  with a token — both now route through the system backend with the
  documented contracts. specs/rekey/00-recovery-and-barrier.yaml (18 cases)
  covers the recovery seal-gating, the init/read/cancel cycle, verification
  status, key-format validation and the invalid-config error contracts. A
  full barrier rekey ceremony requires the current barrier key (the
  harness does not hold it) and is left to operator verification. Also:
  namespaces identity isolation is verified — entities/groups created with
  X-Vault-Namespace are invisible at the root and vice versa
  (specs/namespaces/20-identity-isolation.yaml, 10 cases); the harness now
  substitutes captured values in request paths, not just bodies.
- Secrets import activation flag (compat-control-group branch): the
  documented one-time activation endpoint is now implemented alongside the
  existing enable-scim flag; specs/secrets-import/00-activation.yaml (5
  cases) covers the read lists, activation, one-way semantics and unknown
  feature 404.
- Identity-based rate-limit quotas (compat-control-group branch): the
  configuration surface was already implemented (fields + validation +
  readback); this lane implemented the ENFORCEMENT — requests carrying an
  entity bucket by entity ID at `rate`; entity-less requests bucket by IP
  (entity_then_ip) or share a single bucket (entity_then_none) at
  `secondary_rate`. specs/quotas/rate-limit-identity.yaml (29 cases) covers
  validation, readback, defaults and live 429 enforcement. Pitfall found:
  tokenStore.Lookup requires a namespace in the context — the quota handler
  resolves the namespace before applying quotas, so the lookup reuses that
  context.
  (the transit docs do not document drbg; transit gets it via the shared
  helper but no schema field → inert).
- Entropy augmentation's config-file stanza (entropy "seal") is a server
  configuration surface, not an API surface — nothing to port beyond the
  random API behavior.
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

## CIEPS — Certificate Issuance External Policy Service (2026-10-12)

Implements the documented CIEPS webhook contract
(https://developer.hashicorp.com/vault/docs/secrets/pki/cieps, v2.x latest):

- `internal/builtin/logical/pki/cieps.go`: request/response structures
  (request_version 1, synchronous, user/identity/vault request key values),
  TLS client from the configured trust bundle (CA chain or pinned leaf) or
  client certificates, request_uuid echo validation, and the re-signing
  machinery: the service's certificate signature is ignored; the TBS is
  re-marshaled with the issuing issuer's AIA/CRL-DP URLs, Authority Key
  Identifier (RFC 5280) and Issuer DN, and the TBS's inner signature
  AlgorithmIdentifier is rewritten to the issuer's (RFC 5280 requires inner
  == outer). Signature algorithms are derived byte-exactly from throwaway
  certificates (cached) including PSS/ML-DSA; TBS signing uses
  crypto.SignMessage where available.
- `internal/builtin/logical/pki/path_extpolicy_issue_sign.go`: the six
  documented paths `pki/external-policy/{sign,issue,sign-intermediate}`
  (+ `pki/issuer/:issuer_ref/external-policy/...` variants). Issue mode
  generates key material and builds the CSR on the user's behalf
  (`vault_generated_private_key=true` documented); user parameters are
  forwarded verbatim in `user_request_key_values`; the documented
  `vault_request_key_values` fields are assembled (issuance_mode, mount,
  policy_name, requested_issuer_*, requested_issuance_config,
  vault_is_performance_*). Responses follow the documented semantics: only
  one of error/certificate (both -> error becomes a warning), non-200
  surfaces only the status code, issuer_ref override re-resolves the
  issuer, store_certificate + generate_lease (lease requires store) are
  honored. Response shape is the standard PEM certutil bundle by default.
- `internal/builtin/logical/pki/path_issuance_config.go`:
  `pki/config/external-policy` CRUD — enabled (disabling clears the stored
  URL), HTTPS-only URL when enabled, `trusted_ca` / trusted leaf bundle
  validation, timeout/entity_jmespath/group_jmespath,
  external_service_last_updated timestamping, validated flag.
- `compat/harness/ciepsmock/`: stand-alone TLS mock implementing the
  documented contract (signing CA generated at startup since x509 requires
  parent/key agreement even when Vault ignores the signature), with
  error/both/nonjson/mismatch/status/store/lease modes and a status
  endpoint for request verification.
- Spec `compat/specs/pki-cieps/` (15 cases, all PASS) + notes.md with the
  live-verified mock-mode matrix (error-only 400 verbatim message, both ->,
  non-JSON, UUID mismatch, non-200 status-only, store+lease, disabled
  service 400) and openssl-verified re-signing semantics.

Deviations/limits (documented in `compat/specs/pki-cieps/notes.md`):

- Identity request key values carry entity_id only; the full resolved
  logical.Entity/groups with jmespath projection is deferred (needs the
  identity store wiring).
- ACME-backed CIEPS flows are out of scope of the spec (ACME directory
  variants are covered by pki-transit-ent); the ica issuance_mode path
  shares the re-signing machinery.
- The mock cannot be started/stopped by the harness (manual provisioning
  documented); mock-mode cases therefore live in notes.md rather than the
  auto-run suite.
- encoding/asn1 marshaling honors a set RawContent field verbatim — the
  re-signing code clears the TBS RawContent before re-marshaling so
  mutations (AIA/AKI/Issuer/inner signature algorithm) take effect.

## Snapshot recovery of individual secrets (2026-10-12)

Implements the documented Enterprise "recover a secret from a loaded snapshot"
flow (`https://developer.hashicorp.com/vault/docs/sysadmin/snapshots/recover-a-secret/single-cluster`,
Enterprise-only on upstream) as an API-compatible clean-room surface on OpenBao.

Surface (documented by the recovery guide; sources cited inline):

- `RECOVER` HTTP method (and PUT/POST alias with the same headers) on any
  secret path, gated by the `X-Vault-Recover-Snapshot-Id` request header.
  `X-Vault-Recover-Source-Path` recovers to a different path on the SAME
  mount. `internal/http/logical.go` maps both to `logical.RecoverOperation`.
- New `recover` ACL capability (`internal/vault/policy/policy.go`,
  `internal/vault/policy/acl.go`) — its own capability bit, not a reuse of
  update; `AllowOperation` maps RecoverOperation to it.
- Recovery engine `internal/vault/logical_recover.go`:
  - reads snapshot id + source path from request headers (the core derives
    the request context from `activeContext`, so http-level context values
    do not flow — headers are the transport),
  - reads the SNAPSHOT's mount table from the isolated loaded-snapshot view
    (`core/mounts/` + `core/local-mounts/`) via the load service registered
    on the core (`Core.loadedSnapshotService`),
  - longest-prefix mount match; cubbyhole uses a recursive per-token
    scan with a tiebreaker preferring the caller's own CubbyholeID segment
    (mirroring `router` salting semantics),
  - same-mount constraint, plugin gates (kv v1/cubbyhole/generic only;
    ssh and databases documented for later upstream versions are NOT
    implemented — surfaced as 500 per the version gate),
  - write-back routes a synthetic UpdateOperation (with the caller's
    TokenEntry — the cubbyhole routeCommon requires it) through
    `doRoutingOrRecover` intercept in `request_handling.go`.
- Restrictions honored: no loaded snapshot -> 500; snapshot id mismatch ->
  500; non-root namespace -> rejected; disabled mounts rejected; kv v2 ->
  500 (only kv v1 documented); the load/unload paths remain root-namespace
  only (existing snapshot-load service).

Spec `compat/specs/secret-recovery/00-recover.yaml` — 32 cases, all PASS
against a live raft server (kv v1 write->snapshot->delete->RECOVER->verify,
recover-to-different-path via Source-Path header, cubbyhole per-token
recovery, and the full error contract: no-header 400, wrong snapshot id,
source-not-in-snapshot, kv2 rejected, ssh not-implemented, cross-mount,
unload + recover-without-snapshot). Harness: `capture_raw` (binary snapshot
export), request-header capture substitution, `sleep_ms`, and transitive
dependency skipping (FAIL/ERROR/FEATURE_ABSENT/SKIP all propagate) so the
family degrades to SKIP on non-raft targets instead of FAIL.

Deviations/limits (documented in the spec family notes):
- ssh (/config/ca) and databases static-role/static-cred recovery are
  documented for upstream 1.20.3/1.20.4 — deliberately NOT implemented here;
  they surface the documented version gate as a 500.
- The recovery view is bounded to the currently loaded snapshot (the
  documented 72h auto-unload and single-snapshot load rules come from the
  existing load service).

## Internal UI delivery views: custom messages + default login auth (2026-10-12)

Public docs (developer.hashicorp.com, v2.x latest):
- `GET /sys/internal/ui/authenticated-messages` and
  `.../unauthenticated-messages` (Enterprise-gated feature docs, EE 1.16.0+
  for creation): list the messages a UI client shows after/before login.
  Envelope: `data.keys` (uuid array) + `data.key_info` (map keyed by uuid →
  title/message/type/authenticated/start_time RFC3339Nano/end_time (null
  allowed)/options/link). Namespace semantics: messages active in the
  request namespace plus all ancestral namespaces up to root.
- `GET|LIST /sys/internal/ui/default-auth-methods` (unrestricted, no auth):
  returns `data.{default_auth_type, backup_auth_types,
  disable_inheritance}` for the `X-Vault-Namespace`-derived namespace,
  inheriting from ancestors when unset; `disable_inheritance` on an ancestor
  stops the inheritance walk at that ancestor.

Implementation (new files only; wire-in appends existing path groups):
- `internal/vault/logical_system_internal_ui.go` (new): three delivery
  endpoints backed by the existing config CRUD structs
  (`uiCustomMessage`, `uiDefaultAuth` in
  `logical_system_enterprise_config.go`):
  - active-window filtering (`active` computed from start/end time; entries
    with a non-null end_time in the past or a future start_time are not
    delivered),
  - authenticated vs unauthenticated split driven by the message's own
    `authenticated` flag, independent of the request's auth state,
  - namespace ancestry: the request namespace is resolved via
    `c.NamespaceStore.GetNamespaceByPath`, then ancestor views are walked
    root-ward with `NamespaceScopedView` (nearest config wins for default
    auth; all ancestors' messages are delivered; `disable_inheritance` on
    an ancestor stops the default-auth inheritance walk at that ancestor),
  - GET returns the resolved shape; LIST is registered for the endpoint
    surface (returns the same data).
- `internal/vault/logical_system.go`: appended `b.internalUIPaths()` and
  added the three paths to `PathsSpecial.Unauthenticated` (default-auth is
  documented as reachable without auth; the message endpoints are also
  unauthenticated in the fork — delivery-before-login requires it).
- `internal/vault/logical_system_enterprise_config.go`: POST on a named
  custom-message id that does not exist yet now creates it (upsert),
  matching the documented route table (`POST /sys/config/ui/custom-messages/:id`).

Spec `compat/specs/enterprise-config/03-ui-delivery.yaml` — 21 cases
covering: pre-existing cleanup, create authenticated + unauthenticated
messages, delivery split with/without token, active-window filtering
(future start / past end not delivered), create-batch (LIST collection),
default-auth CRUD, unrestricted access (no token), root resolution, child
inherits root, explicit parent config wins, grandchild skips a
disabled-inheritance parent, namespace ancestral messages visible from
child/grandchild contexts, final cleanup. 54/54 PASS on dev and on the raft
server, idempotent across reruns (async namespace deletion tolerated with
400 + sleep_ms waits).

Harness: Expect-section capture substitution (`substituteExpect`) for
exact/contains/schema/absent values, including dotted keys with embedded
`$slot` segments (per-segment substitution in `subKey`).

## DR operation-token ceremony and secondary maintenance (2026-10-12)

Public doc (developer.hashicorp.com/vault/api-docs/system/replication/replication-dr,
v2.x latest): five DR-secondary routes — GET/POST/DELETE
`sys/replication/dr/secondary/generate-operation-token/attempt`, POST
`.../generate-operation-token/update`, POST `.../operation-token/delete`,
POST `.../reindex`, POST `.../merkle-check`. All are restricted endpoints
(root namespace) and conditionally unauthenticated only when HCL
`enable_unauthenticated_access` includes `generate-operation-token` (this
fork does not implement that opt-in, so the routes require authentication —
matching the default posture and the spec's no-auth 403 probes).

Implementation:
- `internal/vault/dr_operation_token.go` (new): runtime-only ceremony state
  (attempt nonce, required threshold, collected shares, OTP/PGP wrap, live
  issued-token set) with XOR-pad OTP encoding (24-char pad, per the doc
  sample's `otp_length: 24`) and PGP-wrapping via the shared
  `pgpkeys.EncryptShares` helper. Share validation mirrors
  `/sys/rekey/update`: hex-or-base64 decode, barrier key length bounds
  including `shamir.ShareOverhead`; completion via `shamir.Combine`
  (single share passes through for threshold 1). Tokens are 32 random
  bytes; issued tokens are tracked in memory and revoked explicitly.
- `internal/vault/logical_system_replication_dr.go` (new): the five paths,
  registered after the secondary-lifecycle paths in `replicationPaths()`.
  Root-namespace guard mirrors the snapshot-load convention; missing
  `dr_operation_token`/`key`/`nonce` → 400 before any state access;
  unknown operation tokens → 403; reindex recomputes the merkle root and
  merkle-check delegates to the shared corruption-report implementation.
  Deviations: the fork has no real DR streaming, so the ceremony runs on
  any node (the docs describe DR-secondary nodes); issued tokens are not
  persisted (a restart clears them).

Spec `compat/specs/dr-ops/00-operation-token.yaml` — 14 cases: read-shape
(wrapped in the documented `data` envelope), invalid-PGP 400, cancel,
missing-key/nonce update rejections, operation-token-delete/reindex/
merkle-check missing-token 400s, five unauthenticated 403 probes.
14/14 PASS on dev and on the raft server.

Live ceremony verification (not spec-asserted, per the notes' scope):
- dev (threshold 1): POST attempt → nonce+OTP; POST update with the dev
  unseal key → complete=true, encoded_token; OTP-XOR decode yields the
  operation token; reindex 200; merkle-check 200 (corrupted_root: false);
  wrong token → 403; revoke → 204; revoked token → 403.
- raft (threshold 3, 5 shares): three shares → progress 1/2/3, complete at
  3 (shamir.Combine exercised); token authorized for merkle-check + reindex;
  revoke → 204; revocation re-check → 403.

## PKI certificate metadata, batch certs, CA-key export/import, issuer check flags (2026-10-12)

Public doc (developer.hashicorp.com/vault/api-docs/secret/pki, v2.x latest):
issue/sign `cert_metadata` parameter (base64 value; the role's
`no_store_metadata` must be false), GET/LIST `/pki/cert-metadata` ("Read
Certificate Metadata" / "List Certificate Metadata"), POST `/pki/batch/certs`
("Read Batch Certificate"), POST `/pki/keys/:key_ref/export` ("Export CA
key") with the wrapped-key + `export_key_hmac` import pair on POST
`/pki/keys/import`, and the issuer fields `disable_critical_extension_checks`,
`disable_path_length_checks`, `disable_name_checks`,
`disable_name_constraint_checks` (RFC 5280 chain-of-trust relaxations).

Implementation:
- `internal/builtin/logical/pki/path_cert_metadata.go` (new): metadata
  entries under the private `certs-metadata/<hyphen-serial>` prefix (kept
  out of `certs/` so LIST /pki/cert is not polluted); GET returns
  `{issuer_id, expiration, cert_metadata, role, serial_number}` (colon-form
  serial, RFC3339Nano expiration), LIST returns denormalized serials,
  POST `/pki/batch/certs` returns `{certificates: {<serial>: PEM|null}}`.
  `cert_metadata` added to `addNonCACommonFields` + `getCELIssueSignFields`
  so every issue/sign/sign-verbatim/issuer-sign/CEL schema accepts it;
  stored at issue/sign time when non-empty (400 on invalid base64 or on a
  role with `no_store_metadata: true`).
- `internal/builtin/logical/pki/path_keys_export.go` (new): POST
  `/pki/keys/:key_ref/export` — wraps the CA private key to a
  caller-supplied public key (rsa-2048/3072/4096 via RSA-OAEP-SHA256; EC
  P-256/384/521 via ephemeral ECDH-ES + HKDF-SHA256; AES-256-GCM payload).
  Returns `{ca_key_uuid, wrapped_key, export_key_hmac, exported_at}`.
  `export_key_hmac` is deterministic on both mounts
  (`sha256:<hex of the recipient public key DER>`). Requires root/sudo.
  Managed (external) keys → 400. ml-kem-768/1024 recipients documented
  upstream are not implemented (400, noted deviation). The wrapped blob
  imports via POST `/pki/keys/import` (`wrapped_key` + `export_key_hmac`,
  mutually exclusive with `pem_bundle`): the import path in
  `path_manage_keys.go` unwraps (matched by the export-key HMAC
  fingerprint) and re-enters the normal PEM import flow, so the key can be
  named and stored like any imported key.
- Issuer check flags: `issuerEntry` gains the four booleans;
  `buildPathIssuer` fields + `pathUpdateIssuer` writes + `pathGetIssuer`
  read output; the update handler preserves `issuer_name` when omitted
  (fixes a fork bug where any PUT without issuer_name cleared the name,
  breaking by-name reference resolution afterward — flags can only be
  exercised by-name again after this fix).
- Deviations: the four check flags are stored/served but the fork performs
  no RFC 5280 chain validation to relax, so issuance-with-violation
  enforcement is not observable end-to-end; the wrapping envelope is a
  clean-room self-consistent format (the doc sample's HMAC value is a
  placeholder, so no cross-mount wire blob interop with real Enterprise is
  asserted); tidy does not remove metadata entries of deleted certificates
  (`tidy_cert_metadata` counter is a documented deviation).

Specs (all PASS on dev and on the raft server):
- `compat/specs/pki-cert-metadata/00-cert-metadata.yaml` — 19 cases:
  issue/sign with metadata, read (exact metadata/role + schema), LIST,
  missing serial 404, batch-certs found/missing/empty, no_store_metadata
  rejection, issuance without metadata allowed on that role, invalid base64
  rejection.
- `compat/specs/pki-issuer-check-flags/00-issuer-check-flags.yaml` — 11
  cases: default flags false, set-all/persist/clear via by-ID and by-name
  issuer reads, issuance still works after a flag cycle.
- `compat/specs/pki-ca-key-migration/00-migration.yaml` — 19 cases: full
  round-trip (create export key on dest → export default CA key on src →
  import wrapped on dest with key_name → LIST keys shows the imported key
  name), plus negative coverage: missing key ref 400, missing/invalid
  public key 400, unsupported recipient 400, pem+wrapped mutual exclusion,
  wrapped-without-hmac, wrong hmac, corrupt blob.
