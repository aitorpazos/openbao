# Redundancy zones — clean-room compatibility notes

## Evidence and scope

Read `compat/README.md` first. All product evidence below is from public developer.hashicorp.com documentation; no Vault source, binaries, or Git commands were used. Citation IDs resolve to both the exact URL and the displayed version label. Version strings inside sample JSON are example server versions, **not** the documentation version.

| ID | Public documentation URL | Displayed version |
|---|---|---|
| RZ | https://developer.hashicorp.com/vault/docs/enterprise/redundancy-zones | v2.x (latest) |
| RAFT | https://developer.hashicorp.com/vault/docs/configuration/storage/raft | v2.x (latest) |
| AUTO | https://developer.hashicorp.com/vault/api-docs/system/storage/raftautopilot | v2.x (latest) |
| HA | https://developer.hashicorp.com/vault/api-docs/system/ha-status | v2.x (latest) |
| LEADER | https://developer.hashicorp.com/vault/api-docs/system/leader | v2.x (latest) |
| SEAL | https://developer.hashicorp.com/vault/api-docs/system/seal-status | v2.x (latest) |
| CONFIG | https://developer.hashicorp.com/vault/api-docs/system/config-state | v2.x (latest) |
| PEERS | https://developer.hashicorp.com/vault/api-docs/system/storage/raft | v2.x (latest) |
| PERF | https://developer.hashicorp.com/vault/docs/enterprise/performance-standby | v2.x (latest) |
| REPL | https://developer.hashicorp.com/vault/docs/enterprise/replication | v2.x (latest) |
| REPLAPI | https://developer.hashicorp.com/vault/api-docs/system/replication | v2.x (latest) |
| CLI | https://developer.hashicorp.com/vault/docs/commands/operator/raft | v2.x (latest) |

The requested https://developer.hashicorp.com/vault/api-docs/system/state returned HTTP 404, with **no displayed version label**. This is evidence of a missing documentation page, not evidence that a live `/sys/state` API returns 404. The similarly named documented endpoints are `/sys/config/state/sanitized` [CONFIG] and `/sys/storage/raft/autopilot/state` [AUTO]; do not conflate them.

Discovery also fetched the main bodies of 86 system API pages linked in the Autopilot page's expanded system sidebar. The only `redundancy` matches in that bounded scan were HA and AUTO. REPLAPI was separately followed from REPL and had no redundancy matches. This is not a claim to have exhaustively searched every nested API page or every historical version.

## Definition, tagging, and failover

- Redundancy zones are an Enterprise facility for placing voting and non-voting nodes together per availability zone, providing read scaling and resiliency. Autopilot attempts to maintain exactly one voting node per zone and demotes extras to non-voters; non-voters can serve reads but cannot participate in elections. [RZ]
- The operator labels each node through `autopilot_redundancy_zone` in the server's `storage "raft"` configuration stanza. It is an Enterprise string parameter with default `""`; the label is chosen by the operator. These docs do not specify a zone-assignment API, an automatic cloud-zone lookup, a wire-level Raft metadata encoding, or live-reload guarantees. Do not invent any of those. [RZ, RAFT]
- When a zone voter fails, a non-voter in that zone can be promoted. When an entire zone is lost, the introductory example describes promoting a non-voter in a surviving zone. **Both are subject to continued quorum:** the same page explicitly says Autopilot cannot agree on the promotion configuration change after a majority of voters is lost. Zones do not increase ordinary quorum failure tolerance; they increase *optimistic* tolerance of gradual failures with intervening promotions. [RZ]
- The page's two-zone/two-nodes-per-zone example loses quorum when either zone's voter fails. Its three-zone/two-nodes-per-zone example promotes the failed voter's zone standby, leaving three voters and two standbys, and says three additional gradual failures are possible before quorum is lost. These are documented examples, not formulas implemented by these specs. [RZ]
- With automated upgrades, Autopilot waits to transfer leadership until the new version has as much redundancy as the old version, avoiding movement from a healthier to a less healthy state. No exact failover latency is promised here. [RZ]

## Performance standbys and replication are distinct dimensions

Performance standby describes request handling: read-only operations execute locally; requests detecting a storage write are forwarded to the active node. `disable_performance_standby` disables this mode and should be consistent across nodes. Redundancy zones describe Raft voting/promotion placement. Do not equate `performance_standby` with `zone-standby`, or infer zone membership from a standby flag. This distinction is a synthesis of the separately documented mechanisms, not an undocumented mapping between roles. [PERF, RZ, AUTO]

Performance/DR replication operates **between clusters**, each containing an active node and HA nodes. Performance secondaries serve clients; DR secondaries do not serve ordinary reads/writes until promoted. The replication documentation also explicitly classifies Integrated Storage Autopilot configuration as an ignored/non-replicated storage entry, allowing DR secondaries to differ. Redundancy-zone voter promotion is not DR-secondary promotion. [REPL]

Permanent non-voters are separately documented: `retry_join_as_non_voter` configures a permanent non-voter, whereas the Autopilot `zone-standby` node type denotes a non-voter that can be promoted. The join API accepts `non_voter` (boolean, default false), but documents no redundancy-zone assignment parameter. [RAFT, AUTO, PEERS]

## Operator-visible API inventory

### `GET /sys/ha-status`

The endpoint lists the active node and peers heard from since it became active. The curl sample supplies `X-Vault-Token`. The response sample is a top-level, **capitalized `Nodes` array**, not `nodes` and not `data.Nodes`. All three entries, including the active node, have `"redundancy_zone": "a"`. The page explicitly identifies `redundancy_zone`, `upgrade_version`, and `replication_primary_canary_age_ms` as Enterprise-only. No zone request parameter is listed. [HA]

The full example node key set is `active_node`, `api_address`, `clock_skew_ms`, `cluster_address`, `echo_duration_ms`, `hostname`, `last_echo`, `replication_primary_canary_age_ms`, `version`, `upgrade_version`, `redundancy_zone`. The sample has version/upgrade version `1.17.0`; that does not change its displayed documentation label. [HA]

### `GET /sys/storage/raft/autopilot/state`

Root-namespace restricted, Integrated Storage management API; sample curl supplies `X-Vault-Token`. The samples show top-level response objects, not a `data` envelope. The Enterprise sample demonstrates the following additions: [AUTO]

- `optimistic_failure_tolerance`: integer, example `3`; prose defines it as healthy active and backup voting servers that can gradually fail without an outage.
- `redundancy_zones`: object keyed by zone name. `a` has `servers: [vault_1, vault_2, vault_5]`, `voters: [vault_1]`, `failure_tolerance: 2`; `b` has `servers: [vault_3, vault_4]`, `voters: [vault_3]`, `failure_tolerance: 1`.
- `upgrade_info.redundancy_zones`: per-zone upgrade groups. Example `a` contains `target_version_non_voters`, `other_version_voters`, `other_version_non_voters`; `b` contains only the latter two. Do not require every possible upgrade group on every zone. The enclosing example has `status: "await-new-voters"`, `target_version: "1.17.5"`, and cluster-wide version-group arrays.

The general sample includes `servers.<node-id>.node_type`. Prose documents Enterprise values `voter`, `read-replica`, `zone-voter`, `zone-extra-voter`, `zone-standby`; the last is explicitly promotable. `status` is a different field (`voter`, `leader`, `non-voter`). Importantly, the Enterprise-specific JSON sample **does not include a `servers` object**, nor does either sample demonstrate a per-server `redundancy_zone` property in this endpoint. Do not transplant HA's node property here. CLI examples corroborate the zone membership and upgrade grouping. [AUTO, CLI]

`GET` and `POST /sys/storage/raft/autopilot/configuration` are documented, but their listed fields are cleanup/health/quorum/stabilization settings and Enterprise `disable_upgrade_migration`; no zone-label parameter is listed. These runtime Autopilot configuration settings are explicitly distinct from server configuration-file settings. [AUTO]

### Requested negative probes and related APIs

- `/sys/leader`: sample contains `ha_enabled`, `is_self`, `active_time`, leader addresses, `performance_standby`, `performance_standby_last_remote_wal`, `last_wal`, `raft_committed_index`, `raft_applied_index`; **no redundancy-zone field** or zone parameter is documented. [LEADER]
- `/sys/seal-status`: sealed and unsealed samples include seal/progress/version/storage fields; the unsealed example also includes cluster ID/name. **Neither sample documents a zone field**. The endpoint is explicitly unauthenticated. [SEAL]
- `/sys/state`: documentation probe 404 as noted above; no version-labelled field contract can be derived from it.
- `/sys/config/state/sanitized`: configuration excludes potentially sensitive fields including a subset of `Storage.Config` and `HAStorage.Config`. Its sample `storage` object contains cluster/redirect addresses, disable-clustering, and `type: "inmem"`, not `autopilot_redundancy_zone`. Do not infer that the config-file key must appear in sanitized output. [CONFIG]
- `/sys/storage/raft/configuration`: the sample is enveloped under `data.config.servers`; entries show `address`, `leader`, `node_id`, `protocol_version`, `voter`, **not a zone label**. `/sys/storage/raft/join` has the related `non_voter` request parameter described above, not a zone parameter. [PEERS]
- The reviewed replication API overview/status page has no redundancy-zone contract. [REPLAPI]

## Executable checks and limitations

Created two read-only YAML files using the local v1 schema and `feature: redundancy`:

1. `sys-ha-status.yaml`: success plus the documented `Nodes[].redundancy_zone` string shape. No exact zone, member count, or nonempty-string constraint. It permits an empty string, but **does not claim the docs guarantee that an unconfigured node returns an empty string**. It needs a target that successfully exposes HA status; success on a non-HA in-memory dev server is not established by HA. An empty Nodes array passes vacuously because the harness's documented schema subset has no minimum-item assertion. [HA; local README for harness limitations]
2. `sys-raft-autopilot-state.yaml`: success plus integer `optimistic_failure_tolerance`, based on the Enterprise additional-output contract. Optional zone-map objects are shape-checked when present. Requires initialized/unsealed Raft Integrated Storage and root-namespace access; this is **not** an unconditional in-memory dev test. The docs' configured-zone example does not specify no-zone omission/null/default behavior, so the case does not require zone maps or invent zero/empty defaults. [AUTO]

A suitably configured single-node target can exercise response shape without triggering any failure or requiring a populated zone. The docs establish fields, not universal success/default representations for every dev-server backend; prerequisite-sensitive failures must not be mistaken for proven Enterprise incompatibility. Dynamic zone member validation would need map-value schema support (`additionalProperties` is ignored by harness v1), and real failover tests need a multi-node fixture. No claims about a running target are made.

Harness warning from `compat/README.md`: `FEATURE_ABSENT` is only a non-accepted **404** with a feature tag. A shared endpoint returning 200 but omitting required Enterprise fields produces **FAIL**, not FEATURE_ABSENT. Both cases intentionally enforce the documented sample's shape rather than silently accepting missing Enterprise fields.

## Verification performed

Public pages were fetched and inspected, including the primary guide's Autopilot link and the Autopilot page's CLI output link. Both YAML writes passed the write tool's syntax/lint check. Files were read back after writing. No live API/harness execution was possible with the available tool set (no terminal/process runner and no supplied test target/token); runtime compatibility and failover remain unverified. Only this feature directory was written.
