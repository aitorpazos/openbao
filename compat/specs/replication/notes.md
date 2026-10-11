# Replication (performance + DR) — notes

SPDX-License-Identifier: MPL-2.0

Clean-room implementation of the documented Vault Enterprise replication
API surface on OpenBao (MPL-2.0). Written against public documentation
only; no Vault Enterprise source, binaries, or git history were consulted.

## Citation table

| ID  | Source                                                                                                              |
|-----|---------------------------------------------------------------------------------------------------------------------|
| REP | https://developer.hashicorp.com/vault/api-docs/system/replication (v2.x latest)                                     |
| REPP| https://developer.hashicorp.com/vault/api-docs/system/replication/replication-performance (v2.x latest)              |
| REPD| https://developer.hashicorp.com/vault/api-docs/system/replication/replication-dr (v2.x latest)                       |

Clean-room rules observed: no Vault Enterprise source/binaries/git; public
docs only. `system/replication-performance` and `system/replication-dr`
are 404 — the correct paths are under `system/replication/`.

## Documented surface implemented

- `sys/replication/status` (REP; unauthenticated in the docs and in the
  community routing table): `data.performance` / `data.dr` stanzas,
  omitted when the stream is disabled.
- `sys/replication/performance/status` and `sys/replication/dr/status`
  (REPP/REPD; unauthenticated): the single stream's stanza directly under
  `data`.
- Primary lifecycle (both streams): `primary/enable`
  (`primary_cluster_addr` optional), `primary/demote`, `primary/disable`,
  `primary/secondary-token` (`id` required, `ttl` defaults 30m,
  `secondary_public_key` optional), `primary/revoke-secondary` (`id`).
- Secondary lifecycle (both streams): `secondary/enable` (`token`,
  `primary_api_addr`, `ca_file`, `ca_path`), `secondary/promote`
  (`dr_operation_token` required for DR), `secondary/disable`
  (`dr_operation_token` required for DR), `secondary/update-primary`
  (`token` or `update_primary_addrs`), `secondary/generate-public-key`.
- Performance-only: `primary/paths-filter/:id` (CRUD; `mode` allow|deny,
  `paths` array; `id` is the secondary's cluster ID) and
  `secondary/dynamic-filter/:id` (read).
- Maintenance: `sys/replication/recover`, `sys/replication/reindex`
  (`diff`, `force`, `skip_flush`), `sys/replication/merkle-check`.

All endpoints are root-namespace restricted (root token only) per the
docs; the combined/typed status endpoints are additionally
unauthenticated.

## Status stanza shapes

Primary (REPP sample): `cluster_id`, `corrupted_merkle_tree`,
`known_secondaries` (ids), `last_corruption_check_epoch` (epoch string;
"-62135596800" when never), `last_reindex_epoch` (epoch string),
`last_wal` / `last_performance_wal` / `last_dr_wal` (int), `merkle_root`
(hex), `mode: primary`, `primary_cluster_addr`, `secondaries` (array of
connection entries; empty when no secondary is connected),
`ssct_generation_counter` (int), `state: running`.

Secondary: `cluster_id`, `connection_state`, `corrupted_merkle_tree`,
`known_primary_cluster_addrs`, `last_corruption_check_epoch`,
`last_reindex_epoch`, `last_remote_wal` (int), `last_start` (ISO time),
`merkle_root`, `mode: secondary`, `primaries` (connection entries),
`primary_cluster_addr`, `secondary_id`, `ssct_generation_counter`,
`state`.

Types follow the samples: epoch fields are strings; WAL and
`ssct_generation_counter` are integers; `clock_skew_ms`,
`last_heartbeat_duration_ms`, and `replication_primary_canary_age_ms` are
strings.

## Implementation notes

- State machine persisted in barrier storage (`core/replication/<stream>`
  with `<stream>` = `performance` | `dr`) so it survives seal/unseal.
- `cluster_id` on a primary is the local cluster ID; on a secondary it is
  the ID learned from the activation token (the replication-set ID), so
  primary and secondaries report the same value as in the docs.
- The secondary activation token is a JWT response-wrapping token
  (Format "jwt" — the community wrapping code documents that JWT-format
  wrapping tokens are used for replication and plugin setup). The JWT's
  `addr` claim carries the primary's API address; a secondary unwraps by
  POSTing the token to `<addr>/v1/sys/wrapping/unwrap`. When the token
  carries no `addr` claim it is unwrapped in-process via its `jti`.
- `sys/health` / core replication state flags now derive from the
  persisted configuration (perf/dr primary|secondary|disabled; the
  standby component follows the node's HA role), matching the community
  defaults when nothing is configured.

## Documented deviations (phase 1)

- **No WAL streaming.** Secondaries do not connect to the primary and no
  data is replicated; `connection_status` on secondaries reports
  "disconnected" and secondary `state` is "running" rather than the
  streaming sub-states (e.g. "stream-wals").
- **merkle_root is computed on demand** by a bounded walk of the barrier
  storage (limit 100k keys) instead of being served from an
  incrementally maintained index tree. Entries that cannot be decrypted
  under the current keyring are skipped. `last_wal` is the raft applied
  index on raft backends (0 otherwise) — the community storage has a
  single WAL, so `last_performance_wal`/`last_dr_wal` mirror it.
- **corrupted_merkle_tree is always false** and merkle-check reports no
  corruption; corruption detection/recovery belongs to the indexing
  phase.
- **No data wipe on secondary enable.** The docs describe clearing the
  local cluster before activating; phase 1 activation writes the state
  machine without destructive storage changes.
- **Token/paths-filter connection bookkeeping only.** `revoke-secondary`
  removes the secondary's registration; no live connection is severed.
  Paths filters are stored and served but not enforced (enforcement
  arrives with streaming).
- **`recover` returns a warning** ("replication is not enabled" or "no
  replication adverse state detected") instead of performing a real
  recovery exchange.
- **reindex recomputes the merkle walk** and stamps `last_reindex_epoch`
  on configured streams; there is no per-page diff/flush machinery yet.
- **Secondary activation JWTs are not signature-verified** against the
  primary's published key (`sys/wrapping/pubkey`); verification is
  phase-2 hardening.
- Re-enabling a stream reuses the local cluster ID rather than
  generating a new replication-set ID.

## Acceptance

- Unit tests: `internal/vault/replication_test.go` (status shapes,
  primary lifecycle, token issuance + wrapping, paths-filter CRUD,
  same-core activation via the local wrap path, demote/promote/disable,
  DR operation-token gates, reindex/merkle-check/recover, keypair
  generation).
- Harness specs: `compat/specs/replication/*.yaml` on the dev server
  (inmem storage; WAL-independent surfaces).
- Manual cross-cluster check: two dev servers; primary enables + issues a
  token; second dev server activates as secondary with that token and
  reports the primary's cluster_id (documents the JWT transport path).
