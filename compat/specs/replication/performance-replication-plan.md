# Performance Replication — research & implementation plan

SPDX-License-Identifier: MPL-2.0

Written: 2026-11-11. Clean-room: public HashiCorp documentation only; no Vault
Enterprise source, binaries, or git history consulted. OpenBao upstream (MPL-2.0)
source is fair base-game and was consulted where noted.

## 1. Verdict

Yes — feasible, and already partially built. The fork carries:

- **Phase 1 (committed, `19a767e65b` + `ba5fae66`)**: the full documented
  `/sys/replication` operator API surface for both performance and DR streams
  (lifecycle, tokens, paths-filter CRUD, status, maintenance), a per-stream
  state machine persisted in the barrier, and secondary activation through the
  JWT response-wrapping path. Harness: 5 spec files, 57/57 PASS (2 status
  cases pending real WAL values — sibling lane).
- **Phase 2a (uncommitted sibling WIP in-tree)**: pull-based full-state
  snapshot sync (`stream-sync`), sync-token authorization policy, periodic
  secondary pull loop, initial sync before mount-table load, read-only
  enforcement on secondaries.
- **Upstream base (v2.7.1)** already ships the consistency machinery the
  docs describe for replication: Strong Consistency Control (`X-Vault-Index`,
  `X-Vault-Inconsistent`, 412 semantics; GH-3839) and Server Side Consistent
  Tokens (SSCT). `internal/http/index.go`, `api/index.go` — reusable as-is for
  secondary read-after-write behavior.

Remaining work is bounded and staged below. The two genuinely hard pieces are
(cross-cluster) **write forwarding** and the **incremental merkle index**;
everything else is incremental hardening of what exists.

## 2. Documented behavior inventory (citations)

| ID | Source (all v2.x latest unless noted) |
|----|----------------------------------------|
| REP | https://developer.hashicorp.com/vault/docs/enterprise/replication |
| RINT | https://developer.hashicorp.com/vault/docs/internals/replication |
| REPP | https://developer.hashicorp.com/vault/api-docs/system/replication/replication-performance |
| REPD | https://developer.hashicorp.com/vault/api-docs/system/replication/replication-dr |
| RAPI | https://developer.hashicorp.com/vault/api-docs/system/replication |
| CONS | https://developer.hashicorp.com/vault/docs/enterprise/consistency |
| PSB | https://developer.hashicorp.com/vault/docs/enterprise/performance-standby |
| TUT | https://developer.hashicorp.com/vault/tutorials/day-one-raft/multi-cluster-architecture |

Documented contract for performance replication (PR):

- **Architecture** [REP]: one-to-many, primary is system of record; async
  near-real-time; primary is the only cluster that writes shared state.
- **Data classification** [REP]: every storage entry is `replicated` (shared),
  `local` (DR secondaries only), or `ignored` (not replicated; e.g. Autopilot
  config). Shared mounts default; PKI certificates are a documented example of
  mount-local paths. Local mounts on a performance secondary are invisible to
  the primary.
- **Secondary serves client requests locally** [REP][CONS]: reads on
  replicated data; writes to shared state **forwarded to the primary,
  transparent to the client** [REP]. Tokens/leases stay secondary-local
  [REP][RINT]; clients must re-authenticate when switching clusters [RINT].
- **Disconnected secondaries** [REP]: reads succeed (possibly stale), writes
  to replicated state fail; transit enc/dec succeeds; local-mount operations
  succeed; cross-cluster revocation fails; reconnect → automatic reconcile.
- **Implementation details** [RINT]: WAL of all updates (atomic with the key
  update) → log shipping; bounded WAL set with GC; when out of band, merkle
  index diff (of *encrypted keys*) → efficient reconcile (≈2 round trips) →
  resume WAL streaming. Merkle index updated in memory per operation,
  asynchronously flushed, ARIES recovery for crash consistency; index is the
  source of truth; WAL streams are unsynchronized between clusters.
- **Addressing** [RINT]: cluster definitions persist under
  `core/cluster/replicated/info` and `core/cluster/replicated-dr/info`;
  secondaries persist known primaries under `core/primary-addrs/perf` /
  `core/primary-addrs/dr`; heartbeat RPC carries cluster addresses; log line
  "replication: successful heartbeat".
- **Consistency** [CONS]: writes via RPC return the upstream WAL index; nodes
  wait up to 2s (`best_effort_wal_wait_duration`) for the index to arrive in
  the shipped log, else respond with a warning; `X-Vault-Index` response
  header on writes; request-side `X-Vault-Inconsistent: forward-active-node`,
  412 retry semantics, `allow_forwarding_via_header`, `allow_forwarding_via_token`,
  SSCT server-side consistency (1.10+; 412 default on nodes lacking the WAL
  index); `clock_skew_ms` / `last_heartbeat_duration_ms` /
  `replication_primary_canary_age_ms` (canary: active nodes periodically write
  a small record with their local clock; secondaries compute the delta).
- **Security model** [REP]: primary generates a self-signed replication CA;
  per-secondary private key + certificate packaged into the activation token
  (signed-JWT response wrap carrying the primary redirect address); mTLS on
  the cluster port; ALPN multiplexes forwarding and replication; revoking a
  secondary blocks only that secondary's cert.
- **Status shapes** [RAPI]: full JSON samples for primary (dr + performance)
  and performance-secondary (+ DR primary) stanzas; secondary `state` value
  `stream-wals`, `connection_state: ready`; per-second/primary connection
  entries with `api_address`, `cluster_address`, `clock_skew_ms`,
  `connection_status`, `last_heartbeat`, `last_heartbeat_duration_ms`,
  `node_id`, `replication_primary_canary_age_ms`; `merkle-check` response
  shape (`corrupted_root`, `corrupted_tree_map` with `tree_type:
  replicated|local`, `root_hash`, subpage lists, `last_corruption_check_epoch`).
- **Seal compatibility on enable** [REP]: enabling replication replaces the
  secondary's seal config/keys with the primary's (table of Shamir/auto
  combinations).
- **DR stream** (adjacent; drives shared plumbing): DR secondaries serve
  nothing until promoted [REP]; operation-token ceremony (attempt/update/delete,
  reindex/merkle-check under `dr_operation_token`) per REPD; leases/tokens ARE
  replicated for DR [REP][TUT].
- **PR↔DR composition** [TUT]: a performance replica cluster can have its own
  DR cluster(s); a PR primary can be a DR secondary of another set.

## 3. Gap analysis (documented behavior → current fork state)

| # | Documented behavior | State | Owner/lane |
|---|--------------------|-------|------------|
| G1 | Secondary serves client requests; shared writes forwarded to primary | **Partial/missing.** WIP `enforceReplicationReadOnly` rejects writes incl. **logins** — auth mounts replicate, so secondary logins must work | Phase 2b |
| G2 | Disconnected behavior (reads ok / writes fail / local mounts ok / transit ok) | Missing (currently: reads ok, all writes fail, no local-mount carve-out, no disconnect awareness) | Phase 2b |
| G3 | Heartbeat + connection bookkeeping (`connection_status`, `last_heartbeat`, skew, canary; `known_secondaries`; persisted `core/primary-addrs/*`, cluster defs `core/cluster/replicated*/info`) | Missing (WIP stores `LastSyncRFC3339` internally only) | Phase 2c |
| G4 | Merkle index (incremental, in-memory + async flush, ARIES, diff reconcile, source of truth) | Missing. Phase-1 `merkle_root` = bounded on-demand walk; `corrupted_merkle_tree` always false; merkle-check reports no corruption | Phase 3 |
| G5 | WAL streaming with bounded WAL set + GC | Replaced by full-snapshot pull (documented deviation). Delta sync needs G4 | Phase 3 |
| G6 | Paths-filter enforcement + local-mount semantics | Stored, not enforced. Local-mount exclusion not implemented | Phase 3 |
| G7 | Consistency headers/SSCT on secondaries | Machinery in base; not wired to replicated index | Phase 4 |
| G8 | Activation-token signature verification (`sys/wrapping/pubkey`) | Not verified (phase-1 note) | Phase 5 |
| G9 | Seal replacement on secondary enable | Not implemented (deviation candidate — keep local seal; document) | Phase 5 (decision) |
| G10 | Real `last_wal` / `last_performance_wal` / `last_dr_wal`, secondary `state` sub-states (`stream-wals`), `connection_state` | Pending (2 spec FAILs are exactly this) | Phase 2c/3 |
| G11 | DR: no service until promoted; operation-token ceremony (9 specs landed FEATURE_ABSENT); DR reindex/merkle-check | Sibling lane (WIP) | DR lane |
| G12 | Entity/alias identity handling for secondary logins [CONS] | Missing | Phase 2b/4 |

Also documented but out of scope by the standing boundary: byte-compat wire
protocol with real Vault Enterprise replication (RINT's gRPC/ALPN transport is
undocumented at the protocol level). Our transport is OpenBao-native; both
ends are ours; deviation documented in code + notes.

## 4. Implementation plan

Each phase ends harness-green and committed. Specs precede or accompany every
implementation (clean-room rule); every pre-existing file touched gets a
PATCHES.md row.

### Phase 2b — Secondary usability: forwarding, logins, disconnect semantics
The highest-value phase: turns the current read-only replica into a working
performance secondary.

1. **Login on secondaries** (fix G1 regression): auth mounts are replicated;
   login must succeed locally, creating secondary-local tokens/leases
   (expiration is already excluded from sync). Remove login from the read-only
   gate; keep writes-to-replicated-state blocked.
2. **Write forwarding secondary→primary** (G1): route shared-state writes over
   the sync channel to the primary for authoritative processing, replaying the
   response. Design: the sync token already authorizes the primary's
   `stream-sync`; extend it with a forward endpoint that accepts a request
   envelope (original path/body/operation + original client token *context*,
   not the raw token — cluster-local tokens must not cross the wire). The
   primary validates the sync token, re-issues the operation under a
   replication identity, and returns the response. Namespace-aware. Documented
   deviation where the docs don't specify the mechanism (they specify only the
   observable behavior: transparency + failure when disconnected).
3. **Disconnect semantics** (G2): track connection state; when disconnected —
   reads (including transit, local mounts) succeed; shared-state writes fail
   fast with a clear error; no forwarding attempts against a dead primary;
   reconnect resumes sync + forwarding automatically.
4. **Unit + harness specs**: secondary login lifecycle; forwarded write round
   trip; disconnected write failure; local-mount read/write on secondary.
   Extend `compat/specs/replication/` (new `50-secondary-serving.yaml`).
5. **PATCHES.md** rows for `request_handling.go` (already touched by WIP) and
   any core seam.

Acceptance: two-server E2E (PR enable → write on primary → read on secondary;
login on secondary; write on secondary → forwarded; stop primary → reads ok +
writes fail; restart → reconcile). All existing 57 replication cases stay
green.

### Phase 2c — Status truthing: heartbeat, canary, connection bookkeeping
1. **Secondary heartbeat** to the primary (piggyback on the sync pull; add an
   echo-style exchange returning primary clock, WAL index, and cluster
   addresses). Primary records per-secondary: `last_heartbeat`,
   `last_heartbeat_duration_ms`, `clock_skew_ms`, `connection_status`,
   api/cluster addresses, `node_id`; secondary records `primaries[]`,
   `known_primary_cluster_addrs`, `last_start`, `last_remote_wal`,
   `connection_state: ready`.
2. **Canary record**: active (primary) node periodically writes a small
   record with local clock [CONS]; both sides compute
   `replication_primary_canary_age_ms`. Reuse the autopilot echo-channel
   patterns where they fit; otherwise barrier record at a documented path.
3. **Persist addressing** under the documented paths
   (`core/cluster/replicated/info`, `core/cluster/replicated-dr/info`,
   `core/primary-addrs/perf|dr`) — adopting documented paths where our
   storage layout allows, else documented deviation.
4. **Status wiring**: make the 2 pending FAIL cases (`last_performance_wal` /
   `last_dr_wal`) return real indexes; expose secondary `state`
   (`stream-wals` while connected, degraded values while disconnected) and
   `connection_state`.
5. **Sync-token lease hygiene**: token revocation on `revoke-secondary` /
   `secondary/disable` / stream disable (currently minted but never revoked).
   Consider a secondary-access registry so revocation actually severs sync
   (doc: revoking blocks that secondary's future access).

Acceptance: status on both ends matches documented samples for the fields we
populate; heartbeats survive primary HA failover to the new active node.

### Phase 3 — Incremental sync: merkle index, filters, delta replication
The heart of "performance" replication at parity.

1. **Incremental index** (G4): maintain per-stream merkle index of barrier
   keys (encrypted-key domain per [RINT]; we hash decrypted-content digests —
   document as deviation, since our snapshot ships plaintext-over-mTLS)
   updated on write/delete via a narrow barrier seam; in-memory + async
   flush; startup reconciliation pass (ARIES-style consistency check against
   storage); bounded memory.
2. **Delta sync** (G5): `stream-sync` gains a since/index mode: primary and
   secondary exchange index digests; primary returns only differing entries
   (target ≈2 round trips per [RINT]); fallback to full snapshot when the
   diff exceeds a threshold. Removes the 100k-entry full-walk cost from the
   steady state.
3. **Filter enforcement** (G6): paths-filter applied at snapshot/delta
   generation (allow/deny over mount paths + namespaces); secondary-side
   delete of newly-filtered subtrees; local-mount (and local-path) exclusion
   from PR sync; local mounts created on secondaries remain invisible to the
   primary (one-way sync already guarantees this).
4. **merkle-check/reindex truthing**: real corruption detection from the
   index (mismatched subtree hashes → `corrupted_merkle_tree`,
   `corrupted_tree_map` with `tree_type` replicated|local); `reindex diff`
   does key-level verification; `force` rebuilds; `skip_flush` semantics
   honored against the async flush.
5. **Removal of phase-1 deviations** this supersedes: on-demand merkle walk
   (keep as fallback), always-false corruption, no-op reindex.

Acceptance: primary write → secondary converges within one sync interval with
a delta-sized payload (assert entry counts); filtered mounts absent from
secondary storage; deleting data on primary deletes on secondary; merkle-check
detects an induced mismatch.

### Phase 4 — Consistency integration
1. Wire the secondary's replicated index into the existing SSCT/
   `X-Vault-Index`/await-state machinery (upstream base) so read-after-write
   against a secondary follows [CONS]: writes return the index; subsequent
   reads on a stale secondary 412 or forward per the documented header
   contract; `best_effort_wal_wait_duration`-style wait on forwarded writes.
2. `allow_forwarding_via_token` / `allow_forwarding_via_header` documented
   knobs on the replication forwarder (config-only surface exists upstream —
   verify and wire).
3. Identity RPC for shared identity state on secondary logins (G12): entity/
   alias creation forwards to the primary when the identity entry doesn't
   exist locally, per [CONS].
4. Spec the observable behavior: 412-on-stale, header echo, forward-on-
   inconsistent; consistency suite under `compat/specs/replication/60-consistency.yaml`.

### Phase 5 — Activation hardening + seal decision
1. **JWT verification**: secondary verifies activation-token signatures
   against the primary's published key (`sys/wrapping/pubkey` — path exists);
   reject untrusted tokens before unwrap.
2. **Seal replacement** (G9): docs replace the secondary's seal config/keys
   with the primary's on enable. Keeping the secondary's local seal is a
   deliberate, documented deviation (it preserves independent recoverability
   and avoids shipping key material). Recommend: keep local seal; document;
   consult Aitor before implementing either way.
3. `secondary/update-primary` real retarget (WIP stores addresses; make
   heartbeat/sync actually switch), `secondary/promote` promoting streamed
   state (unblock writes, reset replication state), revoke semantics.

### Standing adjacent item (not PR-scoped, listed for completeness)
DR operation-token ceremony + DR-secondary-only reindex/merkle-check variants:
9 specs already landed FEATURE_ABSENT; belongs to the replication/DR lane
(census row 134). Phase 2c/3 plumbing (heartbeat, index) provides the shared
substrate.

## 5. Decisions needed from Aitor

1. **Commit the phase-2a WIP first?** It is uncommitted sibling work in-tree;
   my plan builds on it. Recommend: sibling commits it as-is (green build?
   verify first) so later phases diff cleanly.
2. **Seal replacement** (Phase 5.2): keep secondary-local seal (recommended,
   documented deviation) vs. implement documented replacement semantics.
3. **Forwarding identity model** (Phase 2b.2): replay under a replication
   service identity with client-context metadata (recommended for a first
   cut) vs. full client-token delegation design.
4. **Whether to keep the sibling's `stream-sync` endpoint path** (undocumented
   internal path mounted under the documented tree) or move it under an
   internal prefix before it becomes a compatibility surface.

## 6. Risks

- **Cross-cluster forwarding correctness**: replay semantics for
  non-idempotent operations (leases, counters) must not double-apply on
  retry; needs an idempotency envelope.
- **Merkle index scale**: in-memory index over the full barrier keyspace
  needs partitioning and async flush tuning; ARIES-lite startup scan bounds
  the crash window.
- **Snapshot cost during heavy write load**: delta sync (Phase 3) is the
  mitigation; until then the 10s full-pull loop is the documented limit.
- **Two write planes**: forwarding + local writes (tokens/leases) must not
  fight over the same keys; the skip-key lists already partition storage
  (verify `sys/expiration/` remains secondary-local — yes per WIP).
- **Rebase churn**: `core.go`, `request_handling.go` are shared seams;
  coordinate with sibling lanes before touching.

## 7. References

- Public docs: table in §2. Nothing else was consulted for behavior.
- In-repo context: `compat/specs/replication/notes.md` (phase-1 surface +
  deviations), `PATCHES.md` replication rows, `internal/vault/replication.go`,
  `logical_system_replication.go`, `replication_stream.go` (WIP),
  `internal/http/index.go` (consistency headers, upstream).
