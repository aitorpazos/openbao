<!-- Copyright (c) OpenBao Contributors -->
<!-- SPDX-License-Identifier: MPL-2.0 -->

# Snapshot-load: implementation notes

Status: implemented on the compat-harness branch (2026-10-11). The non-destructive
recovery view was implemented; the original "blocked" analysis below is retained
for provenance. Acceptance: `TestRaft_SnapshotLoad` /
`TestRaft_SnapshotLoad_CrossCluster` (external_tests/raft, raft test cluster with
HTTP handler), harness specs `compat/specs/snapshot-load/` (all PASS live on a
raft-backed server), in-package validation tests `TestSnapshotLoadValidation` /
`TestSnapshotLoadAutoLoad`.

Scope decisions taken:

- The documented non-destructive recovery view is implemented: an isolated
  barrier view built from the snapshot's own ciphertext (unsealed with the
  snapshot's keyring, not the live one), one-at-a-time slot, 72h expiry,
  active-node-change invalidation, root-namespace gating. The
  `snapshot-force` destructive path was NOT reused.
- The per-piece "recover, read, and list" operations referenced by the docs
  prose are not part of the published API reference; the isolated view is an
  internal approximation and recovery operations are deferred until/unless
  their API surface is documented.
- `snapshot-auto/snapshot-load/:name` loads by URL with an HTTP(S) fetch.
  Cloud-native schemes and storage credentials are deferred (cloud storage
  configurations are rejected at creation, so only the documented negative
  paths are currently reachable: unknown config, local-storage prohibition,
  missing `url`).

## Public documentation retrieved

Only public HashiCorp documentation and this repository's OpenBao source were
consulted; no Vault implementation source was read.

- https://developer.hashicorp.com/vault/api-docs/system/storage/raft
- https://developer.hashicorp.com/vault/api-docs/system/storage/raftsnapshotload
- https://developer.hashicorp.com/vault/api-docs/system/storage/raftautosnapshots

The snapshot-load page displays `v2.x (latest)` and Enterprise gating. The raft
page links to this separate snapshot-load API reference.

## Documented contract

`POST /sys/storage/raft/snapshot-load` loads a snapshot **without overwriting the
cluster with the snapshot's data**. Individual pieces of data can subsequently
be recovered, read, and listed. This is NOT a destructive snapshot restore.

The request sample uses `--data-binary @raft.snap`. The page does not document a
multipart request shape, JSON upload parameters, or a force option.

The response example is a JSON object containing `data` with these string fields:

- `cluster_id`
- `created_at` (timestamp)
- `expires_at` (timestamp)
- `snapshot_id`
- `status`, with the example value `loading`

Related routes are `LIST /sys/storage/raft/snapshot-load`, and GET/DELETE
`/sys/storage/raft/snapshot-load/:snapshot_id`. LIST returns `data.keys`;
GET shows the same metadata with `status: ready` (and `auto_config_name`/`url`
when loaded from an automated configuration). DELETE supports the boolean query
parameter `force`, default false, to unload even while loading or recovering.

Restrictions explicitly stated by the snapshot-load page:

- Snapshot must come from the same cluster and have the same unseal keys.
- Only one snapshot can be loaded at a time.
- Automatic unload after 72 hours.
- Active-node change sets loaded snapshot status to `error`; unload and reload
  are necessary before recovery can resume.
- Snapshot loading is unavailable with mlock enabled.

The endpoint page does NOT specify numeric HTTP status codes or exact error
messages/envelopes for an empty body or invalid magic. Do not claim exact error
wording is documented. A 400 negative fixture would be an inference from the
general invalid-request contract, not an endpoint-specific published example.

## Autoload

`autoload_enabled` defaults to false. It automatically loads the latest snapshot
after writing, replacing the previous loaded snapshot. The docs explicitly say
this does not automatically apply the snapshot to the cluster. Local storage
cannot enable it; at most one config can enable it. For intervals below an hour,
loading happens at most hourly.

## Why snapshot-force cannot implement this API

The manual raft page documents `POST /sys/storage/raft/snapshot-force` as a
cluster restore bypassing Autounseal/Shamir key consistency checks. In OpenBao,
`handleStorageRaftSnapshotWrite(true)` shuts down subsystems and invokes
`raftStorage.RestoreSnapshot` against the live raft backend. Both the destructive
replacement and bypassing key consistency checks contradict snapshot-load's
explicit contract. A wrapper around this function would risk erasing live data
when clients expect an isolated recovery view.

No alias handler or registration was added. No validation-only handler returning
synthetic successful metadata was added. No spec was written asserting invented
endpoint-specific errors. Existing specs and sibling work were not changed.

## Required scope decision

Either implement the documented non-destructive recovery view, including an
isolated snapshot store/barrier, key and cluster checks, loaded-snapshot state,
expiry and active-node lifecycle handling, and recovery read routing; or explicitly
authorize a differently named OpenBao-specific destructive restore alias. The
existing snapshot-force endpoint already provides the latter operation.

Full destructive restore testing remains inappropriate for the conformance
harness. A correct snapshot-load test should instead verify live data remains
unchanged after loading. Implementation and tests are pending this scope decision.
