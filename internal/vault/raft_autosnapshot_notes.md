<!-- Copyright (c) OpenBao Contributors -->
<!-- SPDX-License-Identifier: MPL-2.0 -->

# Local Raft automatic snapshots

Clean-room contract: `compat/specs/raft-autosnapshot/{00-config-crud.yaml,10-status.yaml,notes.md}` and this repository's OpenBao source only.

- Config operations require sudo and all routes are root-namespace-only. Configuration uses the system mount's barrier-backed storage. Raft used solely as HA storage is excluded.
- `interval` is required, not defaulted. `retain` defaults to 1 and `file_prefix` to `vault-snapshot`. There is no documented `disable`, `retention`, or server configuration stanza. Delete the configuration to stop its schedule; files are preserved.
- Only `local` is implemented. Cloud storage types are rejected with an invalid-request response rather than silently stored. Cloud credentials, autoload, and snapshot-load recovery are not implemented. Local autoload is explicitly rejected.
- Additional operational validation requires positive interval/retain/space, a representable interval, nonempty directory, and a filename-only prefix. POST replaces the complete configuration; it does not merge fields.
- The supplied notes do **not** specify a complete filename format. This implementation uses `<file_prefix>-<UTC timestamp with nanoseconds>.snap`. This is an implementation choice, not an asserted Vault contract.
- The directory must already exist. Snapshots are written with mode 0600 and atomically renamed from `.partial` files. Only regular matching `<file_prefix>-*.snap` files are subject to retention/space eviction. Symlinks, unrelated files, and directories are not deleted. Configurations with overlapping prefixes share an allowance domain; exports are serialized within a system backend.
- Oldest matching snapshots are evicted as space is needed, keeping the in-progress output plus existing matching snapshots within the allowance when initially within it. An oversized snapshot fails and partial output is removed. A failed export can therefore have evicted previous backups. External writers, abandoned partial files after process crashes, and simultaneous writers from different servers sharing the same directory are not coordinated; use node-local dedicated directories.
- Initialization/cleanup hooks own the worker, with the core's active context canceling it on seal, shutdown, or leadership loss. The worker skips exports while sealed, standby, or DR secondary. Persisted configurations are reconciled after activation. First export is delayed by the configured interval; subsequent attempts are scheduled from completion. Tick resolution is one second.
- Status is in memory and node-local, resets with backend activation, and reports the last completed attempt. Reads serialize with an in-progress export. Configuration changes request cancellation of an in-progress matching export and then wait for it to stop. The underlying Raft snapshot primitive has no context argument: cancellation interrupts output and prevents publication, but cannot interrupt Raft work before output begins.
- HA failover, disk-full faults, crash recovery, and multi-process directory coordination still require dedicated integration coverage. No claims of cloud support or full Vault Enterprise parity are made.
