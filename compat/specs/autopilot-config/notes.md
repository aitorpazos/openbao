# Autopilot configuration: disable_upgrade_migration

## Public contract sources

- **[AUTO]** https://developer.hashicorp.com/vault/api-docs/system/storage/raftautopilot — **v2.x (latest)**, get/set configuration sections.
- **[HTTP]** https://developer.hashicorp.com/vault/api-docs — **v2.x (latest)**, HTTP status codes and errors.

Expected behavior is derived only from public developer.hashicorp.com documentation. No HashiCorp Vault source was consulted. Existing `redundancy/` specs were read but not modified; this new file extends their state/HA coverage with configuration coverage.

## Contract and cases

[AUTO] documents GET and POST `/sys/storage/raft/autopilot/configuration`, restricted to the root namespace and Integrated Storage. Its Enterprise-only `disable_upgrade_migration` parameter is boolean, defaults to false, and disables automated upgrade migration when true. This is a runtime Autopilot setting, explicitly not a server configuration-file setting. It belongs to the automated-upgrade feature surface adjacent to redundancy zones; **the API does not document a redundancy-zone label configuration parameter**.

`00-config.yaml` has six cases:

1. GET the documented top-level response shape and fresh default false. Require the seven fields shown in [AUTO]'s configuration sample, with boolean/string/integer types. Do not invent a `data` envelope or assert deployment-sensitive values of the other six fields.
2. POST `disable_upgrade_migration: true`.
3. GET and require true, rather than accepting an ignored write as conformance.
4. POST `disable_upgrade_migration: false`.
5. GET and require false, testing explicit false handling as well as true.
6. POST a non-boolean string and require 400 plus `errors: string[]` [AUTO parameter type; HTTP invalid-data rule]. No coercion behavior for strings such as `"true"` is prescribed.

Bodyless writes accept 200/204 per [HTTP]'s warning-response rule. Read-after-write dependencies are same-file only. The reset-to-false write is independent of previous assertion results so a failed readback does not suppress it.

**Fixture:** disposable fresh initialized/unsealed Integrated Storage cluster with root-namespace administrative authentication. This suite intentionally changes a cluster setting and restores the documented fresh default, not an arbitrary previous setting. Never run it on production or a cluster with an active upgrade. No actual rolling upgrade, zone promotion, failover, or persistence-across-restart test is claimed.

## OpenBao inspection (not normative)

At inspection time:

- `internal/vault/ha_redundancy_zones.go` exists and describes per-node redundancy-zone reporting.
- `internal/vault/logical_system_raft.go` has the Autopilot state implementation and declares `disable_upgrade_migration` as a boolean configuration input.
- Its `handleStorageRaftAutopilotConfigRead` response map omits `disable_upgrade_migration`.
- Its `handleStorageRaftAutopilotConfigUpdate` handles other configuration fields but does not consume/persist the declared `disable_upgrade_migration` field.

Thus the parameter declaration/state feature does not establish the documented config read/write contract. This is a static observation of local OpenBao, not a claim that an Integrated Storage live test has been performed. Concurrent implementation work may alter it.

## Verification and live baseline

PyYAML parsed the file. From `compat/harness`, ran:

```text
go run . --target http://127.0.0.1:1 --token x --specs ../specs/autopilot-config --format table
```

All six cases loaded and produced connection-refused ERRORs; there were no loader/schema errors.

`go build -o /tmp/bao-dr-spec .` succeeded. Ran the harness against a fresh initialized/unsealed **in-memory** dev server on `127.0.0.1:25441`, not a Raft fixture:

| File | PASS | FAIL | FEATURE_ABSENT | SKIP | ERROR |
|---|---:|---:|---:|---:|---:|
| `00-config.yaml` | 0 | 0 | 6 | 0 | 0 |

All requests returned 404. This is the generic dev baseline, **not proof that Raft routes are missing**; their backend prerequisite is absent. A real Integrated Storage fixture is required to verify the static config-field gaps above and distinguish response-envelope differences. Expectations deliberately remain the documented top-level sample. The disposable server was terminated after testing.
