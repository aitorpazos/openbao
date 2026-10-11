# Raft automated snapshots: public-documentation contract

## Provenance and clean-room boundary

Only public rendered HashiCorp documentation was used for API assertions. No
Vault source, binaries, decompilation, or remembered Enterprise behavior was
consulted. Existing repository specs and harness files were read only for harness
syntax and classification. No implementation files were inspected or changed.

Every page below displayed **`v2.x (latest)`** in its version selector:

| Reference | URL | Use |
| --- | --- | --- |
| A | https://developer.hashicorp.com/vault/api-docs/system/storage/raftautosnapshots | Automated snapshot API, parameters, samples, restrictions |
| B | https://developer.hashicorp.com/vault/api-docs | `/v1/`, HTTP status codes, error envelope, general limits |
| C | https://developer.hashicorp.com/vault/docs/configuration/storage/raft | Server Raft configuration; distinction from automated backups |
| D | https://developer.hashicorp.com/vault/api-docs/system/storage/raft | Manual snapshot export, restore, force restore |
| E | https://developer.hashicorp.com/vault/docs/concepts/integrated-storage | Integrated Storage overview; checked for automated backup configuration |
| F | https://developer.hashicorp.com/vault/docs/configuration | Server configuration overview; checked for snapshot/disable configuration |

The YAML `source` and `source_version` identify A. Their notes additionally cite
B (`#http-status-codes`, `#error-response`) for shared assertions. These are
latest-documentation contracts, not a claim that an older Vault version supports
all documented fields.

## Findings that correct the task's assumptions

- The named status endpoint **is documented**: `GET
  /sys/storage/raft/snapshot-auto/status/:name`. A does not document a bare
  `/sys/storage/raft/snapshot-auto/status` endpoint. No invented aggregate-status
  probe or permissive status-family assertion is included.
- A marks the **entire auto-snapshot surface Enterprise**, with an appropriate
  Enterprise license required and calls restricted to the root namespace. Config
  create/update, read, list, and delete explicitly require `sudo`. The status
  section does not itself say `sudo`; the fixtures use an administrative token
  because their setup and cleanup require it. No unauthenticated status claim.
- C does **not** document a `vault.storage.raft.auto_snapshot` configuration-file
  stanza, `max_file_size`, or an auto-snapshot `disable` flag. F and E did not
  supply one either. Do not implement these as documented Vault server options
  based on the task's wording. The verified configuration mechanism is API A.
- C's `snapshot_interval` (default 120 seconds; checks staggered between one and
  twice the interval) and `snapshot_threshold` (default 8192 commit entries) are
  low-level Raft snapshot parameters, **not** exported backup schedules or
  retention policies.
- A's actual local limit is **`local_max_space`**, a byte allowance for all
  snapshots matching `file_prefix` in `path_prefix`, not a per-file maximum.
  Attempts fail when there is insufficient space in that allowance.
- There is no endpoint-specific missing-name response example. The unknown and
  deleted read cases derive 404 and an `errors` array of strings from B's general
  invalid-path/error contract. They deliberately do **not** assert an exact
  message or `{"errors":[]}`. B specifies that exact empty envelope for an empty
  **LIST**, not for a missing config read. This inference should be revisited if
  more specific public documentation becomes available.

## Verified API and field inventory

All paths below omit the common `/v1` prefix (B).

| Method | Path | Contract from A |
| --- | --- | --- |
| POST | `/sys/storage/raft/snapshot-auto/config/:name` | Create or update a named config |
| GET | `/sys/storage/raft/snapshot-auto/config/:name` | Read config in `data` |
| LIST | `/sys/storage/raft/snapshot-auto/config` | `data.keys`, array of names |
| DELETE | `/sys/storage/raft/snapshot-auto/config/:name` | Delete config |
| GET | `/sys/storage/raft/snapshot-auto/status/:name` | Named config's status in `data` |

No PATCH behavior, merge rules, or omitted-field update preservation is specified
by A; the update fixture resends all required fields. B permits success 200 or
204 for operations without a documented data response. Read/list/status samples
have JSON data and use 200. Read schemas are open to additional fields.

Common config parameters (all part of A's Enterprise API):

- `name`: required string, path parameter.
- `interval`: required integer seconds or Go duration string, e.g. `24h`.
- `retain`: integer, default 1; when writing a snapshot, older snapshots beyond
  the retention count are deleted.
- `path_prefix`: required string; local directory or cloud bucket prefix.
  Trailing slash required for `azure-blob` and `google-gcs`; optional for `local`
  and `aws-s3`.
- `file_prefix`: string, default `vault-snapshot`.
- `storage_type`: required, one of `local`, `azure-blob`, `aws-s3`, `google-gcs`.
- `autoload_enabled`: boolean, default false; forbidden for local, enabled on at
  most one config. This **loads** a snapshot for recovery access, not restores it.
- Local: required integer `local_max_space`.

Cloud backend fields documented in A (recorded, **not exercised**):

- S3: required `aws_s3_bucket`, `aws_s3_region`; optional `aws_access_key_id`,
  `aws_secret_access_key`, `aws_session_token`, `aws_s3_endpoint`,
  `aws_s3_disable_tls`, `aws_s3_force_path_style`, `aws_s3_enable_kms`,
  `aws_s3_server_side_encryption`, `aws_s3_kms_key`. AES256 server-side encryption
  cannot be combined with KMS enablement. Credentials may come from SDK mechanisms
  on AWS/GCP; the docs separately warn AWS EKS service-account IAM roles cannot
  be used for this feature and require explicit access/secret keys there.
- GCS: required `google_gcs_bucket`; optional `google_service_account_key` (JSON
  string), `google_endpoint`, `google_disable_tls`.
- Azure: required `azure_container_name`; `azure_account_name`, `azure_auth_mode`
  (`shared`, `managed`, `environment`), `azure_account_key` (shared),
  `azure_client_id` (managed), `azure_blob_environment`, `azure_endpoint`.
  Environment auth uses `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`,
  `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`.

Cloud credentials are never supplied by these fixtures. A's local read sample
says nothing about cloud credential redaction; **no redaction behavior is
asserted or inferred** from unrelated specs.

The local read sample documents string `file_prefix`, `path_prefix`,
`storage_type` and integer `interval`, `retain`, `local_max_space`. The sample
normalizes `24h` to `86400`. Config cases verify documented defaults, sample
shape, list membership (not list equality), and POST updates.

Status samples contain string `last_snapshot_end`, `last_snapshot_error`,
`last_snapshot_start`, `last_snapshot_url`, `snapshot_start`, `snapshot_url`.
Autoload examples also contain `next_snapshot_start`,
`loaded_snapshot_expires_at`, `loaded_snapshot_id`, `loaded_snapshot_status`,
or `loading_error`. Presence before the first scheduled snapshot is unspecified;
the schema requires an object `data` and types these properties only when present.
No fixed URL, timestamp, scheduling instant, empty error, or snapshot success is
asserted. A's initial `snapshot_start` sample contains `2020-108T...`, so it is
not a sound basis for timestamp-format validation.

## Negative cases, limits, and deliberate gaps

Missing required `interval`, `path_prefix`, `storage_type`, and local
`local_max_space` each expect 400 using A's required markers and B's invalid-data
contract. Invalid intervals use malformed duration syntax and an object, not
undocumented bounds. Local autoload rejection follows A's explicit prohibition.
No claim is made about zero/negative interval boundaries, minimum interval,
maximum retain, maximum configs, unknown DELETE idempotence, or error wording.
The invalid-fixture cleanup allows 200/204/404 because it is housekeeping for a
name that should never have been created, not an idempotence conformance claim.

Documented limits:

- Autoload runs at most hourly when configured intervals are below an hour; only
  one config can enable autoload (A). This is not an hourly snapshot-write limit.
- Local disk allowance and retention are as described above (A).
- A documents snapshot loading separately at `POST
  /sys/storage/raft/snapshot-auto/snapshot-load/:name`, with required `url`.
  It excludes local storage; snapshots must share cluster/unseal keys; only one
  may be loaded at a time; automatic unload after 72 hours; active-node change
  makes the loaded snapshot unusable until unload/reload; mlock precludes loading.
  This recovery-data loading API is outside the CRUD/status fixtures.
- B documents a tunable default maximum request size of 32MB and listener JSON
  payload limits. No auto-snapshot-specific request rate or config-count quota
  was found in the retrieved pages.

## Manual snapshot surface (documentation only)

D is **not Enterprise-gated** for these operations, unlike A. Thus public Vault
API documentation already describes the general/manual surface without the
Enterprise restriction. This finding is about the docs, not a claim from Vault
source inspection. OpenBao documentation was not used as a contract authority
because this task limits normative sources to developer.hashicorp.com.

- `GET /sys/storage/raft/snapshot`: returns a **binary** snapshot of the current
  Raft cluster state, intended to be redirected to a file, not a JSON `data`
  response.
- `POST /sys/storage/raft/snapshot`: accepts the binary snapshot and restores the
  cluster to its contents. Request completion means validation and acceptance,
  **not completion of restore**. Restore runs in the background, tears down
  subsystems, swaps the database, and restarts subsystems. D says to wait for
  `post-unseal setup complete` and `vault is unsealed` logs before regular use.
- `POST /sys/storage/raft/snapshot-force`: same restoration action, but bypasses
  checks that Autounseal or Shamir keys are consistent with the snapshot.
  It is **not a force-create snapshot endpoint**.
- All three are unavailable with Raft exclusively as `ha_storage`. Large
  snapshot operations may require increased `VAULT_CLIENT_TIMEOUT` and listener
  `http_read_timeout`.

No manual export/restore test is included: these specs target automated snapshots,
manual export is binary (the harness expects JSON), and restoring a cluster would
be destructive. No restore request was made.

## Fixture safety and proposed implementation seams

Run serially against a disposable, unsealed, active Raft target, in root namespace
with a sudo-capable token. Reserved names: `compat-snap-crud`,
`compat-snap-invalid`, `compat-snap-status`. These must not preexist. Directories
are on the **server**, under `/tmp/compat-snap-crud/` and
`/tmp/compat-snap-status/`; provision them as writable before a real scheduling
integration run. No directory is created by the HTTP harness. Configs use `24h`
(or its documented numeric equivalent), a bounded local allowance, and no cloud
credentials. A does not guarantee that the initial snapshot is delayed; do not
interpret the long interval as a no-write guarantee. Cleanup deletes configs
without depending on successful read/schema assertions; if interrupted, manually
remove the reserved configs. Do not assume deleting config removes existing
snapshot files: the docs do not promise it.

Implementation plan, **design suggestions, not claims about Vault internals**:

1. Add root-scoped system-backend (`sys/`) handlers for the five documented
   routes, with sudo gating on config operations and normal authentication/ACLs
   on status. Validate documented requirements and keep full update semantics
   conservative until additional public evidence resolves partial updates.
2. Persist named configuration through the core's protected/barrier-backed
   system storage, separate from configuration-file Raft tuning. Normalize
   intervals to seconds for reads; keep backend credential storage behind a
   dedicated abstraction. Resolve credential read/redaction policy explicitly
   before cloud support rather than asserting an invented Vault contract.
3. Place the scheduler in a core-owned lifecycle service, started only for the
   active/unsealed Raft storage node; cancel on sealing, leadership loss, config
   replacement/deletion, and shutdown. Reconcile persisted configs on activation.
   This placement is a proposal; no repository-specific seam was verified.
4. Reuse the project's existing manual snapshot export primitive, with a local
   writer, atomic publish, retention restricted to the matching prefix, bounded
   disk usage, and per-config status bookkeeping. Never use restore/force restore
   to produce a backup. Put cloud writers and autoload recovery behind separate
   interfaces and extend tests only from documented contracts.
5. Follow up with scheduler/failover/disk-full integration tests in a disposable
   Raft environment. These HTTP fixtures intentionally do not prove scheduling,
   retention execution, cloud authentication, or completed snapshot state.

## Harness verification

Executed from the repository's `compat/harness` directory:

```sh
go run . --target http://127.0.0.1:24533 --token compat-harness --specs ../specs/raft-autosnapshot --format table
```

Exit status: **0**. YAML loading and schema validation succeeded.

- **PASS**: `config-unknown-read`, `config-read-deleted`,
  `config-invalid-cleanup` (all HTTP 404).
- **FEATURE_ABSENT**: all remaining config and status cases (all HTTP 404).
- **FAIL / ERROR / SKIP**: none.

Expected-404 PASS results are weak negatives: an absent route satisfies them and
they do not demonstrate a working Enterprise implementation. The harness keeps
running dependencies after FEATURE_ABSENT, so read/status cases were actually
requested, not skipped. Schemas were validated syntactically but their successful
response shapes cannot be verified against this feature-absent target. No harness
or implementation edits, no git commands, and no fabricated responses were used.
