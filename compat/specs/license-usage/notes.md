# License and usage reporting conformance

## Sources and clean-room scope

All API contracts below come from public HashiCorp Developer documentation, version **v2.x (latest)**:

- https://developer.hashicorp.com/vault/api-docs/system/license — License status; HashiCorp and IBM license examples.
- https://developer.hashicorp.com/vault/api-docs/system/utilization-report — Get utilization report and example.
- https://developer.hashicorp.com/vault/api-docs/system/internal-counters — Entire page, including Entities, Client count, Cumulative namespace client count, Partial month client count, configuration read/update, and Activity export.
- https://developer.hashicorp.com/vault/api-docs#http-status-codes and https://developer.hashicorp.com/vault/api-docs#error-response — successful reads, successful writes (200/204), invalid data (400), and the JSON errors array.

The three area pages were read in full, including example bodies. No Vault implementation source was consulted. The two designated existing spec examples and the local compatibility harness were read only to determine file format and runner limitations. No git commands were used. Only new deliverable files in this directory were authored.

An additional lookup of https://developer.hashicorp.com/vault/api-docs/system/license-features returned HTTP 404. There is no retrieved versioned contract for that URL, and no feature endpoint was invented.

## Executable coverage

- `00-license-status.yaml`: read-only `GET /sys/license/status`; typed `data.autoloading_used`, `autoloaded`, and `persisted_autoload`, including the common license structure shown for both issuers. No fixed license identifier, issuer, features, dates, or paid-feature enforcement is required by these assertions.
- `10-utilization-report.yaml`: `GET /sys/utilization-report`; typed snapshot fields for auth methods, KV counts, quotas, leases, namespaces, PKI, replication, and secret engines. No fixture-specific totals or mount names.
- `20-internal-counters.yaml`: entities; current billing-period activity; RFC3339 and Unix time queries; namespace limit parameter; cumulative and monthly shapes; config read; empty config POST preserving omitted values; invalid date, format, enabled value, and retention bounds. Export is covered by JSON error responses only.

The suite intentionally has no cross-file dependencies or resource creation. `compat-lic-*` is reserved for fixtures and used for invalid sentinel inputs. Every case is independent, so loader/transport verification exercises every request instead of skipping dependents.

## Preconditions and operational constraints

Use an initialized, unsealed, stable Enterprise reference with a root token in the root namespace. The license shape fixture assumes an autoloaded license and persisted license metadata. OpenBao is license-free: this surface is a compatibility status representation, not an instruction to introduce license installation or commercial enforcement.

The internal-counters source restricts activity/monthly and configuration updates to root. Utilization accepts root or administrative namespace. Export needs `sudo` as well as path capabilities. Cumulative may be called in any namespace and is Enterprise tech preview; export is also tech preview. The specs use root throughout and do not create namespace or ACL fixtures.

Activity must be enabled, retained reports queryable, current-period data available, and background loading complete. The historical cases require retained data in the billing period containing June 2025; they are not guaranteed to pass on a fresh dev server. Epoch inputs were checked against the RFC3339 dates. Enterprise activity queries normalize to annual billing periods, not arbitrary requested slices. Custom non-yearly contracts are explicitly unsupported by the activity endpoint in the current documentation; export is the documented alternative. Cumulative requests should not be run concurrently on large namespace populations.

The only valid configuration write is an empty POST, relying on the explicit rule that omitted parameters retain their existing values. No valid disable or reduced-retention write is issued, so the suite neither discards monthly data nor needs destructive cleanup. Invalid writes are expected to be rejected under the documented bounds and general 400 contract. The suite does not capture and compare config before/after; empty-write success alone is not a proof of preservation.

## Corrections, documentation gaps, and deliberate omissions

### License

The license page documents **`GET /sys/license/status`**, not `GET /sys/license`. It does not document legacy license install/delete CRUD. No POST/DELETE rejection status is inferred merely from absence of these operations. Stored licenses are no longer supported; no legacy `stored` assertion is added. The autoloading boolean is type-checked rather than pinned to true, preserving room for a license-free compatibility representation; nested object assertions still use the documented loaded-license fixture.

### Utilization

This is a cluster-wide **snapshot**. There is no documented `duration`, `end-date`, start/end time, request body, pagination, or report-generation job. No such parameters or endpoints are tested. The sample shows a global lease quota object; it is type-checked if present, not required when no global quota is configured. Dynamic map entries are not pinned to the sample's auth/engine keys.

### Internal counters

- The configuration route is **`/sys/internal/counters/config`**, with **GET and POST**, not `/activity/config` and not PUT. `/activity/query` is not documented. The actual cumulative endpoint is `/activity/cumulative`.
- Config `enabled` accepts `enable`, `disable`, or `default`; reads of default settings use `default-enabled` or `default-disabled`. The deprecated `default_report_months` parameter is documented but not exercised. Retention is explicitly 48–60 months. Current Enterprise versions cannot disable counting because manual license utilization reporting is always enabled; no disabling test is attempted.
- The body samples provide explicit `data` envelopes. Activity `by_namespace` is an array; cumulative `by_namespace` is a path-keyed object; monthly counters are directly under `data`, rather than under `data.total`. Cumulative dynamic map entries are not deeply validated by this suite.
- The source uses `by_namespaces` in prose but `by_namespace` in JSON; schemas follow JSON. Early explanatory mount fragments use `path`, while full responses use `mount_path`/`mount_type`. Mount count schemas require common counter fields and type-check optional extra counters, because some source examples omit them.
- Introductory text still describes estimated current-month new clients, while the explicit version note says Enterprise 1.20+ returns actual values. No estimation, ordering, fixed totals, sum equality, or specific billing date is asserted. Some samples contain trailing/missing commas and illustrative counts that should not be treated as executable fixtures.
- Date parameters are `start_time` and `end_time` (RFC3339 or Unix); prose occasionally calls the latter `end_date`. Specs follow the parameter tables. `limit_namespaces` is exercised without asserting ranking against unknown activity. `current_billing_period` is deprecated and omitted because current billing is already the Enterprise default.
- Empty-history response status/shape and the transient background-loading error status are not specified on the page. The suite does not invent 204/404 alternatives or test that transient error; it requires loaded, queryable activity.

### Export and harness limitation

The export source documents `format=json` (default) and `format=csv`, monthly normalization, namespace filtering, client deduplication, earliest activity, and month ordering. Current-month data can lag by up to 20 minutes. JSON output is **JSON lines**, not an array or Vault `data` envelope; CSV flattens arrays as indexed columns and metadata maps as dotted columns. The response-field prose says `client_first_usage_time`, but JSON/CSV samples say `client_first_used_time`; no spelling assertion is made pending clarification.

The local runner (`compat/harness/main.go`) unconditionally applies `json.Unmarshal` to any nonempty response, even for status-only assertions. Therefore real multi-record JSONL or CSV success cases would produce runner `bad JSON` errors instead of useful conformance findings. Successful export cases and detailed per-record schemas are deliberately deferred; invalid-format/date requests still cover the export route through the documented JSON error contract. No harness changes were made. A future raw/JSONL/CSV response mode is needed to cover exports honestly.

## Verification performed

- `uv run --with pyyaml python3 -c "import yaml,glob; [yaml.safe_load(open(f)) for f in glob.glob('compat/specs/license-usage/*.yaml')]"` completed successfully (exit 0).
- From `compat/harness`: `go run . --target http://127.0.0.1:1 --token x --specs ../specs/license-usage --format table` loaded every spec and produced only request-level `ERROR ... connect: connection refused` results; no loader errors. Exit 1 is expected for the deliberately unreachable target.
- This verifies YAML/loader/request construction, not live Vault/OpenBao behavior. No target API success or conformance pass is claimed.
