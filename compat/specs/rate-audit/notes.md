# Identity rate limits, rotation orphans, and Enterprise audit filtering

SPDX-License-Identifier: MPL-2.0

## Provenance and scope

All contract sources below were read from public **developer.hashicorp.com** documentation, labeled **v2.x (latest)**. No HashiCorp Vault source was read and no git commands were used. Existing OpenBao files were inspected only for spec/harness conventions and baseline feature presence. These files are specs, not endpoint implementations.

| Source URL (all v2.x (latest)) | Contract used |
| --- | --- |
| https://developer.hashicorp.com/vault/api-docs/system/rate-limit-quotas | Create/update parameters `group_by`, `secondary_rate`; read response `data` fields; DELETE cleanup |
| https://developer.hashicorp.com/vault/api-docs/system/rotation-orphans | Read a list of orphans, GET route table and curl example |
| https://developer.hashicorp.com/vault/api-docs/system/audit | Enable/disable routes, string-valued `options`, Enterprise `filter`, `fallback`, `exclude` |
| https://developer.hashicorp.com/vault/docs/enterprise/audit/filtering | Supported filter properties, enable-time configuration, one fallback per installation, practical examples |
| https://developer.hashicorp.com/vault/docs/enterprise/audit/exclusion | JSON-encoded exclusion array, required fields, optional condition, unconditional and multiple conditional examples |
| https://developer.hashicorp.com/vault/api-docs#http-status-codes | 200 reads, 200/204 write success, 400 invalid input |
| https://developer.hashicorp.com/vault/api-docs#error-response | Errors array of strings; no exact error wording asserted |

The three requested API pages were read in full, as were their linked filtering/exclusion references. Negative cases combine explicit parameter restrictions with the general 400 contract; endpoint-specific wording is not invented.

### Existing coverage / no duplication

- Studied `enterprise-config/00-group-policy-application.yaml` and `control-group/00-config.yaml` first.
- At authoring time `compat/specs/quotas/` contained lease-count coverage only; no existing rate-limit or sys/audit spec was found in the spec inventory.
- OpenBao's `internal/vault/logical_system_quotas.go` already registers rate-limit list/read/write/delete and includes `role`. The public API page does **not** mark `role` as Enterprise. This suite therefore does not relabel role limits as an Enterprise identity feature or add generic quota CRUD coverage.
- OpenBao's `internal/vault/logical_system_paths.go` already registers audit list/enable/disable. This suite uses enable/disable only to exercise and clean up Enterprise options, not as a separate baseline CRUD suite.
- `filter_default` and `filter_paths` do not appear on the requested audit page. `format` and `hmac_accessor` are not labeled Enterprise. None are speculated into this suite.

## Files and cases

- `00-identity-rate-limits.yaml`: 11 cases. Invalid grouping and incompatible secondary rates; create/read `entity_then_ip`; update/read `entity_then_none`; accept omitted secondary rate on a fresh fixture; cleanup. Explicit readbacks of Enterprise fields prevent silent ignoring of identity options from satisfying these cases.
- `10-rotation-orphans.yaml`: 2 read-only cases. GET `/v1/sys/rotation/orphans` (curl example) and its trailing-slash form (route table). The public route is **not** `/sys/rotation-orphans`, and the page does not document LIST or deletion.
- `20-audit-filtering.yaml`: 14 cases. Enable fallback, reject second fallback, enable read-operation filter, reject unsupported filter property, enable unconditional/conditional exclusions, reject malformed exclusion JSON, and unconditional cleanup of every reserved device name.

Dependencies refer only to earlier cases in the same file. Cleanup intentionally has no dependency so it remains runnable after failures, including accidental acceptance of negative inputs.

## Execution prerequisites and safety

Use only an initialized, unsealed, appropriately licensed disposable Enterprise target with a root-namespace root token. The API docs restrict audit operations to root and require sudo; quota operations allow root or administrative namespace. Reserved names are exclusively `compat-ra-*`; all must be unused beforehand. No concurrent runs or unrelated traffic.

Rate tests temporarily create a global quota. Require no pre-existing global quota. High primary/secondary rates are fixture choices to avoid throttling the suite, not contractual defaults. Cleanup deletes the fixture rather than restoring prior state.

Audit tests require **no existing fallback** and an independent healthy **unfiltered** audit device that stays enabled throughout. The target process must be able to create/write `/tmp/compat-ra-*.log`. These are server-side files. Never use this setup for production audit retention. The suite disables only its own devices, with fallback last; it does not remove log files. Preserve or remove those separately after inspection. Cleanup is best-effort, not a transaction or guaranteed finalizer if the harness is interrupted.

## Deliberate gaps

- Identity enforcement (separate entity buckets, fallback grouping by IP versus one shared bucket, effective default secondary rate) needs controlled authenticated/unauthenticated traffic, entity fixtures and timing. This configuration-only suite does not claim that acceptance/readback proves throttling behavior.
- `none` is an Enterprise grouping mode but is not identity-based; it appears only in the documented incompatible-secondary-rate negative case. No standalone aggregate/IP quota CRUD is added.
- The effective default of `secondary_rate` is documented as `rate`; its stored read representation when omitted is not specified. No exact default readback is invented.
- Rotation's sample is a bare `{"orphans":[...]}` object, without an HTTP envelope. Following the established specs, assert object/success rather than guess top-level versus `data`. No deterministic orphan creation, empty-list representation, exact entries, or missing-object status is asserted. This is deliberately a route smoke test, not complete orphan-content conformance.
- Audit enable success alone can be a false positive on implementations that ignore unknown device options. Negative cases improve discrimination, but this suite does not inspect emitted files or prove filtering, fallback routing, exclusion removal, immutable-source evaluation, or telemetry. That needs a log-aware integration fixture. Audit list's example likewise omits an envelope; no speculative option-readback placement is asserted.
- No license-negative, namespace isolation, auth/ACL denial, undocumented methods, or exact error strings are added. Missing feature routes are not accepted as successful fallbacks.

## Verification performed

Executed from the OpenBao repository:

```sh
uv run --with pyyaml python3 -c "import yaml,glob; [yaml.safe_load(open(f)) for f in glob.glob('compat/specs/rate-audit/*.yaml')]"
```

Result: exit 0, all three YAMLs parse.

Executed from `compat/harness`:

```sh
go run . --target http://127.0.0.1:1 --token x --specs ../specs/rate-audit --format table
```

Result: every case reported **ERROR**, exclusively `dial tcp 127.0.0.1:1: connect: connection refused`; expected process exit 1. No loader, unknown-field, schema, or dependency errors. This proves loadability/request construction only, not Enterprise runtime conformance. No live Enterprise target was exercised.
