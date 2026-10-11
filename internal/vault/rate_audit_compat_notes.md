<!-- SPDX-License-Identifier: MPL-2.0 -->
# Rate/audit configuration compatibility

Clean-room inputs: `compat/specs/rate-audit/*.yaml`, its `notes.md`, existing
OpenBao MPL source, and the public rate-limit-quota and audit-filtering API/docs
pages referenced by the specs. No Vault implementation source was consulted.

## Scope and limitations

- `group_by` and `secondary_rate` are validated, stored, cloned and returned by
  quota CRUD. Empty grouping defaults to `ip`; omitted/zero secondary rate for
  entity modes uses the primary rate. A secondary rate cannot be explicitly set
  for `ip` or `none`. **Admission remains the existing IP limiter.** Entity ID
  propagation, separate entity/fallback buckets, and aggregate `none` enforcement
  are deferred; accepted configuration does not prove enforcement.
- GET `sys/rotation/orphans` (with optional trailing slash) is root-namespace only.
  The current rotation-policy implementation has no LDAP/OS-account scheduler
  integration and therefore no such orphan producers. The endpoint returns an
  empty `data.orphans` array. Actual rotation discovery/recovery is deferred.
- Audit `filter`, `fallback`, and `exclude` use existing mount-option persistence
  and audit-list readback. Enable-time validation checks supported filter
  properties, predicate syntax, exclusion arrays/JSON pointers, and boolean
  fallback values. Fallback uniqueness is checked under the existing audit-table
  lock before backend creation. No new dependencies were added.
- **Audit support is configuration-only.** The broker continues logging to all
  enabled devices. It does not apply filters, route only unmatched events to a
  fallback, remove excluded fields, or emit fallback telemetry. Do not rely on
  these options to suppress sensitive log fields. The predicate validator handles
  the documented comparison examples and boolean combinations, not a claim of
  complete external expression-language compatibility. Emitted-log integration
  tests and runtime evaluation remain separate work.

## Verification

Commands executed from the repository (Go 1.27.1 darwin/arm64):

- `go build -o /tmp/bao-rataudit .`: exit 0.
- `go vet ./internal/vault/...`: exit 0.
- `gofmt -l` on all eight touched Go files: no output.
- `go test ./internal/vault/quotas/ -count=1`: PASS, package 27.104s.
- `go test ./internal/vault/ -run 'IdentityQuota|SecondaryRate|RotationOrphan|AuditFilter|Quota' -count=1 -v`: PASS, package 1.372s.
- `go test ./internal/vault/ -run 'TestLoginMfa|TestRotationPolicy|KMIP|Spiffe|ControlGroup|AgentRegistry|EnterpriseConfig' -count=1`: PASS, package 3.083s.
- Live binary: dev mode on 127.0.0.1:25161, root token `compat-harness`, explicit
  `unsafe_allow_api_audit_creation = true` in a temporary config. Port availability
  checked with lsof; health returned initialized/unsealed. An independent,
  unfiltered file audit device remained enabled throughout the harness.
- `cd compat/harness && go run . --target http://127.0.0.1:25161 --token compat-harness --specs ../specs/rate-audit --format table`: **27/27 PASS**.
- Cleanup: harness removed all its fixtures; audit list contained only the
  independent device and quota GET returned 404. Dev process stopped and lsof
  confirmed listener ports were free. Temporary log artifacts remain in `/tmp`.

Full execution artifacts: `/tmp/bao-rataudit-harness.txt`,
`/tmp/bao-rataudit-unit.log`, `/tmp/bao-rataudit-regression.log`, and
`/tmp/bao-rataudit-server.log`.

## Porting seams

`PATCHES.md` records the four source-file seams. The only change to
`logical_system.go` is this registration line after `rotationPolicyPaths`:

```go
b.Paths = append(b.Paths, b.rotationOrphanPaths()...)
```

The only change to `audit.go` is under `auditLock`, before the existing
matching-name loop:

```go
if err := validateAuditFilterOptions(entry, c.audit.Entries); err != nil {
    return err
}
```

The remaining edits to pre-existing files are confined to quota field schemas,
validation/storage/readback in `logical_system_quotas.go`, and two persisted
fields, clone copies and the legacy IP default in `quotas/quotas_rate_limit.go`.
No request-handling, core, replication, identity, HTTP, mount, raft, agent-registry,
SPIFFE, enterprise-config, or control-group implementation was modified.
