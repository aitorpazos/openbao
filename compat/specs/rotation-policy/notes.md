# Rotation policy: documented contract and scope corrections

## Clean-room sources

Only rendered public HashiCorp documentation was used for the Vault contract.
No Vault source code, binaries, decompilation, or inferred implementation was used.
Local harness/spec files were read only to learn the harness format and behavior.

| URL | Version label actually displayed | Use |
| --- | --- | --- |
| https://developer.hashicorp.com/vault/api-docs/system/policies-rotation | `v2.x (latest)` | POST/GET/DELETE policy methods, paths, required integer parameters, read sample, deletion warning, Enterprise license |
| https://developer.hashicorp.com/vault/docs/enterprise/automated-credential-rotation/rotation-policies | `v2.x (latest)` | Supported workflows, assignment/unassignment, defaults, retry semantics, update propagation |
| https://developer.hashicorp.com/vault/docs/enterprise/automated-credential-rotation/overview | `v2.x (latest)` | Scheduler, status fields, HA, backoff and orphaning |
| https://developer.hashicorp.com/vault/api-docs/system/mounts | `v2.x (latest)` | Mount enable/read/tune inventory; no documented rotation_policy parameter |
| https://developer.hashicorp.com/vault/api-docs#http-status-codes | `v2.x (latest)` | 200/204 success, 400 missing/invalid data, 404 invalid path |
| https://developer.hashicorp.com/vault/api-docs#error-response | `v2.x (latest)` | errors array of strings |
| https://developer.hashicorp.com/vault/api-docs/system/rotation-policy | **No version label: page is 404** | Requested API documentation URL does not resolve |
| https://developer.hashicorp.com/vault/docs/concepts/rotation | **No version label: page is 404** | Unsuccessful concepts-page lookup; not an assertion source |

The working API link was discovered in the public system API sidebar, not guessed
from implementation. The task's proposed API differs materially from this public
contract. The requested "Automatic Key Rotation" concepts page was not established;
the actual policy API links to automated **credential** rotation documentation.

## Documented API and fields

All routes have the general `/v1/` prefix:

- `POST /sys/policies/rotation/:name`: create or update.
- `GET /sys/policies/rotation/:name`: read.
- `DELETE /sys/policies/rotation/:name`: delete.
- `name`: required string path parameter.
- `max_retries_per_cycle`: required integer; maximum backoff applications after failures.
- `max_retry_cycles`: required integer; maximum requeues to the next scheduled rotation after the per-cycle retry limit.

The API does **not** document LIST, `/sys/rotation-policy`, a policy-level
`rotation-status`, or a policy-level `rotate-now`. It does not document `max_age`,
`disable_after`, a policy cron field, or a policy interval. Their existence or
absence at runtime is not established by these pages. No acceptance/rejection
assertions for those invented requests were added.

The read sample shows the two integer fields as a bare JSON object. It does not
explain whether this is the complete HTTP response or an abbreviated `data`
payload. To avoid enshrining an ambiguous wire envelope, reads currently assert
200 and an object only. Exact value persistence and field nesting require a more
explicit public HTTP example before stronger conformance assertions are added.
No undocumented numeric minimum, partial-update behavior, or error text is asserted.

`00-policy-crud.yaml` uses the documented sample values (3/3 and the usage example's
5/4) for create/update. Negative tests cover each missing required field, both
missing, and invalid object values for integer fields. General HTTP docs ground
the 400 and unknown/deleted 404 expectations; these are not endpoint-specific
error examples. Final cleanup allows 404 as a fixture cleanup concession, not as
an assertion that a successful Enterprise DELETE returns 404.

## Enterprise gating and supported integrations

The API requires an appropriate Vault Enterprise license. The policy and overview
guides say an appropriate Enterprise license or HCP Vault Dedicated cluster is
required; no specific SKU or unlicensed-error status is asserted.

The policy guide explicitly lists **LDAP secrets static roles** and **OS secrets
accounts** as currently supported policy workflows. It tells readers to consult
plugin documentation for compatibility. The consulted policy docs do not establish
policy support for database, PKI, transit, transform, KMIP, or KV-v2. This is not an
assertion that those engines lack all forms of automatic key/credential rotation.

Assignment is credential/role-level: the guide uses `ldap/static-role/alice` with
`rotation_period="24h"` and `rotation_policy="custom-ldap-policy"`. Unassign by
writing `rotation_policy=""` on the role. The default policy is
`max_retries_per_cycle=6`, `max_retry_cycles=3`. Latest policy values are fetched on
each requeue cycle, so updates may not immediately affect active entries.

Deletion does not check whether plugins still use a policy. The docs advise
reverting plugins to defaults or reassigning them **before** deleting a policy;
automatic unassignment on deletion is not documented.

## Deferred status/trigger and mount-tune specs

**`10-status-trigger.yaml` was intentionally not created.** There is no documented
policy-level status or force-rotate endpoint in the consulted API. Therefore the
response to a no-attached-mounts trigger, its method, status shape and error cases
cannot be specified clean-room. Empty YAML placeholders would also fail the
harness requirement for nonempty cases.

The actual overview says to read a role or credential in its plugin for status:

- `last_vault_rotation`: timestamp of the last successful automatic or manual rotation.
- `next_vault_rotation`: timestamp of the next scheduled automatic rotation.
- `ttl`: seconds until the next scheduled rotation.

Manual success updates the last timestamp but not the next scheduled time or
its TTL schedule. `last_rotated_time` is not the documented field here. There is
no documented policy-level force flag in these sources. The overview discusses
periodic evaluation of pending schedule/period rotations and dispatch to plugins,
not cron syntax stored in policy objects.

**`20-mount-tune.yaml` was intentionally not created.** The mounts API documents
POST and GET `/sys/mounts/:path/tune`, but neither its write parameters nor its read
example includes `rotation_policy`. It gives no accepted/rejected behavior for
that unknown field on KV-v2. A successful unknown-field POST would not establish
persistence or integration. A 400 expectation would be equally invented. No KV
mount is created, no unknown tune field is submitted, and no claim of automatic
policy unsetting on delete is made. A public contract for that behavior is needed
before adding the requested file.

These omissions are deliberate documentation blockers, not implementation TODOs
backed by an assumed API. Cloud/LDAP/OS fixtures were not introduced to disguise
missing KV integration evidence.

## Proposed implementation seam (design only)

Subject to controller approval of the corrected scope, a new system-paths file
could register the **documented** `/sys/policies/rotation/:name` CRUD operations
and delegate storage/validation of the two integer retry limits to a policy store.
Scheduler integration belongs at supported plugin credential/role registration,
not at generic KV mount tune. No implementation was inspected or changed.

The public overview describes active-node-only execution, state restoration after
leadership changes, primary-cluster execution for shared mounts, and independent
local-mount execution. It describes exponential backoff with jitter and a maximum
delay, plus orphaning after policy limits. The policy guide specifies refresh on
requeue and manual re-registration after fixing an orphan's underlying problem.
These are design requirements for a future scheduler seam, not exercised by this
CRUD-only suite. Do not add guessed `/sys/rotation-policy` routes to satisfy the
original task wording.

## Verification

Executed from `compat/harness`:

```sh
go run . --target http://127.0.0.1:24533 --token compat-harness --specs ../specs/rotation-policy --format table
```

The real target returned 404 for all requests. Parsing and execution completed
with exit code 0 and no FAIL/ERROR results. Positive CRUD requests and malformed
writes classified FEATURE_ABSENT. Unknown/deleted reads and the two tolerant
cleanup requests classified PASS.

Important harness limitation: dependencies skip only a FAIL, not FEATURE_ABSENT
(`main.go`). Thus expected-404 reads also PASS on an absent feature despite their
creation dependencies. This differs from the requested expectation of PASS only
for cleanup; it is not evidence of feature support. The documented 404 contract
was not altered merely to manufacture a preferred classification. No harness
files were modified.

Fixtures reserve `compat-rot-crud`, `compat-rot-invalid`, and the absent read-only
name `compat-rot-unknown`. Use a disposable target, no concurrent suite copies,
no preexisting policies/attached roles with these names. Both writable policy
names have unconditional final cleanup, including after negative-test failures.
