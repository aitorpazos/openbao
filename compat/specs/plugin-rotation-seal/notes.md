# Plugin identity, provider rotation, and backing seals

Clean-room conformance specifications, not implementation. All behavioral sources below are public **developer.hashicorp.com** documentation labeled **v2.x (latest)** when consulted. No HashiCorp Vault implementation source was consulted. OpenBao source was inspected only to establish the local baseline. No git commands or pre-existing repository files were changed.

## Sources and attribution

Every URL in this table uses source version **v2.x (latest)**.

| Source | Contract used |
| --- | --- |
| https://developer.hashicorp.com/vault/api-docs/secret/identity/tokens | Plugin and secrets-sync issuer discovery and public JWKS shapes |
| https://developer.hashicorp.com/vault/api-docs/auth/aws | `/auth/:mount/config/client`: WIF audience/TTL, role ARN, access-key exclusion, root scheduling |
| https://developer.hashicorp.com/vault/api-docs/secret/aws | `/:mount/config/root`: corresponding secrets-engine fields |
| https://developer.hashicorp.com/vault/api-docs/auth/azure | `/auth/:mount/config`: WIF audience/TTL, client ID, client-secret exclusion, root scheduling |
| https://developer.hashicorp.com/vault/api-docs/secret/azure | `/:mount/config`: corresponding secrets-engine fields, tenant and subscription IDs |
| https://developer.hashicorp.com/vault/api-docs/auth/gcp | `/auth/:mount/config`: WIF audience/TTL, service-account email, credentials exclusion, root scheduling |
| https://developer.hashicorp.com/vault/api-docs/secret/gcp | `/:mount/config`: corresponding secrets-engine fields |
| https://developer.hashicorp.com/vault/api-docs/auth/ldap | LDAP **auth** `rotation_url`, root scheduling, config readback |
| https://developer.hashicorp.com/vault/api-docs/secret/ldap | LDAP **secrets** self-managed config, static-role password/DN, `rotation_policy`, static migration/status/stop |
| https://developer.hashicorp.com/vault/api-docs/secret/databases | Connection-level skip-import flag, static-role passwords and schedules, rootless/skip-import workflows |
| https://developer.hashicorp.com/vault/api-docs/secret/databases/postgresql | DSN, PostgreSQL `self_managed`, exclusion of root username/password, disabled connection verification |
| https://developer.hashicorp.com/vault/api-docs/system/policies-rotation | Named policy fixture with retry-cycle limits, cleanup |
| https://developer.hashicorp.com/vault/api-docs/system/sealwrap-rewrap | GET status counters and POST start with 200/202 |
| https://developer.hashicorp.com/vault/api-docs/system/seal-backend-status | Unauthenticated, unwrapped backing-seal health response |
| https://developer.hashicorp.com/vault/api-docs/system/auth | Enable/disable disposable auth mounts |
| https://developer.hashicorp.com/vault/api-docs/system/mounts | Enable/disable disposable secrets mounts |
| https://developer.hashicorp.com/vault/api-docs#http-status-codes | Success 200/204, invalid requests 400 |
| https://developer.hashicorp.com/vault/api-docs#error-response | JSON errors array |

**Documentation correction:** self-managed LDAP, `rotation_policy`, `static-migration`, and `static-migration/stop` are documented on **secret/ldap**, not **auth/ldap**. The specs do not invent these routes under an auth mount.

## Spec inventory

### `00-plugin-identity.yaml`

- Plugin and secrets-sync discovery: top-level issuer/JWKS URI strings, supported response/subject types and signing algorithms; JWKS array with common public-key metadata. No fixed deployment URL, key ID, RSA modulus or nonempty-key requirement.
- AWS auth and secrets: `identity_token_audience`, `identity_token_ttl`, required `role_arn`; reject simultaneous `access_key` and audience and reject an audience without a role ARN.
- Azure auth and secrets: audience/TTL and `client_id` readback; reject simultaneous `client_secret` and audience. Tenant/resource or subscription fixture values accompany config writes.
- GCP auth and secrets: audience/TTL and required `service_account_email` readback; reject an audience with an empty selector.
- Documented TTL default is 3600 seconds; executable readback uses an explicit numeric 600 so no assertion depends on minting/decoding a token.

The plugin JWKS paragraph's curl example uses `/identity/oidc/.well-known/keys`, whereas the plugin discovery sample advertises `/identity/oidc/plugins/.well-known/keys`. The spec follows the advertised `jwks_uri` path, documenting this discrepancy rather than claiming the generic JWKS route is plugin-specific coverage.

**GCP exclusion fixture gate:** the docs exclude `credentials` with `identity_token_audience`. To isolate this negative on a provider-capable target, supply a syntactically valid disposable service-account JSON/key fixture and an otherwise valid audience/email config. Do not use `credentials: '{}'`: that can return 400 solely for malformed credentials and falsely claim exclusion coverage. This negative is intentionally not in the fixture-free YAML.

### `10-provider-rotation.yaml`

- All six AWS/Azure/GCP auth+secrets config surfaces: schedule/window/disabled readback, nonzero period versus schedule exclusion, period/window exclusion, period below 10 seconds, window below one hour.
- All scheduling inputs are explicit in negatives to avoid inheriting a previous write's schedule/window. Automated root rotation remains disabled. Omitted GCP credentials exercise documented optional/ambient configuration, not a supplied real identity.
- LDAP auth: separate `rotation_url`, schedule/window/disabled readback and period/schedule exclusion.
- LDAP secrets: `self_managed` and config skip-import readback, immutable self-management mode, forbidden bindpass, required static-role password and DN, skip-import onboarding; a disposable named rotation policy is attached and read back.
- Migration: explicit `include_role_names` requirement, empty-mount status/start/stop. No assertion of a real migration's completion, ordering, or counters on a new empty mount.
- Database: PostgreSQL config with `verify_connection: false`; `skip_static_role_import_rotation`; static-role `skip_import_rotation` and imported `password`; rootless PostgreSQL `self_managed`, username/password exclusion, and deprecated `self_managed_password`. Read static credentials to check the supplied dummy password survives skip-import instead of requiring a real rotation.
- Database static schedules have a documented 5-second minimum period, unlike the cloud/root 10-second minimum. The 4-second negative exercises an already-present OpenBao validation.

`skip_import_rotation` is a creation-time instruction; the suite does not require that flag to be echoed from a static-role read. It checks the observable imported password instead. Config-level flag readback is separate. These are onboarding/config checks; they do not prove that credentials authenticate to a remote service.

### `20-seal-rewrap.yaml`

- Unauthenticated `GET /sys/seal-backend-status`: top-level `healthy`, `fully_wrapped`, `backends`; per-backend name/configured/disabled/healthy; optional `unhealthy_since`.
- `GET /sys/sealwrap/rewrap`: `data.is_running` and integer failed/processed/succeeded entry counters.
- **POST**, not PUT, starts a background rewrap. Expected 202 when started or 200 if already running; no assumption about how long it runs. Subsequent status checks shape only.
- Do not confuse seal rewrap with response-wrapping-token rewrap.

## Safety, fixtures, and limits

Use only a disposable, isolated administrative target, ideally with outbound network blocked and cloud credential environment variables removed. All reserved mounts and `compat-pr-policy` must be absent before starting. Cleanup disables only reserved mounts and deletes that policy; it is unconditional. No concurrent runs against the same target. No login, cloud token exchange, explicit root rotation, or explicit static-role rotation is requested.

**Rewrap is not a dry-run.** On a supported target, the POST acts on all seal-wrapped entries. Never run this file against production merely to check route existence.

Actual LDAP/DB password verification and rotation, scheduled cloud rotations, backoff/retries from the policy, GCP credentials/audience exclusion with a valid key, LDAP migration with pre-upgrade roles, and seal re-encryption require external fixtures. They are documented gates, not fake successful cases. A licensed reference target may need valid provider config even for config acceptance; distinguish that prerequisite failure from a field-validation failure. No live cloud/LDAP/DB fixture was available here.

For a real LDAP migration fixture, GET with `include_role_names=true` has the documented `data.migrated` and `data.unmigrated` arrays plus `total_role_count`, `total_successfully_migrated`, and `total_remaining` counts. The empty-mount smoke case deliberately does not assert this sample-shaped response when the docs say an inactive migration returns nothing.

The docs do **not** promise general unknown-field rejection. Do not invent it or interpret a successful write as proof of support: config readback catches ignored Enterprise fields. Error assertions use documented status/envelope, not unstable implementation wording.

The harness has no general capture/interpolation or JWT decoding. This suite uses only fixed fixtures, schemas, exact fields and list membership. The current harness does support `no_auth: true`; discovery and backing-seal cases use it because a blank token header alone is overridden by the run token. No token capture is used. Dependencies are same-file only. Current harness skips only a direct dependency with verdict FAIL; ERROR, FEATURE_ABSENT and SKIP do not propagate transitively. Consequently some reads after skipped writes still execute and report FEATURE_ABSENT. This is a harness observation, not a server contract.

## OpenBao in-tree findings

These are implementation inventory observations, **not** sources for expected Vault behavior.

- `internal/builtin/logical/database/path_config_connection.go` has database connection config, `verify_connection`, plugin selection, root credentials and allowed roles. `internal/builtin/logical/database/path_roles.go` has static username and `rotation_period` plus its minimum validation. PostgreSQL is registered in `internal/helper/builtinplugins/registry.go`.
- Searches did not locate the requested database `skip_import_rotation`, `skip_static_role_import_rotation`, `self_managed`, static scheduling or rootless input fields. A password stored internally in the static-account structure is not evidence that the API accepts the Enterprise password input.
- Contrary to the task's suggested LDAP premise, **this checkout/build does not register LDAP auth or LDAP secrets**. The current builtin registry has neither LDAP nor AWS/Azure/GCP plugins; local LDAP-related SDK helpers/API client/docs and commented test code do not establish a runnable backend. Live mount attempts return 400; a direct LDAP probe returned `plugin not found in the catalog: ldap`.
- `internal/vault/identity/store_oidc.go` registers generic `oidc/.well-known/openid-configuration` and `oidc/.well-known/keys`, not the plugin/secrets-sync issuer subpaths.
- `internal/vault/logical_system_sync.go` already has sync-destination identity audience/TTL/selector fields and mutual-exclusion validation. That existing sync configuration is distinct from plugin config and issuer discovery; this suite does not duplicate the secrets-sync specs.
- `internal/vault/logical_system_rotation_policy.go` already implements named rotation policies; the policy fixture create/delete passes live.
- `sealwrap/rewrap` appears in `internal/vault/request_handling.go`'s restricted-path list. No backing-seal-status handler or rewrap handler was found. Authenticated probes returned unsupported path; unauthenticated discovery/backing-seal probes returned 403 before reaching any route.

## Verification and baseline

Executed YAML parsing using:

```sh
uv run --with pyyaml python3 -c "import yaml,glob; [yaml.safe_load(open(f)) for f in glob.glob('compat/specs/plugin-rotation-seal/*.yaml')]"
```

All three files parsed. Executed the harness table command against `http://127.0.0.1:1` with token `x`: **every case ERROR, connection refused; no loader errors** (36 / 91 / 4 cases respectively).

Built the repository binary with `go build -o /tmp/bao-plugin-rotation .` successfully. Started a fresh dev server on checked-free `127.0.0.1:25301`, root token `compat-harness`, as a tracked background process; health returned initialized/unsealed and version `2.0.0-HEAD`. Ran:

```sh
cd compat/harness
go run . --target http://127.0.0.1:25301 --token compat-harness \
  --specs ../specs/plugin-rotation-seal --format table
```

Final fresh-server baseline:

| File | PASS | FAIL | FEATURE_ABSENT | SKIP | ERROR | Cases |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `00-plugin-identity.yaml` | 6 | 10 | 6 | 14 | 0 | 36 |
| `10-provider-rotation.yaml` | 17 | 17 | 15 | 42 | 0 | 91 |
| `20-seal-rewrap.yaml` | 0 | 1 | 3 | 0 | 0 | 4 |

The live command exits 1 because genuine FAIL results exist. Identity-file PASS results are cleanup only, not WIF functionality. Rotation-file PASS results include database mount/config, short-period rejection, named-policy creation, and cleanup; rootless config write acceptance alone is not feature support.

Actionable failures: unsupported provider mounts; unauthenticated issuer/seal-status routes returning 403; missing database config skip-import readback; static import/rootless writes returning 500 instead of performing no-network skip-import; rootless+root-credentials config incorrectly accepted (204); seal rewrap routes 404. No expected result was weakened to match these gaps.
