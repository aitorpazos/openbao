# Secrets Sync — clean-room compatibility notes

## Sources and provenance

Only the following public HashiCorp documentation was used for API/behavior claims. **Every reference below includes the displayed version label: `v2.x (latest)`.** References apply to every row/bullet in the paragraph/table they introduce; observed local results and suite design decisions are explicitly distinguished from documentation claims.

- **[API]** https://developer.hashicorp.com/vault/api-docs/system/secrets-sync — **v2.x (latest)**, title `/sys/sync` (Enterprise). All provider, config, association, unified-list, and GitHub-app sections are on this single page; there were no separate provider API sidebar pages to follow.
- **[SYNC]** https://developer.hashicorp.com/vault/docs/sync — **v2.x (latest)**. Activation, lifecycle, statuses, templates, granularity, security and reconciliation.
- **[FLAGS]** https://developer.hashicorp.com/vault/api-docs/system/activation-flags — **v2.x (latest)**.
- **[HTTP]** https://developer.hashicorp.com/vault/api-docs — **v2.x (latest)**. `/v1/`, LIST aliases, empty lists, status codes and error envelope.
- **[AUDIT]** https://developer.hashicorp.com/vault/api-docs/system/config-auditing — **v2.x (latest)**. General audit request-header configuration, not a Secrets Sync API.

The suggested starting URL `https://developer.hashicorp.com/vault/api-docs/secret/secrets-sync` returned a documentation-site **404** (observation; no displayed version). The actual API prefix is **`/v1/sys/sync/`**, NOT `/v1/sys/secrets-sync/`. `secrets-sync` is the activation flag and this suite's `feature`, not the routing prefix. This is a SYS-level feature, not an engine to mount. [API; FLAGS; HTTP]

No Vault source, BSL source, binaries, or decompilation were consulted. No git commands were used. Repository reads were limited to the harness README and example specs; all writes are in this directory.

## Activation and operational prerequisites

Secrets Sync needs an appropriate Enterprise license (the narrative also covers HCP Vault Dedicated). Activation is a one-time trigger; requests before activation return an error indicating that the feature has not been activated. The status code of that error is **not specified** here. `GET /v1/sys/activation-flags` is documented unauthenticated and returns `data.activated` and `data.unactivated` lists of feature keys. `PUT /v1/sys/activation-flags/secrets-sync/activate` activates it; the narrative also permits POST. Activation-flags API calls are root-namespace scoped, and activation cannot be undone. [SYNC; FLAGS]

**Suite decision:** require an already-activated disposable target, root/admin-capable token, no ambient provider credentials and blocked outbound provider access. Activation is not automatically performed because it is irreversible and has client-count implications. No KMIP-style engine-mount gate is applicable. Non-list cases do not accept 404, allowing the repository harness to report `FEATURE_ABSENT`. A 400 activation error can satisfy a negative case, so **negative-only passes do not prove compatibility or activation**. Confirm activation separately before interpreting negatives. The PATCH config shape case is the non-list positive surface check.

## Full documented endpoint inventory

Paths below omit the common `/v1` prefix. All rows derive from **[API]**, except activation rows from **[FLAGS]**. `:type` and `:name` are required string URL parameters; the documented destination types are **`aws-sm`, `azure-kv`, `gcp-sm`, `gh`, `vercel-project`**, not `aws`, `azure`, `gcp`, or `github`.

| Method | Path | Request / response surface |
|---|---|---|
| GET | `/sys/activation-flags` | No body; activation lists |
| PUT | `/sys/activation-flags/secrets-sync/activate` | No provider fields; updated activation lists |
| PATCH | `/sys/sync/config` | Optional `disabled`, `queue_capacity`; config data |
| LIST | `/sys/sync/destinations` | Unified destination list grouped by type |
| LIST | `/sys/sync/destinations/:type` | Destination names for one type |
| GET | `/sys/sync/destinations/:type/:name` | Redacted destination details |
| DELETE | `/sys/sync/destinations/:type/:name` | Optional `purge=false`, `force_delete=false`; no sample response |
| POST | `/sys/sync/destinations/aws-sm/:name` | AWS create/update |
| POST | `/sys/sync/destinations/azure-kv/:name` | Azure create/update |
| POST | `/sys/sync/destinations/gcp-sm/:name` | GCP create/update |
| POST | `/sys/sync/destinations/gh/:name` | GitHub create/update |
| POST | `/sys/sync/destinations/vercel-project/:name` | Vercel create/update |
| GET | `/sys/sync/destinations/:type/:name/associations` | All associations and latest status for destination |
| POST | `/sys/sync/destinations/:type/:name/associations/set` | Required body strings `mount`, `secret_name`; link or refresh |
| POST | `/sys/sync/destinations/:type/:name/associations/remove` | Required body strings `mount`, `secret_name`; unlink and unsync |
| LIST | `/sys/sync/associations` | Unified associated-secret index and counts |
| GET | `/sys/sync/associations/:mount/:name` | Destinations/status by secret; both path strings required |
| GET | `/sys/sync/associations/destinations?mount=:mount&secret_name=:name` | Same lookup; supports slashes in mount/secret names |
| POST | `/sys/sync/github-apps/:name` | Configure custom GitHub app; required `app_id`, `private_key` |
| GET | `/sys/sync/github-apps/:name` | Read redacted app configuration |
| DELETE | `/sys/sync/github-apps/:name` | Delete app configuration; no sample response |

Important negative findings within this documented surface: no `associations/unset` (the operation is **remove**), no separate `/status` or `/sync-status`, no ordinary GET unified destinations collection (use LIST), no documented GET/POST/DELETE config operation, no `/sys/sync/audit` or `/sys/sync/config/audit`, and no GitHub-app LIST endpoint. Do not turn those documentation omissions into assertions that all such operations must fail. [API]

`GET ?list=true` is the documented generic alias for LIST, and PUT/POST are generic synonyms. Empty LIST results may return 404 with `{"errors":[]}`. Thus the suite allows 200/404 on LIST cases, but those cases cannot distinguish feature absence from an empty result. [HTTP]

### Config and audit

`PATCH /sys/sync/config` is restricted to root or administrative namespace. Fields: `disabled` boolean, default **false**; `queue_capacity` integer, default **1,000,000**. Setting disabled true prevents sending secrets, queues triggering operations, and leaves queued operations PENDING until reactivated/completed. Queue capacity is the maximum number of pending internal operations. No documented capacity bounds or GET config shape are supplied; the **PATCH response** has `data: {disabled: <bool>, queue_capacity: <int>}` and sample `mount_type: "system"`. The sample payload serializes disabled as string `"true"`; tests use the declared type and do not reject all boolean-string coercion. [API, Configuration]

There is no sync-specific audit endpoint on the API page. General audit configuration instead documents GET `/sys/config/auditing/request-headers`, and GET/POST/DELETE `/sys/config/auditing/request-headers/:name`; root namespace and sudo are required. POST accepts `hmac` boolean default false. The all-header response sample is `{"headers":{"X-Forwarded-For":{"hmac":true}}}` and the single-header sample is `{"X-Forwarded-For":{"hmac":true}}`. These are unrelated core endpoints and are intentionally not relabeled `feature: secrets-sync`. [API; AUDIT]

## Destination fields, exact names and defaults

All provider fields below are transcribed from **[API]**'s corresponding Create/Update sections. `name` is always a **required URL string**, not a required JSON body field. Defaults below are documented defaults, not observed runtime values. Unless marked required/conditional, fields are optional.

### Shared destination options

All five providers document these fields. [API]

| Field | Type | Default / meaning |
|---|---|---|
| `secret_name_template` | string | `""`; provider-normalized default template |
| `granularity` | string | `"secret-path"` for AWS/Azure/GCP; `"secret-key"` for GitHub/Vercel |
| `disable_strict_networking` | boolean | false; disables both IP and port restrictions |
| `allowed_ipv4_addresses` | list of strings | nil; IPv4 CIDR allowlist |
| `allowed_ipv6_addresses` | list of strings | nil; IPv6 CIDR allowlist |
| `allowed_ports` | list of integers | nil; permitted port numbers |
| `custom_tags` | string-to-string map | nil; **AWS/Azure/GCP only**, merged with built-in tags |

The normal secret-name pattern is `vault/<accessor>/<secret-path>`; casing/delimiters are normalized per provider. AWS's response shows `vault/{{ .MountAccessor }}/{{ .SecretPath }}`. Azure's API prose gives `vault-kv-1234-my-secret`; GitHub's gives `VAULT_KV_1234_MY_SECRET`. The GCP and Vercel API prose uses the generic slash example; do not infer exact provider-normalized outputs from it. The only documented granularities are `secret-path` (whole JSON document, string-encoded if necessary) and `secret-key` (each key separately; nested list/map values JSON encoded). Networking defaults block special-purpose IPv4/IPv6 addresses and permit ports 80/443; nil API allowlists are not a claim of unrestricted networking. [API; SYNC, Name template / Granularity / Endpoint security]

### AWS Secrets Manager — `aws-sm`

[API, Create/Update AWS Secrets Manager destination]

| Field | Type | Default / requirement |
|---|---|---|
| `access_key_id` | string | `""`; optional, credential-provider-chain fallback; mutually exclusive with `identity_token_audience` |
| `secret_access_key` | string | `""`; credential-provider-chain fallback |
| `role_arn` | string | `""`; assume role using STS; **required with `identity_token_audience` for WIF** |
| `external_id` | string | `""`; optional role trust-policy external ID |
| `identity_token_audience` | string | `""`; required for WIF, matches AWS IAM OIDC audiences; excludes `access_key_id` |
| `identity_token_key` | string | `""`; key must already be configured, otherwise default signing key |
| `identity_token_ttl` | string/int | **3600**; accepts duration strings |
| `region` | string | `""`; inferred through provider-chain/environment fallback |

Also all shared AWS options above. **No `bucket` field is documented**: this is Secrets Manager, not S3. Neither region nor static credentials are unconditionally required; do not assert 400 for an empty AWS body solely because they are omitted. [API]

### Azure Key Vault — `azure-kv`

[API, Create/Update Azure Key Vault destination]

| Field | Type | Default / requirement |
|---|---|---|
| `key_vault_uri` | string | **required**, URI of existing Key Vault |
| `client_id` | string | **required**, Azure app registration client ID |
| `tenant_id` | string | **required**, target tenant ID |
| `client_secret` | string | `""`; required for client-secret auth; excludes `identity_token_audience` |
| `identity_token_audience` | string | `""`; required for WIF; excludes `client_secret` |
| `identity_token_key` | string | `""`; preconfigured key or default signing key |
| `identity_token_ttl` | duration | `"1h"`, **non-negative** |
| `cloud` | string | parameter annotation literally says `"cloud"`; prose says **Azure Public Cloud** default |

Also shared Azure options. Omitting client_secret selects WIF if audience is set, otherwise Azure managed identity. Preserve the cloud-default documentation inconsistency; no guessed enum/default literal is asserted in YAML. [API]

### GCP Secret Manager — `gcp-sm`

[API, Create/Update GCP Secret Manager destination]

| Field | Type | Default / requirement |
|---|---|---|
| `credentials` | string | annotated **required**, but prose limits this to static auth; JSON credentials, excludes audience; WIF/ADC alternatives |
| `project_id` | string | `""`; override project inferred from service-account JSON or ADC |
| `replication_locations` | list | nil; storage replication locations, not a read-access restriction |
| `locational_kms_keys` | string-to-string map | nil; location name to KMS resource name |
| `identity_token_audience` | string | `""`; required for WIF, excludes credentials |
| `service_account_email` | string | `""`; service account impersonated with WIF audience |
| `identity_token_key` | string | `""`; configured signing key, otherwise default |
| `identity_token_ttl` | duration | `"1h"`, **non-negative** |

Also shared GCP options. The source says credentials may be JSON contents or `@path/to/file`; these specs do not assume an HTTP server dereferences local filesystem paths. The fallback prose accidentally says `client_secret` for ADC although GCP's parameter is `credentials`; do not add a GCP client_secret field. An example alone includes **`global_kms_key`**, but the parameter table omits its type/default/constraints; record this example-only field without inventing validation rules. The WIF sample also has a missing JSON comma; it is not copied verbatim into executable cases. Neither missing credentials nor missing project_id is treated as an unconditional 400. [API]

### GitHub — `gh`

[API, Create/Update GitHub Repository Action destination]

| Field | Type | Default / requirement |
|---|---|---|
| `enterprise_url` | string | `""`; self-hosted GitHub Enterprise Server URL |
| `secrets_location` | string | `"repository"`; **repository or organization**, not environment |
| `access_token` | string | `""`; fine-grained/personal token, alternative to app auth |
| `app_name` | string | `""`; configured app name, paired with installation ID |
| `installation_id` | string | `""`; **required when app_name authentication is used** |
| `repository_owner` | string | `""`; repository location owner |
| `repository_name` | string | `""`; repository location repository |
| `environment_name` | string | `""`; optional repository environment; absent means repository-global |
| `organization_name` | string | `""`; organization target (BETA) |
| `organization_visibility` | string | `""`; organization mode values **all, private, selected** (BETA) |
| `selected_repository_names` | list | nil; repositories for selected visibility (BETA) |

Also shared GitHub options, with **secret-key** default granularity and no documented custom_tags. The selected-repository sample uses a comma-delimited string despite the list annotation; this suite does not outlaw the documented sample representation. Parameter annotations do not mark owner/name/token unconditionally required, so do not invent unconditional missing-field requirements. [API]

### Vercel — `vercel-project`

[API, Create/Update Vercel Project destination]

| Field | Type | Default / requirement |
|---|---|---|
| `access_token` | string | **required**, permission to manage environment variables |
| `project_id` | string | **required** |
| `team_id` | string | `""`, optional |
| `deployment_environments` | list of strings | **required**; development, preview, production |

Also shared Vercel options; secret-key granularity default, no documented custom_tags. This additional documented provider is included even though the task's examples named only AWS/GCP/Azure/GitHub. [API]

### Custom GitHub app configuration

POST requires URL `name` string and body `app_id` string, `private_key` string, with no defaults documented. GET/POST samples contain `data.app_id` **number**, `data.fingerprint` string, `data.name` string, `data.private_key: "*****"`, and `mount_type: "system"`. There is a documentation mismatch between string request annotation and numeric response example (the request sample even uses `"true"` as app_id); do not derive an accepted-ID grammar from that example. App configurations with active destination authentication references cannot be deleted. Deleting local configuration does not delete the remote GitHub app. [API, Configure/Read/Delete custom GitHub app]

## Response shapes and status surfaces

These are **documented sample shapes**, not claims that every optional envelope field is always present. Standard examples include `request_id`, `lease_id`, `renewable`, `lease_duration`, `data`, `wrap_info`, `warnings`, `auth`; config/app examples also show `mount_type`. Do not assert generated IDs, timestamp values, or list ordering. [API]

- **Destination GET and AWS POST:** `data = {connection_details: <object>, name: <string>, options: <object>, type: <string>}`. Sensitive connection values are obfuscated. AWS sample masks access_key_id and secret_access_key with `"*****"`, preserves region; options uses **`granularity_level`**, not request field `granularity`, and `secret_name_template`. AWS POST additionally shows `options.custom_tags: {}`. No provider-specific POST response sample is supplied for Azure/GCP/GitHub/Vercel; do not invent exact credential masks or complete option schemas for them. [API, Read destination / AWS Create/Update]
- **Unified destination LIST:** `data.keys` array of **type strings with trailing `/`**, `data.key_info` object mapping those strings to arrays of destination names, `data.total_destinations` integer. Example types `aws-sm/`, `gh/`. **Typed LIST:** `data.keys` destination-name strings and `data.total_destinations` integer (no key_info in sample). [API, List destinations / List destinations by type]
- **Association GET/set/remove:** `data = {associated_secrets: <map>, store_name: <string>, store_type: <string>}`. Keys are `<mount-accessor>/<secret-name>`; values contain `accessor`, `secret_name`, `sync_status`, `updated_at`, all strings. GET/set sample shows SYNCED; remove sample shows UNSYNCED. These samples do not guarantee immediate completion of asynchronous work. [API, Read / Set / Remove association; SYNC]
- **Unified association LIST:** `data.keys` array of combined mount/secret path strings; `data.key_info` map from those keys to **arrays** of `{mount: <string>, secret_path: <string>}`; `data.total_associations`, `data.total_secrets` integers. Note **secret_path** here, not secret_name. Multiple destinations per secret mean association count may exceed secret count. [API, List associations]
- **Destinations by secret, both GET forms:** `data.associated_destinations` map keyed `<type>/<destination-name>`; values `{type: <string>, name: <string>, sync_status: <string>, updated_at: <string>}`. The query spelling is **secret_name** even though prose names the parameter `name`. [API, Read destinations by secret]
- **DELETE destination/app:** no sample body/status specific to these operations. Generic success allows 200 or 204, with 204 indicating no body. [API; HTTP]

There is no separate status resource in the documented inventory: status lives on associations and reverse association lookups. The complete narrative status table is **UNKNOWN, PENDING, SYNCED, UNSYNCED, INTERNAL_VAULT_ERROR, CLIENT_SIDE_ERROR, EXTERNAL_SERVICE_ERROR**. UNKNOWN means state cannot be determined; PENDING is queued; SYNCED/UNSYNCED are successful delivery/removal; the last three distinguish Vault-internal, configuration/privilege, and external-service problems. Documentation mentions an error code on failed operations but these API samples do **not** establish a separate field name such as `last_error`, `error_code` or `sync_error`; none is invented here. [SYNC, Associations / Sync statuses; API]

## Lifecycle, validation and errors

- Sync is one-way, asynchronous, event-based KV-v2 synchronization. Vault remains the source of record; updates and deletes propagate to destinations. Only KV-v2 is currently supported. Associations track latest status/timestamp and failures. [SYNC; API, Set association]
- `set` links an existing destination to a secret using **mount path** and secret name, not KV's `data/` API path and not mount accessor. It triggers sync; repeating it refreshes without recreating the link and can retry a resolved failure. Reads report the mount by accessor. [API]
- `remove` unlinks and triggers unsync, deleting the external secret. It reports success if the association is removed, already absent, or the remote secret was already removed. This is not a guarantee about a nonexistent **destination**, so no missing-destination remove-success test is inferred. [API]
- Deleting a destination with associations is disallowed unless purged. `purge=true` asynchronously unsyncs secrets and deletes associations before deleting the destination. `force_delete=true` permits deletion despite unsync failures and can orphan external secrets. No purge or force-delete cases are used here. [API]
- Name-template/granularity updates affect newly associated secrets; existing ones are not automatically renamed/repartitioned. Updating an association can force recreation (old remote secret deleted, new one synced). Supported template placeholders: DestinationType, DestinationName, NamespacePath, NamespaceBaseName, NamespaceID, MountPath, MountBaseName, MountAccessor, SecretPath, SecretBaseName, SecretKey; SecretKey is available only for secret-key granularity. [SYNC]
- Vault checks secret read permission when creating/updating an association. The narrative demonstrates HTTP **403** and `permission denied to read the content of the secret ... in mount ...`. Revoking the original caller's read access later does not remove an existing association. This suite has no additional ACL persona, so the documented authorization negative is deferred. [SYNC, Vault access requirements]
- The docs do **not** give a specific status/message for associating a nonexistent secret or destination, or the validation/lookup order. Such cases are deliberately not asserted as 400/404. Missing required fields and invalid types/enums use the generic **400 invalid/missing data** contract, not invented endpoint error strings. Standard errors are `{"errors":[<string>, ...]}`. Cloud errors can instead involve generic HTTP 502 or association failure status; exact timing is not pinned. [API; HTTP; SYNC]
- Automatic exponential-backoff retries and background reconciliation scans are enabled by default. They do not protect against out-of-band remote modifications or implement bidirectional sync. Destination collision handling is last-write-wins. A synced secret counts as a distinct client even when sent to multiple destinations. [SYNC]

## What this suite does and does not test

**Design:** 43 cases in 11 YAML files, `feature: secrets-sync`; independent files, no cross-file dependencies. Fixed `compat-sync-*-invalid` destination names and `compat-sync-invalid-app` are reserved to this suite. Run serially in a disposable namespace/instance with these names unused. Every provider/app file includes an unconditional DELETE cleanup, even after a failed negative. No association or remote resource is intentionally created, no mount is enabled, and global config is not deliberately changed (the sole positive config call is an empty PATCH).

**Included:** provider-required-field/auth-conflict/type/enum negatives; custom app required fields; destination and association unified-list shapes; typed destination list shapes; required reverse-lookup query parameters; config no-op response shape and type negatives; cleanup deletes. No fake cloud-success fixtures. Invalid credential-shaped literals are intentionally unusable and do not represent API responses.

**Limits:** public docs do not promise all destination validation occurs before cloud-client initialization. Run with provider egress denied and ambient credential discovery disabled; a network-dependent failure is not proof of a documented validation result. In particular gh-app-missing-installation also references an unconfigured app, and gcp-conflicting-auth uses a structurally empty credential document: the assertion is only generic 400, not which validation wins. Positive provider CRUD/read-redaction/status, set/remove, refresh, retry, purge, template/granularity changes and cloud sync completion need controlled configured destination/association fixtures and are deferred. Even a credential-free successful destination creation is not assumed portable across environments.

**Harness limits:** LIST 404 is accepted because [HTTP] documents empty lists. The optional `data` schema checks populated results but cannot require data only on 200; harness v1 has no status-conditional schema. Dynamic map values cannot be fully validated because `additionalProperties` is ignored by v1. Consequently these list tests are intentionally partial, not presence probes or exhaustive response validation. Missing-resource GETs are not added merely to inflate the case count, since 404 could mask missing feature support.

| File | Cases |
|---|---:|
| `aws-sm.yaml` | 5 |
| `azure-kv.yaml` | 5 |
| `gcp-sm.yaml` | 4 |
| `gh.yaml` | 5 |
| `vercel-project.yaml` | 5 |
| `github-apps.yaml` | 4 |
| `config.yaml` | 5 |
| `destinations-list.yaml` | 1 |
| `destinations-list-by-type.yaml` | 5 |
| `associations-list.yaml` | 1 |
| `associations-destinations.yaml` | 3 |
| **Total** | **43** |

## Verification actually performed

- All YAML writes returned tool lint status **ok**. A file-content search counted **43** `- id:` entries with the per-file counts above.
- Browser probe of `http://127.0.0.1:8200/v1/sys/health` reached an initialized, unsealed, non-standby server reporting `version: "2.0.0-HEAD"`. That response alone does not identify it conclusively as stock OpenBao.
- **Unauthenticated** GET `/v1/sys/sync/destinations?list=true` returned **403**, body `{"errors":["permission denied"]}`. Unauthenticated GET `/v1/sys/activation-flags` also returned **403** with that body. These are local observations, not compatibility expectations, and do not establish authenticated route absence.
- No authenticated server token or terminal/execution tool was supplied to this subagent. Therefore the Go harness was **not run**, no authenticated 404 was verified, and no Enterprise conformance pass is claimed. Parent/operator should run the harness with an authorized token against an already-activated disposable target. The task's expected stock-OpenBao absence remains an expectation, not an observed result. Do not replace these observed 403s with an invented 404 report.
