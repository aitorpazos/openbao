# Vault Enterprise SCIM — documentation-only conformance scope

## Provenance

Only public rendered HashiCorp documentation was used for product contracts. No Vault source, repository history, or Git commands were accessed. The local harness and existing conformance YAMLs were read solely for format/execution conventions. `compat/specs/README.md` was absent; rotation-policy and snapshot-load examples were studied.

Browser tools were unavailable. Instead, HTTPS GET plus BeautifulSoup extracted the complete `article` text (falling back to `main`) and links; long tool output was read in paginated form. The following pages were read in full. Labels below are the **displayed labels**, not inferred release versions.

| URL | Version label | Establishes |
| --- | --- | --- |
| https://developer.hashicorp.com/vault/docs/enterprise/scim-overview | v2.x (latest) | Enterprise beta, 2.x.x-or-later prerequisite, one-way activation, namespace routing, principal-based authentication, bearer-token setup, mappings, ownership, limitations, asynchronous deletion |
| https://developer.hashicorp.com/vault/api-docs/secret/identity/scim | v2.x (latest) | Client management methods/parameters, user/group methods and supported filters/PATCH, payload examples, discovery, unauthenticated ServiceProviderConfig, explicit `/Me` 501 |
| https://developer.hashicorp.com/vault/api-docs/system/activation-flags | v2.x (latest) | Root-only GET/PUT activation API, unauthenticated status, `data.activated` / `data.unactivated`, irreversible activation |
| https://developer.hashicorp.com/vault/api-docs | v2.x (latest) | `/v1/`, token/namespace headers, generic statuses and management error envelope; anchors `#http-status-codes`, `#error-response`, `#namespaces`, `#api-operations` |

Discovery used the official `https://developer.hashicorp.com/server-sitemap.xml`. Neither SCIM article links an official RFC; no extra RFC-only schema, PATCH payload, pagination, or status contract has been imported. The reviewed SCIM pages do not establish an Okta/JumpCloud-specific connector contract. They describe generic external identity platforms; Terraform/HCP SCIM APIs are not Vault APIs.

## Documented inventory

All paths below are relative to `/v1`. Sources are the SCIM API page unless otherwise stated.

| Area | Methods and paths | Documented contract |
| --- | --- | --- |
| Activation | GET `/sys/activation-flags`; PUT `/sys/activation-flags/enable-scim/activate` | Root only, status readable without auth; errors before activation, no undo. Exact feature key from overview. |
| Client configuration | POST, GET, DELETE `/identity/scim/client/:client_name`; LIST `/identity/scim/client` | Namespace-unique name; required string `access_grant_principal` is an existing same-namespace entity ID. Optional string `alias_mount_accessor` must identify an existing same-namespace non-local auth mount; cannot change or clear it after creation. |
| Client deletion | DELETE as above | Marks `deleting: true`; asynchronously removes owned entities, aliases, groups and client config. New protocol requests are blocked. No completion deadline given. |
| Users | POST, GET `/identity/scim/v2/Users`; GET, PUT, PATCH, DELETE `/identity/scim/v2/Users/:id` | Entity mapping: `id`, `userName` (entity name), `externalId`, `active` (inverse disabled). Creation requires userName and externalId; externalId immutable. `groups` read-only, direct memberships managed by same client only. |
| User filter/PATCH | User GET collection and PATCH item | `eq` on userName/externalId/active; `gt`, `ge`, `lt`, `le` on meta.lastModified. PATCH supports only one replace operation on active. |
| Groups | POST, GET `/identity/scim/v2/Groups`; GET, PUT, PATCH, DELETE `/identity/scim/v2/Groups/:id` | Internal-group mapping: `id`, `displayName`, `members[].value` containing user entity IDs. Only client-owned users; no groups as members. |
| Group filter/PATCH | Group GET collection and PATCH item | `eq` on displayName; `gt`, `ge`, `lt`, `le` on meta.lastModified. Other filter attributes/operators rejected. PATCH limited to member add/remove. |
| Discovery | GET `/identity/scim/v2/ServiceProviderConfig`; GET `/identity/scim/v2/Schemas[/:id]`; GET `/identity/scim/v2/ResourceTypes[/:id]` | ServiceProviderConfig explicitly unauthenticated; other discovery requests use client auth in specs. Protocol response media type application/scim+json. |
| Unsupported | `/identity/scim/v2/Me` | Explicit 501 Not Implemented. No bulk, sort, ETag or change-password operations. |

The user sample includes core User schema and optional-looking Vault Metadata extension `urn:ietf:params:scim:schemas:extension:vault:2.0:Metadata` with `items: [{key, value}]`. The page does not fully specify extension requirements, validation, or response behavior, so these are not asserted.

SCIM clients and their principals are namespace-scoped. The overview documents both an embedded namespace path (example `/v1/admin/identity/scim/v2/Users`) and the standard `X-Vault-Namespace` header. A client can manage only resources it created; it cannot adopt existing resources, migrate resources between clients, or remove SCIM management. Administrators can read managed resources and modify non-SCIM-managed fields, but only the owning client can delete them or modify SCIM-managed fields. SCIM does not manage policies.

## Executable scope and fixture contract

This is a **partial, fixture-backed suite**, not a self-bootstrapping CRUD lifecycle. Five YAML files cover activation status, management read/list/input validation, discovery including `/Me`, user list/filters/required fields, and group list/filter/operator rejection. Generic 200 and 400 expectations are explicitly sourced to the general API contract, not claimed as endpoint-specific example responses. Management errors assert the general errors array; protocol errors intentionally do not assert a Vault errors envelope. The filter cases exercise acceptance/rejection, **not result membership or isolation**.

Use a disposable initialized/unsealed licensed Enterprise target in the **root namespace**. External setup must:

1. Activate enable-scim once, with root-namespace authorization. The YAML deliberately does not make this irreversible change. No negative preactivation status is guessed.
2. Create a dedicated entity and a SCIM client named `compat-scim-actor` using that generated entity ID as access_grant_principal. Follow the overview's token-auth alias/role workflow, or another documented auth method resolving to the entity. A normal root token is not a substitute for an entity-bound protocol token.
3. Supply the entity-bound token as the harness run token. In this disposable environment it also needs management read/list/write/delete permissions for the fixture paths in addition to protocol ACLs. No credentials are embedded in specs.
4. Through that client, create the active user `compat-scim-user` with externalId `compat-scim-external-user`, and internal group `compat-scim-group`. Save all returned IDs externally. These fixtures keep collection reads and positive filters nonempty without inventing empty-result response contracts.

Reserved names (must not collide with other workloads):

- Client `compat-scim-actor`: fixture owner retained until the entire suite finishes.
- Client `compat-scim-invalid`: initially absent, exclusively for invalid management requests and unconditional cleanup.
- User name `compat-scim-user`, externalId `compat-scim-external-user`, group displayName `compat-scim-group`: externally provisioned read fixtures.
- User name `compat-scim-invalid-user`, externalId `compat-scim-invalid-external`: malformed-create fixtures; never preprovision.
- Entity ID `00000000-0000-0000-0000-000000000000`: deliberately nonexistent. Verify absence externally; this is not a purported valid principal.
- Any setup entity, alias, token-role and policy names should use the exclusive `compat-scim-` prefix, with IDs/accessors recorded by the operator. These names are fixture conventions, not product constraints.

Do not run concurrent copies. At completion (including failure), delete the dedicated actor client and wait externally for asynchronous removal of all managed resources and client configuration. Then revoke the fixture token and remove setup roles, policies, aliases and principal entity as appropriate. Do not remove a shared auth mount. `compat-scim-invalid` has unconditional DELETE cleanup accepting documented generic success/not-found statuses, but no immediate deleted-read assertion: async completion is not guaranteed. If malformed user creation succeeds on a buggy target, actor deletion also cleans those leaked users. **Never point this suite at a shared production client.** Activation cannot be cleaned up; discard the disposable target if necessary.

## CRUD coverage deferred rather than fabricated

The docs expose a real management API; this is not merely an external-connector feature. However, a valid client create needs a generated entity ID. Full positive lifecycle coverage requires an orchestrator capable of capturing those values:

- Client: create with an existing principal, read/list, POST updated configuration using a second existing principal, reject changing/clearing an initialized alias accessor, DELETE, then poll for completion. Establish update semantics and exact response contract first; the API table names POST but does not separately specify an update payload or read response.
- User: POST the documented payload, capture id, GET, PUT replacement preserving externalId, PATCH active, reject externalId changes, DELETE, verify removal. Patch document schema, detailed PUT requirements and endpoint-specific statuses require further authoritative documentation.
- Group: POST documented payload with an owned user ID, capture group id, GET/PUT, member add/remove PATCH, reject non-owned user and nested group membership, DELETE. No guessed PATCH documents are included.
- Test two clients/namespaces to verify scope, token-entity resolution, admin restrictions, alias creation/rename synchronization, immutable/local/cross-namespace accessor failures and async cascade cleanup.

No placeholder IDs are sent as supposedly valid resources. No undocumented exact error strings, deletion polling deadline, response envelope, discovery resource identifiers, generated field format, pagination default, or SCIM error body is asserted. The overview mentions `/clients` alongside `/client`, but only the singular LIST route is in the API method table; the plural alias is not tested. License-denial and activation-denial statuses are not specified. Namespace routing is documented but not exercised by this root-only suite.

## Harness findings and validation

The current harness supports `no_auth`, JSON bodies, explicit request headers, same-file dependencies and token-only capture. It cannot capture/interpolate arbitrary entity IDs, auth accessors, SCIM resource IDs or client IDs; it cannot poll asynchronous deletion or validate response headers. No external Okta/JumpCloud system is necessary for raw HTTP probes, but the prepared principal/client/user/group fixtures are necessary for the authenticated subset.

For future SCIM PATCH requests explicitly set `Content-Type: application/scim+json`: the harness otherwise defaults PATCH bodies to `application/merge-patch+json`. `errors_contain` targets the Vault errors array and should not be used for undocumented SCIM error envelopes. Dependencies skip FAIL, not FEATURE_ABSENT; status-only negatives and cleanup are not evidence that the feature is implemented. `/Me` 501 alone could also pass on an uninitialized target; enforce prerequisites and inspect positive discovery results.

`go run . --help` succeeded and exposes no validation-only flag. Python `yaml.safe_load_all` parsed all five YAML files successfully; field and same-file dependency checks passed: **20 cases total**. The actual Go loader was also exercised safely with `go run . --specs ../specs/scim --filter feature=__scim_validation_only_no_cases__ --format table`, which exited 0 and printed only the table header. Inspection of `loadSpecs` confirms strict YAML decoding and `checkSpec` run **before** feature filtering, so this validates every file while selecting zero HTTP requests. No live-server conformance run was attempted.
