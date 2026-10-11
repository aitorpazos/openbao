# Agentic IAM conformance scope

Specs only; no implementation or Vault source was consulted. Public documentation
was fetched live while authoring. Every page below displayed **v2.x (latest)**;
this is a rolling documentation label, not a tested server release. The two API
references explicitly require **Vault Enterprise 2.1.0 or later**, with an
appropriate Enterprise license.

## Sources and claim map

All URLs below use https://developer.hashicorp.com:

- https://developer.hashicorp.com/vault/api-docs/secret/agent-registry
  — v2.x (latest). Registry methods, fields, required existing entity, unique
  display names, one registration per entity per namespace, root ceiling-policy
  prohibition, default-policy opt-out, optional authorization details.
- https://developer.hashicorp.com/vault/ai/iam/concepts/agent-registry
  — v2.x (latest). Ceiling/baseline intersection and automatic `default` plus
  `default-ceiling` on create/update unless `no_default_ceiling_policy=true`.
- https://developer.hashicorp.com/vault/ai/iam/reference/agent-reg-summary
  — v2.x (latest). Registry endpoint inventory; API reference controls schemas.
- https://developer.hashicorp.com/vault/api-docs/system/config-oauth-resource-server
  — v2.x (latest). Profile methods, fields, static/JWKS exclusivity, issuer
  normalization/uniqueness/immutability, unique-ID-claim immutability, partial
  update preservation, automatic old-mode clearing, idempotent delete, examples.
- https://developer.hashicorp.com/vault/ai/iam/concepts/oauth-profiles
  — v2.x (latest). Namespace isolation with no inheritance; namespace-local
  issuer uniqueness; direct versus delegated registration requirements.
- https://developer.hashicorp.com/vault/ai/iam/reference/oauth-server-summary
  — v2.x (latest). Summary names collection and name-addressed operations; the
  fuller API reference additionally documents the ID-addressed read.
- https://developer.hashicorp.com/vault/ai/iam
  — v2.x (latest). Agentic IAM overview and ACL/RAR intersection.
- https://developer.hashicorp.com/vault/ai/iam/concepts/rar
  — v2.x (latest). OAuth JWT authentication on every request without a separate
  login step. No agent-login endpoint is invented here.
- https://developer.hashicorp.com/vault/api-docs#http-status-codes and
  https://developer.hashicorp.com/vault/api-docs#error-response
  — v2.x (latest). Generic 400 for invalid/missing data, 404 for unknown paths
  and empty LIST, 200/204 success compatibility, `errors` array of strings.
  No endpoint-specific error text is asserted. Unknown-object 404 assertions
  use this generic contract, not an endpoint-specific missing-record example.

## Documented surface and coverage

Paths below omit the transport `/v1` prefix used in YAML.

| Family | Method/path | Coverage |
| --- | --- | --- |
| Registry | POST `/agent-registry/register` | Missing fields/nonexistent entity; creation and update using `id` fixture-gated |
| Registry | GET/POST/DELETE `/agent-registry/registration/id/:id` | Missing-ID read; positive CRUD fixture-gated |
| Registry | GET/POST/DELETE `/agent-registry/registration/display-name/:display_name` | Missing-name read and unconditional cleanup; positive CRUD fixture-gated |
| Registry | GET `/agent-registry/registration/entity-id/:entity_id` | Missing-entity read; positive lookup fixture-gated |
| Registry | LIST and GET `?list=true` on `/agent-registry/registration/id` and `/agent-registry/registration/display-name` | Empty namespace, status-only `[200,404]` |
| OAuth | LIST and GET `?list=true` on `/sys/config/oauth-resource-server` | Empty and populated collections |
| OAuth | POST `/sys/config/oauth-resource-server/:name` | Valid static RSA profile; missing issuer/static keys/JWKS URI, invalid PEM/type, both exclusivity directions, issuer normalization and duplicate rejection, immutable-field rejection and unchanged-value acceptance, partial updates |
| OAuth | GET `/sys/config/oauth-resource-server/:name` | Static key/default readback, normalized issuer, updated fields and preservation of omitted fields, unknown/deleted reads |
| OAuth | DELETE `/sys/config/oauth-resource-server/:name` | Delete twice (idempotence), unconditional final cleanup |
| OAuth | GET `/sys/config/oauth-resource-server/id/:config_id` | Missing-ID read; positive read fixture-gated |

Registry fields are `id`, `display_name`, `entity_id`, `description`, `owner`,
`ceiling_policies`, `no_default_ceiling_policy`, and
`optional_authorization_details`. Registration requires an existing entity; each
entity has at most one registration per namespace. Display names are unique
within a namespace. `root` cannot be a ceiling policy. Default ceilings are added
unless opted out. These successful governance behaviors require entity fixtures;
no false proof of root rejection using a nonexistent entity is included.

Profile create/update fields documented by the API are `issuer_id`, `use_jwks`,
`jwks_uri`, `jwks_ca_pem`, `public_keys` (objects containing unique `key_id` and
`pem`), `audiences`, `no_default_policy`, `optional_authorization_details`,
`user_claim`, `supported_algorithms`, `jwt_type`, `clock_skew_leeway`, `enabled`,
`unique_id_claim`, and `actor_claim`; `name` is the path parameter. Static mode
needs keys, JWKS mode needs a URI, and the two modes exclude each other's key
configuration. `jwt_type` must be `access_token`. `issuer_id` is lowercased and
trailing slashes trimmed, unique per namespace, and immutable. `unique_id_claim`
is also immutable: updates may omit it or repeat its stored value, not change it.
The specs exercise these documented update rules, not an invented PUT/PATCH API.

## Execution and fixture contract

Use a disposable initialized/unsealed target, appropriate Enterprise license,
and an administrative token, in the root namespace. Initially both collections
must be empty. Names and issuers prefixed `compat-agentic-` are exclusively
reserved for this suite; no concurrent runs or preexisting objects under these
names. The all-zero UUID is an explicitly nonexistent entity, registration, and
profile config ID, not a fabricated positive fixture. `compat-agentic-unknown`
must not exist. Cleanup deletes only reserved names and runs without dependencies.

The static RSA-2048 public key was generated locally with OpenSSL. The private key
was piped into public-key extraction and is not retained. This is configuration
validation, not token issuance; no signing key or external IdP is needed. The
mutual-exclusion negatives reference `https://127.0.0.1:1/compat-agentic-jwks`, an
unavailable endpoint on the TARGET, only alongside invalid conflicting key mode
settings. There is no successful JWKS retrieval assertion; implementations that
fetch before validating may attempt that local connection.

A future fixture-aware suite must arrange real identity entities and discover
IDs from actual target responses, never assume UUIDs from documentation examples.
Provide two entities, two registration display names in the reserved pattern,
and real registration IDs. This enables create/read/update/delete by both lookup
forms, update through `/register` with `id`, entity-ID lookup, nonempty listings,
duplicate entity/name rejection, root ceiling rejection, automatic defaults and
opt-out, metadata updates, and optional-RAR configuration round trips. Cleanup
registrations before their entity fixtures. Fixture lifecycle and entity APIs are
not implemented by these specs.

For positive OAuth ID lookup, create a reserved profile, GET it by name, obtain
`data.config_id`, then read that ID. **Correction to prior research:** live docs
say successful creation returns **204 with no body**, not an ID-bearing creation
response (warnings may produce a response). Read examples expose `data.config_id`.
The ID-read example's request UUID differs from its example response UUID; neither
is used as a real fixture. Current harness cannot express this discovery flow.
No placeholder substitutions or unsupported capture fields are embedded in YAML.

Namespace-isolation fixtures require a disposable child namespace and a token
with suitable access. Create independent same-issuer profiles in root and child;
verify no visibility/inheritance and namespace-local collision enforcement, then
clean up each independently. Those cases are deferred rather than silently
assuming an existing child namespace or creating one outside this suite's scope.

## Deliberate gaps and harness limitations

- `compat/harness/main.go` captures only `auth.client_token` through
  `capture_token`/`use_captured_token`; it has no arbitrary response-field capture,
  path interpolation, or entity/config-ID propagation. No harness changes made.
- Same-file dependencies skip only `FAIL`, not `ERROR`, `FEATURE_ABSENT`, or
  transitive `SKIP`. All cases therefore still execute against the deliberately
  unreachable verification target. A passing expected-404 or 400 alone is not
  evidence of feature availability. Empty collections deliberately have no body
  schema assertions and allow 200/404.
- Positive JWKS fetch, custom CA validation, key refresh and mode-switch clearing
  require a controlled JWKS fixture. No external availability dependency is added.
  Duplicate key IDs and individual key-object validation are documented but not
  isolated here. Positive static configuration is fully executable independently
  of an IdP; it is not conflated with successful JWT authentication.
- Read samples include `data` and public keys, supporting explicit readback.
  They omit `unique_id_claim` and `actor_claim`; both are documented write fields,
  but no invented readback location is asserted for them. Unique-ID immutability
  is tested with changed and unchanged writes. Actor-claim resolution is deferred.
- Authentication, entity aliases, RAR enforcement, actor/subject delegation,
  baseline/ceiling policy intersections, token-header limits, and enabled-profile
  authentication effects require real JWT/identity fixtures and are not covered.
  Neither an agent login API nor a separate token minting API is specified.
- Registry deletion of an absent object is not explicitly guaranteed idempotent;
  cleanup permits 200/204/404. OAuth absent deletion explicitly succeeds, so
  its repeated-delete cases require 200/204.
- Schema parsing and unreachable-target execution verify harness compatibility,
  not conformance of a live Vault Enterprise server. No licensed server was used.
