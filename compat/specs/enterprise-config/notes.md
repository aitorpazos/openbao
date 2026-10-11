# Enterprise configuration conformance

## Sources and clean-room scope

All endpoint claims below come from these public documentation pages, each labeled **v2.x (latest)** when read:

- https://developer.hashicorp.com/vault/api-docs/system/config-group-policy-application — Get/Set group policy application information and introductory restrictions.
- https://developer.hashicorp.com/vault/api-docs/system/config-ui-custom-messages — List/Create/Read/Update/Delete custom message.
- https://developer.hashicorp.com/vault/api-docs/system/config-ui-login-default-auth — Create/List/Read/Update/Delete GUI default login/auth configuration.
- https://developer.hashicorp.com/vault/api-docs#http-status-codes — general 200/204 success, 400 invalid or missing input, 404 invalid path and empty LIST contracts.
- https://developer.hashicorp.com/vault/api-docs#error-response — `{errors: [string, ...]}` for errors.

Read each endpoint page in full. No Vault implementation/source was consulted. Existing local control-group and rotation-policy specs informed format; local harness code was inspected only for assertion/capture capabilities. No git commands were used.

## Prerequisites and safety

All three pages require an appropriate Enterprise license. Use a disposable, initialized, unsealed dev server with a root token and no concurrent users or suite runs. Group mode must initially be its documented default; root login configuration and custom-message collection must initially be absent/empty. Reserve `compat-ecfg-*`. The custom-message spec **leaves a server-generated-ID fixture**, requiring manual cleanup or destruction of the disposable target. Do not run on a shared server. No production auth methods, external services, or child namespaces are provisioned.

## Inventory

### Group-policy application

- Singleton `/sys/config/group-policy-application`: GET; POST and PUT to set. No DELETE documented.
- Root or administrative namespace only. Setting affects all groups in all namespaces, replicated between primary and secondaries.
- `group_policy_application_mode`: string enum `within_namespace_hierarchy` (default) or `any`. The page supplies payload examples but no formal parameter/requiredness table. Missing-field behavior is not asserted.
- Default confines policies to the namespace hierarchy; `any` allows group policies irrespective of namespace hierarchy. Page warns this setting applies to ACL policies, not Sentinel RGPs, for 1.15.0+, 1.14.4+, 1.13.8+.
- GET sample is the bare object `{group_policy_application_mode: within_namespace_hierarchy}`; write response unspecified.
- Coverage: initial GET, invalid enum/type (general 400), POST `any`, GET, PUT hierarchy, GET, unconditional POST default reset. Writes allow 200/204 per general contract.
- Gap: sample omits the HTTP envelope, as in the established control-group spec; object-only GET assertions avoid assuming top-level versus `data`. No cross-namespace authorization, actual policy evaluation, RGP, or replication tests on a bare dev server. Cleanup restores the required initial default, not arbitrary previous state.

### UI custom messages

- Collection `/sys/config/ui/custom-messages/`: LIST and POST. Item `/sys/config/ui/custom-messages/:id`: GET, POST update, DELETE. Samples also use the collection path without trailing slash, as these specs do.
- `id` is a required string path parameter for item methods, assigned by the server at creation; there is no documented client-selected ID/name.
- LIST filters: optional bool `active`, optional bool `authenticated`, optional string `type` (`banner` or `modal`). Omission includes both values/categories. Response `data.keys` is an array of IDs and `data.key_info` maps IDs to metadata (sample: title, type, authenticated, start_time, end_time).
- Create/update parameters: required strings `title`, base64 `message`, RFC3339 `start_time`; optional bool `authenticated` defaults true (post-login); optional string `type` defaults `banner` and permits `banner`/`modal`; optional `link` map with exactly one link-title-to-URL property; optional `options` map of UI properties; optional RFC3339 string `end_time`, omitted means no end. No defaults for link/options are explicitly specified.
- Namespace-scoped storage; at most 100 messages per namespace, excess returns an error (specific status/text not provided). Page does not impose a root/admin-only restriction. Pre-login messages can be retrieved anonymously; never put sensitive content in them.
- Create response sample: `data` with string `id`, bool `active`, string `start_time`, nullable `end_time`, string `type`, bool `authenticated`. Read adds title/message/link/options; update sample shows active/title/start_time/end_time/type/message/authenticated. Delete response unspecified.
- Coverage: three missing required fields, invalid type enum/base64/timestamps/bool type, successful minimal create with documented defaults, LIST and filtered LIST response structure. No timing-dependent `active` value asserted.
- **Harness blocker:** paths are literal; capture only supports auth tokens, not arbitrary `data.id`. Therefore successful item GET/update/DELETE cannot be linked to the created fixture without modifying the harness, forbidden by the specs-only task. No fabricated UUID, unsupported interpolation, or client-selected ID is used. These CRUD cases and update-invalid cases remain gaps. Default assertions run on CREATE instead of subsequent GET.
- Cleanup: on the disposable server, LIST, identify `key_info` entries titled `compat-ecfg-message` or `compat-ecfg-invalid`, and DELETE each corresponding ID. If a missing-title negative case was unexpectedly accepted, also remove that fixture from the initially empty collection. Alternatively destroy the dev target. Automated cleanup is not claimed.
- Further gaps: active/pre-login filters, anonymous retrieval route (not specified here), link/options round trips, boundary-time behavior, capacity limit, namespace isolation, missing/deleted item behavior. Empty LIST is avoided because the general API contract permits 404, which alone cannot establish feature support.
- Documentation inconsistencies: create payload has authenticated true but sample response false; sample times do not match payload; read message sample ends in a period and examples contain trailing commas. Assertions use parameter prose for defaults and do not copy inconsistent encoding/timestamp samples.

### Default GUI login configuration

- Collection `/sys/config/ui/login/default-auth`: LIST. Named `/sys/config/ui/login/default-auth/:name`: POST create/update, GET, DELETE.
- Root or administrative namespace only. One login configuration per target namespace; children can inherit their parent's configuration.
- Required path string `name`, letters/numbers/underscores/dashes.
- Optional string `namespace_path` defaults `""`; explicitly use `root` for the root namespace. Empty-string namespace semantics not stated.
- String `default_auth_type` is labeled required, but prose makes it conditional: provide it if backups are unset. `backup_auth_types` array defaults `[]`, must contain at least one method if the default is unset. Both accept github, jwt, ldap, oidc, okta, radius, saml, token, userpass. The prose's plural `default_auth_types` is inconsistent with the declared singular request key; specs use singular.
- Optional bool `disable_inheritance` defaults false; true prevents children inheriting the default and backup settings. Payload samples use a quoted boolean, but the parameter type is bool; specs send actual booleans.
- LIST `data.keys` names and `data.key_info` metadata (name/namespace_path/disable_inheritance). GET `data` contains backup_auth_types/default_auth_type/disable_inheritance/namespace_path. Write/delete response bodies unspecified.
- Coverage: missing both methods, invalid default/backup enums and inheritance type; minimal create; GET exact default backup list and inheritance flag; LIST membership/metadata; invalid update; valid inheritance update and exact GET; backup-only update and read of explicit values; unconditional delete. Invalid fixture cleanup accepts 200/204/404 because no resource should have been created; this cleanup is not a feature assertion.
- Gaps: unknown/deleted read statuses and defaults not specified; no guessed read-before-write expectations. No child namespace creation/inheritance evaluation, duplicate-namespace conflict status, name-length rules, auth-method UI rendering, or normalized empty default on backup-only update. No extra auth mount is necessary for the token-only configuration.

## Assertion policy and verification

400 assertions derive from documented requiredness/types/enums plus the general invalid-input contract; none asserts invented error wording or undocumented coercion. No special Enterprise-absent status is asserted. Method tables govern DELETE, since the message/login DELETE curl samples omit `--request DELETE`. Same-file dependencies only; cleanup requests have no dependencies. Harness dependent negative cases do not establish feature availability by themselves.

Validation commands:

```sh
uv run --with pyyaml python3 -c "import yaml,glob; [yaml.safe_load(open(f)) for f in glob.glob('compat/specs/enterprise-config/*.yaml')]"
cd compat/harness && go run . --target http://127.0.0.1:1 --token x --specs ../specs/enterprise-config --format table
```

Verification results: PyYAML parsing exited 0 for all three files. An additional check confirmed unique case IDs and earlier same-file dependencies: 8 group-policy cases, 11 custom-message cases, 14 login cases (33 total). The harness loaded all files and produced 33 ERROR verdicts, each `connect: connection refused`, with no loader errors; exit status 1 is expected for the deliberately unreachable target.

The unreachable-target run verifies loading/request construction only, not server conformance. No licensed Vault server was exercised.
