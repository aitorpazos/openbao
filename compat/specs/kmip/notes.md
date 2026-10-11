# KMIP HTTP compatibility notes

## Sources and boundaries

All API claims below use these public documentation references, each viewed with version label **v2.x (latest)**. Section names identify the applicable sample/parameter table. No Vault implementation source was consulted.

- **[API]** https://developer.hashicorp.com/vault/api-docs/secret/kmip — v2.x (latest).
- **[Guide]** https://developer.hashicorp.com/vault/docs/secrets/kmip — v2.x (latest).
- **[HTTP]** https://developer.hashicorp.com/vault/api-docs — v2.x (latest), especially API operations, Error response, HTTP status codes.
- **[Mounts]** https://developer.hashicorp.com/vault/api-docs/system/mounts — v2.x (latest), Enable/Disable secrets engine.

The public API sidebar links KMIP to a single comprehensive page: configuration, CA, listener, scope, role, credential, template and experimental client endpoints are sections there, not separate CRUD subpages. The endpoint map below describes that page, not an assumed older release. The guide explicitly dates multiple-CA support to Vault 2.0; do not apply these latest-only additions to older releases without a separate versioned specification. [API; Guide]

These artifacts test the HTTP control plane only. The native KMIP **binary protocol (TTLV over TLS)** is explicitly OUT OF SCOPE for this JSON HTTP harness: no byte framing, TLS handshake, native protocol errors, managed-object lifecycle conformance or cryptographic behavior is asserted. The public guide describes a separate authenticated KMIP listener and KMIP 1.4 profiles; it is not a TTLV wire-format specification. The experimental HTTP/XML client API is a separate, documented HTTP surface, inventoried below but not silently enabled or exercised by these bare-mount cases. [Guide, KMIP conformance; API, Client API (alpha)]

## Conventions and response interpretation

Paths below are relative to `/v1/compat-kmip`; the published samples use `/v1/kmip`, and the mount name is configurable. Colon fields are required URL parameters, not required JSON keys. `LIST` also has the documented `GET ?list=true` equivalent. Samples generally show only `data`; do not assert absence of ordinary Vault response envelope fields. [API, introduction; HTTP, API operations]

`K` below means the sampled response `{"data":{"keys":["name"]}}`, with string array entries (credential lists contain serial-number strings). `—` means **no response sample documented**, not a claimed null body. Successful mutations without documented data accept 200 or 204, as the general API explicitly instructs. `C` means sampled `data` containing `ca_chain: string[]`, `certificate: string`, `serial_number: string`. Certificates in samples are PEM strings; their example contents and serials are not reproducible test fixtures. [API, respective Sample response sections; HTTP, HTTP status codes]

## Configuration and certificate authorities

| Method/path | Required fields | Optional fields | Documented response sample |
|---|---|---|---|
| POST `/config` | None | Config fields below | — |
| GET `/config` | None | None documented | `data` with every config field listed below |
| GET `/ca` | None | None documented | `data.ca_pem: string`, concatenated PEM certificates |
| POST `/ca/:name/generate` | URL `name`; body `key_type`, `key_bits` | `ttl` | C |
| POST `/ca/:name/import` | URL `name`; `ca_pem`; one scope selector and one role selector | Selector alternatives below | `data.ca_chain: string[]`, `certificate: string`, `imported: true`, `scope_field: "OU"`, `role_field: "CN"` |
| GET `/ca/:name` | URL `name` | None documented | C plus `key_type: "rsa"`, `key_bits: 2048`, `imported: false` |
| POST `/ca/:name` | URL `name` | `scope_name`, `scope_field`, `role_name`, `role_field` | — |
| LIST `/ca` | None | None documented | K |
| DELETE `/ca/:name` | URL `name` | None documented | — |

Source for every row: [API, Configuration management and Certificate Authority management, corresponding method/parameter/sample sections].

Config fields, types and documented defaults:

- `listen_addrs`: list or comma-separated string, default `["127.0.0.1:5696"]`; all addresses are listened on. The field is **not `listen_address`**.
- `server_hostnames`: list or string, default `["localhost"]`; DNS SANs, first hostname used as CN.
- `server_ips`: list or string, default `[]`; IP SANs; IPv4 and IPv6 localhost automatically included.
- `tls_ca_key_type`: string, `ec`, allowed `rsa` or `ec`; `tls_ca_key_bits`: integer, `521`, valid sizes depend on type.
- `tls_min_version`: string, `tls12`. The config payload example uses `tls11`; the config field description does not enumerate supported versions. Do not transplant the named-listener version enum into this legacy field without evidence.
- `default_tls_client_key_type`: string, `ec`, allowed `rsa` or `ec`; `default_tls_client_key_bits`: integer, `521`, type-dependent valid sizes.
- `default_tls_client_ttl`: integer seconds or duration string, default `86400` / `24h`.

The GET sample returns the three list fields as arrays, key bits and TTL as numbers, and type/version fields as strings. Config has no documented DELETE operation. Writing config generates the legacy CA and starts the KMIP server; changes to non-client settings restart an already-running server. GET `/ca` explicitly errors before any config write. No endpoint-specific status/error sample is supplied for that error. [API, Write config, Read config, Read CA]

Named CA generation accepts `key_type` `rsa` or `ec`; `key_bits` is required with RSA values `2048,3072,4096` and EC values `224,256,384,521`. Optional `ttl` defaults to `365d` and accepts integer seconds or duration string (sample `8760h`). Import requires PEM `ca_pem`, exactly one of `scope_name` (fixed string) / `scope_field` (certificate field), and exactly one of `role_name` / `role_field`. Field selectors allow `CN`, `O`, `OU`, `UID`. Imported CAs verify clients only: they cannot generate client/server certificates. Update only supports imported CA scope/role settings; generated CAs cannot be updated. In-use CAs cannot be deleted while referenced by a role/listener. No alternate fixed-selector import response sample or imported-CA read sample is given, so do not assume an exhaustive schema from the generated-CA sample. [API, Generate CA through Delete CA]

## Named listeners

| Method/path | Required fields | Optional fields | Documented response sample |
|---|---|---|---|
| POST `/listener/:name` | URL `name`; body `ca`, `address` | Fields below | L |
| GET `/listener/:name` | URL `name` | None documented | L |
| LIST `/listener` | None | None documented | K |
| DELETE `/listener/:name` | URL `name` | None documented | —; stops/removes listener |

`L` is `data` with `ca: string`, `address: string`, `server_hostnames: string[]`, `server_ips: string[]`, `additional_client_cas: string[]`, `also_use_legacy_ca: boolean`, `tls_min_version: string`, `tls_max_version: string`, `tls_cipher_suites: string`. Write/read samples show empty strings for maximum version and cipher suites. `ca` must name a generated CA; `address` is host:port. Optional fields: `server_hostnames` list/string default `[]`; `server_ips` list/string default `["127.0.0.1","::1"]`; `additional_client_cas` list/string default `[]`; `also_use_legacy_ca` boolean default false; `tls_min_version` string default `tls12`, allows `tls12|tls13`; `tls_max_version` optional string, same enum; `tls_cipher_suites` comma-separated string, TLS 1.2 only. [API, Listener management, all four sections and samples]

## Scopes and roles

| Method/path | Required fields | Optional fields | Documented response sample |
|---|---|---|---|
| POST `/scope/:scope` | URL `scope` | No body fields documented | — |
| LIST `/scope` | None | None documented | K |
| DELETE `/scope/:scope` | URL `scope` | Query `force` boolean, default false | — |
| POST `/scope/:scope/role/:role` | URL `scope`, `role` | Role fields below | — |
| GET `/scope/:scope/role/:role` | URL `scope`, `role` | None documented | `data` operation booleans below |
| LIST `/scope/:scope/role` | URL `scope` | None documented | K |
| DELETE `/scope/:scope/role/:role` | URL `scope`, `role` | None documented | — |

Scope POST creates a named scope; a separate scope GET or update payload is not documented. Scope deletion requires `force` when managed objects exist. **No `template` field is documented or required on a role.** Role creation has no required JSON field; a body-less scope creation is explicitly shown. The cases use a role with `operation_get:true`, not an invented missing-template negative. [API, Write/List/Delete scope, Write/Read/List/Delete role]

Optional role fields: `ca` string (omitted means legacy CA), `tls_client_key_type` string (`rsa|ec`), `tls_client_key_bits` integer (type-dependent), `tls_client_ttl` integer seconds or duration string; TLS settings override engine defaults. `operation_none` and `operation_all` are booleans default false, each mutually exclusive with every other `operation_` parameter. The other API-listed booleans default false: `operation_activate`, `operation_add_attribute`, `operation_create`, `operation_decrypt`, `operation_destroy`, `operation_discover_versions`, `operation_encrypt`, `operation_get`, `operation_get_attribute_list`, `operation_get_attributes`, `operation_import`, `operation_locate`, `operation_query`, `operation_register`, `operation_rekey`, `operation_revoke`. The Read role sample contains these individual fields set to true, not the CA/TLS fields or pseudo-operations. No exhaustive role read schema is inferred. [API, Write role and Read role samples]

Documentation discrepancy: the guide additionally lists `operation_create_keypair`, `operation_delete_attribute`, `operation_mac`, `operation_mac_verify`, `operation_modify_attribute`, `operation_rekey_keypair`, `operation_sign`, `operation_signature_verify`, `operation_rng_seed`, `operation_rng_retrieve`. They are documented supported operations, but absent from the API page's parameter list/read sample; no default/read shape assertions for these additions are made here. The guide also says updating a pseudo-operation role with individual operations overwrites the prior pseudo-operation. [Guide, Supported KMIP operations; API, Write role]

## Client credentials

Let `R = /scope/:scope/role/:role`; both URL fields are required for every row.

| Method/path | Additional required fields | Optional fields | Documented response sample |
|---|---|---|---|
| POST `R/credential/generate` | None | `format` | C plus `private_key: string` |
| POST `R/credential/sign` | PEM CSR required by narrative, but `csr` is not tagged `<required>` in parameter list | `format`; `csr: string` input | C, no private key |
| GET `R/credential/lookup` | Query `serial_number: string` | Query `format` | C, no private key |
| LIST `R/credential` | None | None documented | K (serial strings) |
| POST `R/credential/revoke` | Exactly one of `serial_number` or `certificate` | Selector alternatives | — |

`format` defaults to `pem_bundle`, allows `pem`, `pem_bundle`, `der`. The page supplies PEM examples, not a distinct DER sample; do not guess DER/base64 encoding or exact bundle contents. Revoke selectors are strings default empty; `certificate` must be PEM. Lookup's field description says “to revoke” even though the endpoint narrative is a read operation; treat this as an apparent documentation typo, not a second revoke endpoint. Private keys can only be obtained at generation. CSR key type and size must match the role; signing does not export the client's private key. Generated certificates tie scope/role identifiers to KMIP authorization. There is no documented credential update or HTTP DELETE endpoint: revocation uses POST. Missing scope/role are missing URL segments, **not missing required body fields**. [API, Client credentials, all endpoint parameters and samples; Guide, Client certificate generation/signing]

## Templates and experimental HTTP client

The latest page does document templates, but **not template CRUD**: built-in XML templates can only be listed/read. They are not role configuration objects. This API requires server experiment `kmip.client_api.alpha1` (`vault server -experiment kmip.client_api.alpha1`, or the documented configuration experiment option). The bare-engine YAML deliberately excludes these gated endpoints. [API, Client API (alpha)]

| Method/path | Required fields | Optional fields | Documented response sample |
|---|---|---|---|
| LIST `/template` | None | None documented | K |
| GET `/template/:name` | URL `name` | None documented | `data.template: string`, `data.parameters: string[]` |
| POST `/scope/:scope/role/:role/client[/:operations]` | URL scope/role; every batch item's operation must be specified | Fields below | `data.response: string` containing KMIP response XML |

Client request fields: `operations` string default empty, slash-separated operation names; `template` string default empty, a built-in name or raw XML with `PARAMETER_<name>` placeholders; `params` map<string,string>. Omitting `template` selects a built-in based on the operations URL segment. Named top-level replacements equivalent to keys in `params`: `algorithm`, `attr_name`, `attr_type`, `attr_value`, `block_cipher_mode`, `data`, `iv_counter_nonce`, `length`, `name`, `padding_method`, `revocation_reason_code`, `unique_identifier`, `usage_mask`. The API does not give a universal per-operation required-field schema; inspect the chosen template's placeholders. GET `template/create` samples parameters `["algorithm","length","name","usage_mask"]`. No template POST/DELETE is documented. [API, List templates, Read template, Execute KMIP request]

The LIST sample contains `addattribute`, `create`, `destroy`, `get`, `getattribute`, `getattributelist`, `getattributes`, `locate`, `locate_addattribute`, `locate_by_name`, `locate_decrypt`, `locate_encrypt`, `locate_get`, `locate_getattribute`, `locate_getattributelist`, `locate_getattributes`, `locate_modifyattribute`, `locate_revoke`, `locate_revoke_destroy`, `modifyattribute`, `revoke`, `revoke_destroy`. The prose built-in table omits standalone `getattributes` despite the LIST sample including it; prefer runtime discovery rather than a frozen exact list assertion. [API, List templates sample and Built-in templates]

## Listener ownership and operator configuration

Operators select legacy `listen_addrs`, named listener `address`, SANs, key types/sizes, client TTLs, CA references/trust sets and named-listener TLS versions/ciphers through HTTP. Certificate generation, server certificate issuance, listener start/restart, scope/role identifiers in generated certificates and permission evaluation are engine responsibilities, not separately documented HTTP endpoints. Legacy CA creation is automatic and cannot import an external replacement; imported named CAs are client-verification-only. Generated CAs/client certificates use entropy augmentation if enabled. [API, Write config, Generate/Import CA, Write listener, Generate credential; Guide, KMIP Certificate Authorities, Client certificate generation]

The KMIP listener is separate from Vault's HTTP listener; default port 5696 can be changed, including for multiple mounts. All servers in a cluster use the same KMIP listener configuration; native clients can reach the active or performance standbys using TLS client certificates. A layer-4 TCP load balancer should support long-lived connections; forwarding to the primary happens when necessary. Named listeners may coexist with or replace legacy configuration. Neither native listener reachability nor cluster forwarding is asserted by a successful HTTP configuration response. [Guide, introduction and Named Listeners]

There is wording tension: the setup guide says configuration can be left unwritten to use defaults, while the API says writing config generates CA/starts listening and reading the CA before a config write errors. The bare-mount CA negative follows the explicit API rule; default listener activation timing needs live verification rather than a guessed contract. [Guide, Setup; API, Write config and Read CA]

## Negative cases, fixtures and verification limits

The YAML files are independently mount-scoped scenarios (a deliberate multi-endpoint exception to the README's one-endpoint-per-file preference so setup/cleanup do not depend on cross-file state). Each first case POSTs `/v1/sys/mounts/compat-kmip` with `{type: kmip}`; each ends with cleanup DELETEs and unmount. Run files **serially**, with that mount initially absent, against a disposable authorized target. Cleanup depends on successful ownership-establishing setup, not on every intervening assertion. No source files or other agents' changes are touched. Mount API behavior: [Mounts].

Coverage: role pseudo-operation exclusions; required named-CA generation/import fields and invalid type/size/PEM; missing listener CA/address; missing credential lookup serial; revoke selector exclusion; missing CSR; invalid generate format; legacy CA before config. The positive controls exercise scope creation/list and role creation/read/list, proving that absence of a role template or scope body field is not itself an error. Constraints come from the corresponding [API] sections above.

All negative cases assert HTTP 400 and `{"errors":[string,...]}` structure using the general invalid/missing-data definition, **not an endpoint-specific documented KMIP 400 sample**. The KMIP page supplies no literal error messages; there are no invented regexes or golden messages. Bare-mount credential tests may encounter missing-CA validation before the invalid field; the missing-address listener case also has no real CA, and the both-selectors revoke input includes malformed PEM. These are rejection tests, not claims about validation order or isolated diagnostic reasons. Missing CSR is narrative-derived, unlike the explicitly required CA generation fields. Treat exact status for the unconfigured-CA error as a general-HTTP-derived expectation awaiting live confirmation. [HTTP, Error response and HTTP status codes; API, relevant parameter constraints]

Deferred: successful config writes/listener lifecycle (bind network sockets); isolated import-selector exclusions with a real valid CA fixture; generated/imported CA positive CRUD; credential generate/sign/lookup/revoke positive flows with captured serial/certificate; unsupported-path/method assertions not promised by KMIP docs; permission/license errors; all experimental client/template execution; binary KMIP. The HTTP harness v1 has no response-variable capture, so generated serials cannot be safely hard-coded for a later lookup/revoke. CA/credential positive sample shapes remain mapped above even though these cases do not execute them. This is an intentional coverage boundary, not a claim those APIs are unsupported.

Validation: write-time YAML lint succeeded for each file; case IDs/dependencies and counts were inspected using available file tools. No licensed Vault/OpenBao test endpoint or execution-shell tool was supplied to this subagent, so the harness was **not run**, and no conformance PASS results are claimed.
