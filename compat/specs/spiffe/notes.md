# SPIFFE Enterprise conformance — public-documentation contract

## Provenance and scope

Specifications only; no implementation changes. Studied existing SCIM activation/client and rotation-policy CRUD specifications before authoring. Discovery used <https://developer.hashicorp.com/sitemap.xml>, its `sitemap-0.xml` and `server-sitemap.xml` children. Sitemaps have no Vault version label and are discovery aids, not behavioral authorities. Read the complete rendered main content of every page below, including examples and caveats. No HashiCorp Vault source, GitHub edit links, external SPIFFE/SPIRE source, or runtime Vault observations informed these contracts. No git commands were used.

Every listed documentation page displayed **v2.x (latest)**. This is a moving documentation label, not a claim about a specific released binary or the earliest version supporting SPIFFE. The historical version selector alone does not establish introduction dates.

| Public documentation URL | Displayed version | Establishes |
| --- | --- | --- |
| https://developer.hashicorp.com/vault/api-docs/auth/spiffe | v2.x (latest) | Auth config/read, four bundle profiles, deferred initial fetch and rollback, role CRUD/list, login inputs |
| https://developer.hashicorp.com/vault/docs/auth/spiffe | v2.x (latest) | Enterprise license; consuming X.509/JWT SVIDs; bundle formats; auth versus issuing secrets engine |
| https://developer.hashicorp.com/vault/docs/auth/spiffe/spiffe | v2.x (latest) | Mount type `spiffe`, single trust domain per mount, Authorization passthrough, audience allowlist, refresh behavior, TLS/proxy requirements |
| https://developer.hashicorp.com/vault/docs/auth/spiffe/spire-auth-vault | v2.x (latest) | End-to-end SPIRE setup and Vault auth integration; external node/workload attestation; HTTP login examples |
| https://developer.hashicorp.com/vault/api-docs/secret/spiffe | v2.x (latest) | Secrets config/read, role CRUD/list, mintjwt, public-key/discovery endpoint response examples |
| https://developer.hashicorp.com/vault/docs/secrets/spiffe | v2.x (latest) | Enterprise license; standalone JWT signer without external CA/SPIRE; X.509 issuance belongs to PKI |
| https://developer.hashicorp.com/vault/docs/secrets/spiffe/spiffe | v2.x (latest) | Mount type, valid JSON role-template example, configuration/mint workflow, mention of trust_bundle/web |
| https://developer.hashicorp.com/vault/docs/secrets/spiffe/mint-svid | v2.x (latest) | Root-token bare dev-server mint; `.data.token`; path-subject expansion; unauthenticated curl discovery/JWKS responses |
| https://developer.hashicorp.com/vault/api-docs/system/auth | v2.x (latest) | Auth mount enable/read/list/disable and tune; passthrough_request_headers; explicit `data` envelope in mount read/list examples |
| https://developer.hashicorp.com/vault/api-docs/system/mounts | v2.x (latest) | Secrets mount lifecycle/read/list/tune and explicit `data` envelope in read/list examples |
| https://developer.hashicorp.com/vault/api-docs | v2.x (latest) | `/v1/` prefix, token headers, unauthenticated login concept, general 200/204/400/404 contracts, errors array, empty LIST `404 {"errors":[]}` |

## Documented Vault operator API inventory

Paths below omit `/v1/` and use the documentation's default mount names; mounts may be placed at other paths. `secrets/spiffe` in conceptual guidance is not an invented literal API prefix.

### SPIFFE authentication plugin

- `POST /sys/auth/:path`, `GET /sys/auth`, `GET /sys/auth/:path`, `DELETE /sys/auth/:path`: ordinary auth mount management, using `type: spiffe`. `GET/POST /sys/auth/:path/tune` are the standard tuning API. JWT login needs `config.passthrough_request_headers: [Authorization]` on enable or the corresponding tuning parameter.
- `POST /auth/spiffe/config`: create/change trust-domain configuration; empty payload refreshes an existing cached bundle. Required common inputs are `trust_domain` (optional `spiffe://` prefix) and `profile`; optional `audience` defaults empty (denies all JWT-SVIDs) and `defer_bundle_fetch` defaults false.
  - `static`: required `bundle`, PEM X.509 certificate or SPIFFE JWKS.
  - `https_web_pem`: required HTTPS `endpoint_url`; optional `endpoint_root_ca_truststore_pem`, otherwise system roots.
  - `https_web_bundle`: required HTTPS `endpoint_url`; optional root truststore; JWKS bundle over HTTPS.
  - `https_spiffe_bundle`: required `endpoint_spiffe_id`, `endpoint_url`, and bootstrap JWKS `bundle`.
  - Remote initial fetch is synchronous unless deferred. Initial fetch failure returns an error and rolls back configuration changes; no exact HTTP status or wording is given for that failure.
- `GET /auth/spiffe/config`: configuration plus cached-bundle metadata. Example includes configuration version, cached bundle version/fetch time/refresh hint/sequence number. No separate status endpoint is documented.
- `POST /auth/spiffe/role/:name`: create/update; required `workload_id_patterns`, optional `display_name`, `alias_metadata`, and documented token controls (`token_ttl`, `token_max_ttl`, `token_policies`, deprecated `policies`, `token_bound_cidrs`, `token_explicit_max_ttl`, `token_no_default_policy`, `token_num_uses`, `token_period`, `token_type`). Patterns match the workload path with trust domain removed; terminal `*` and path-segment `+` are supported. Identical patterns across different roles are forbidden; overlapping patterns use policy priority matching.
- `GET/DELETE /auth/spiffe/role/:name` and `LIST /auth/spiffe/role`: role read/delete/list.
- `POST /auth/spiffe/login`: optional `role`; optional `type` in `auto`, `cert`, `jwt`, default `auto`. JWT SVID goes in `Authorization: Bearer ...`, not a fabricated body `jwt` field. X.509 SVID comes from the TLS client certificate. Role omission selects by configured patterns. Login response examples include an issued Vault token and SPIFFE metadata.

### SPIFFE secrets engine

- `POST /sys/mounts/:path`, `GET /sys/mounts`, `GET /sys/mounts/:path`, `DELETE /sys/mounts/:path`: ordinary secrets mount lifecycle with `type: spiffe`. Standard mount tune endpoints also exist.
- `POST /spiffe/config`: required `trust_domain`; `bundle_refresh_hint` default `1h`, cannot exceed `key_lifetime/10`; `key_lifetime` default `24h`; optional `jwt_issuer_url` defaults to cluster API address; `jwt_signing_algorithm` in RS256/RS384/RS512/ES256/ES384/ES512, default RS256; `jwt_oidc_compatibility_mode` default false, limits generated SPIFFEID length to 255 characters when enabled.
- `GET /spiffe/config`: current configuration.
- `POST /spiffe/role/:name`: required `template` (stringified JSON or base64), optional `ttl` default `5m`, `use_jti_claim` default false. Template must contain `sub`, as a full SPIFFE ID or path. Mint fails for an invalid expanded SPIFFE ID or mismatched trust domain. Engine controls `iss`, `aud`, `iat`, `exp`, optional `jti`, and provenance `vault.entity.id`; token lifespan is capped by the signing key lifespan.
- `GET/DELETE /spiffe/role/:name`, `LIST /spiffe/role`: role read/delete/list.
- `POST /spiffe/role/:name/mintjwt`: audience input; returns a JWT-SVID, with `.data.token` confirmed by the walkthrough.
- `GET /spiffe/.well-known/openid-configuration` and `GET /spiffe/.well-known/keys`: OIDC metadata and JWKS; walkthrough explicitly calls these without a token and shows raw top-level JSON, not a Vault `data` wrapper.
- `trust_bundle/web` is mentioned in the setup guide as serving public trust bundles for another Vault cluster, but the API reference does not give its HTTP method or complete request/response contract. Inventory only; no guessed executable case.

## Executable coverage and isolation

Each YAML owns its complete mount lifecycle; no inter-file ordering or dependencies are required. Run in root namespace on a disposable initialized/unsealed appropriately licensed Enterprise target (or compatible OpenBao target), with an administrative token. The secrets engine walkthrough explicitly supports a root-token dev server, so entity provisioning is unnecessary for the literal templates used here.

| File | Cases | Covered surface / reserved fixture |
| --- | ---: | --- |
| `10-auth-config.yaml` | 15 | Mount enable/read/list; required-field/profile/bundle negatives; deferred config create/read/update; disable. Reserves `auth/compat-spiffe-config/`. |
| `20-auth-roles.yaml` | 12 | Empty/nonempty role LIST; required patterns; wildcard-bearing create; duplicate-pattern rejection; read/update/delete/deleted read; disable. Reserves `auth/compat-spiffe-roles/`, roles `compat-role`, `compat-duplicate`, `compat-invalid`. |
| `30-secrets-config.yaml` | 11 | Mount lifecycle/read/list; required trust domain, algorithm and refresh-hint negatives; config create/read/update. Reserves `compat-spiffe-secrets-config/`. |
| `40-secrets-roles.yaml` | 14 | Required template/sub negatives; role CRUD/list; mint using path and full SPIFFE subjects. Reserves `compat-spiffe-secrets-roles/`, roles `compat-role`, `compat-invalid`. |
| `50-secrets-discovery.yaml` | 5 | Mount/config setup; unauthenticated discovery and JWKS structure; disable. Reserves `compat-spiffe-discovery/`. |

All reserved mounts MUST be absent before a run and exclusively owned by that run. Do not run concurrent copies or use production mounts. Final mount DELETEs have no dependencies, so cleanup is attempted after failures; if interrupted, an operator must disable the reserved mounts manually. Role DELETEs are also unconditional. No other mount or policy is changed. Unmounting the secrets fixtures removes stored signing keys; minted tokens have no external relying party in these tests.

Additional literal fixtures: trust domain `example.org`; auth audiences `vault`/empty list; mint audience `compat-relying-party`; workload subjects `/compat-workload` and `spiffe://example.org/compat-updated`; auth patterns `service1`, `team1/*`, `team2/+/service1`, updated to `service2`; arbitrary alias metadata `suite=compat-spiffe`. These are test choices, not required production values. No custom policy is created; the auth role uses `default`.

Deferred auth configuration uses `https://127.0.0.1:1`, an intentionally unavailable HTTPS endpoint on the **target**. Do not place a service there. The documented defer flag suppresses the initial fetch, not necessarily later periodic attempts; fixtures are promptly unmounted. Nothing requires an external SPIRE server. Positive static-bundle configuration could also be tested with a generated public CA/JWKS fixture, but this suite deliberately embeds neither synthetic key material nor abbreviated documentation certificates.

## Open questions, omissions, and interpretation limits

- No auth/config DELETE, config LIST, named trust-domain CRUD, dedicated SPIFFE health/status endpoint, or Vault `x509pop` endpoint appears in these sources. `x509pop` is a SPIRE node-attestor example, not a Vault API. SPIRE server/agent commands, node registration, Workload API calls, NGINX and Grafana setup are external integration guidance, not Vault operator endpoints.
- Real auth login, audience denial, role-selection priority, alias population, token policy behavior and SVID verification require a real signed JWT or client-certificate fixture. No successful login is claimed. Login failure status/order is not specified (configuration versus credential versus invalid type), so no bare-mount error is asserted as validation of login inputs.
- A successful auth role operation before config is not explicitly conditioned on configuration by the API docs. `20-auth-roles.yaml` therefore tests role management without a bundle. If live behavior demands config first, resolve the documentation gap rather than infer extra prerequisites from source.
- Config/role/list API examples largely omit the surrounding HTTP envelope. Those read/list cases intentionally assert only status and object, not invented `data.*` locations. Their breadth does **not** prove exact read-back values or returned role membership. System mount examples do explicitly show `data`, so mount type assertions are exact there.
- The secrets config read sample misspells `jwt_oidc_compability_mode`; requests consistently use documented `jwt_oidc_compatibility_mode`. No assertion preserves or silently corrects the ambiguous response spelling. Duration values in examples are strings; no undocumented type normalization is asserted.
- The auth `https_web_bundle`/`https_spiffe_bundle` endpoint parameter descriptions mention PEM although their profile prose says JWKS; the latter also contains a `JKWS` typo. No content-type or format conversion behavior is inferred.
- The short auth configuration guide omits the required bootstrap bundle in one HTTPS-SPIFFE example; the API and complete SPIRE walkthrough include it. No invalid-success case follows the abbreviated example.
- The API role-template example appears to omit enclosing JSON braces; setup/walkthrough show valid complete JSON objects and are the basis of literal templates here.
- API mint audience has an empty-string default, but the setup guide calls audience required. All mint cases supply it; missing/empty audience behavior is not asserted.
- Discovery API sample lists only RS256; walkthrough lists six supported algorithms. Assert RS256 membership, not exact equality. Key count, rotation schedule, signing-key modulus, issuer host and timestamps are deliberately not fixed. JWKS schema and mint string checks do not prove cryptographic validity, token claims or a nonempty key set.
- Remote fetch rollback/refresh timing, cached bundle metadata values, replication behavior, TLS/proxy identity forwarding, signing-key rotation, JWT verification, length/TTL enforcement and dynamic auth-to-mint flows are inventoried but outside these static no-server-setup cases.
- All negative 400 expectations derive from documented required/type/enumeration/constraint rules plus the general HTTP invalid-request contract. No exact error messages are invented. Deleted reads use the general missing-path 404 contract; empty role LIST uses the explicit generic empty-list contract. Write/delete success permits 200 or 204 per the general API warning guidance.

## Verification and harness findings

- PyYAML `safe_load` successfully parsed all five YAML files: **57 cases total**. The host Python lacked PyYAML; verification used an isolated temporary `uv` environment with PyYAML, without changing repository dependencies.
- `cd compat/harness && go run . --help` succeeded, exit 0.
- Strict load was exercised by `go run . --target http://127.0.0.1:1 --token x --specs ../specs/spiffe --format table`. All 57 cases reached request execution and printed `ERROR ... dial tcp 127.0.0.1:1: connect: connection refused`; exit 1 as expected. **No YAML, unknown-field, schema, or dependency loader errors occurred.** This is a real loader check, not live Vault/OpenBao conformance evidence.
- Harness dependencies skip only a prior `FAIL`, not `ERROR`, `SKIP` or `FEATURE_ABSENT`. Hence every case was attempted during the no-server check. Do not treat a negative 404 PASS or a skipped dependent check as proof that SPIFFE exists. Unsupported-plugin mount enable may produce FAIL rather than FEATURE_ABSENT depending on the target response. Cleanup remains unconditional.
- Harness supports `no_auth` (used for discovery), same-file dependencies, dotted exact keys and array membership. It has no general response-variable substitution or JWT decoding/signature verification; assertions do not pretend otherwise.
