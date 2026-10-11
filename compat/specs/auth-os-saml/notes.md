# SAML, SCEP, and OS local-account conformance

## Provenance and scope

Clean-room specs derived from public documentation only. No HashiCorp Vault source was read. Each source below displayed **v2.x (latest)**; that is the source version label, not a guarantee that every earlier release implements these interfaces.

| Source URL | Sections / use | Version |
| --- | --- | --- |
| https://developer.hashicorp.com/vault/api-docs/auth/saml | Entire page: config, role CRUD, SSO URL, callback, token | v2.x (latest) |
| https://developer.hashicorp.com/vault/api-docs/auth/scep | Entire page: role CRUD and delegated login | v2.x (latest) |
| https://developer.hashicorp.com/vault/api-docs/secret/os | Entire page: config, hosts, accounts, credentials, versions, recovery | v2.x (latest) |
| https://developer.hashicorp.com/vault/docs/auth/scep | Roles configure authentication; direct login is unsupported | v2.x (latest) |
| https://developer.hashicorp.com/vault/api-docs/secret/pki/issuance#scep-certificate-issuance | SCEP protocol paths and PKI SCEP configuration | v2.x (latest) |
| https://developer.hashicorp.com/vault/docs/secrets/pki/scep | PKI/auth delegation, batch tokens, protocol path aliases, RSA issuers, client prerequisites | v2.x (latest) |
| https://developer.hashicorp.com/vault/docs/secrets/os | Plugin registration name, SSH behavior and deferred verification, recovery | v2.x (latest) |
| https://developer.hashicorp.com/vault/api-docs/system/auth | Enable/disable auth mounts | v2.x (latest) |
| https://developer.hashicorp.com/vault/api-docs/system/mounts | Enable/disable secrets mounts, delegated accessors | v2.x (latest) |
| https://developer.hashicorp.com/vault/api-docs#http-status-codes | Success 200/204, invalid input 400, empty LIST 404 | v2.x (latest) |
| https://developer.hashicorp.com/vault/api-docs#error-response | JSON errors array; no exact message assertions | v2.x (latest) |

The PKI API index at https://developer.hashicorp.com/vault/api-docs/secret/pki (v2.x (latest)) was used to locate the separate issuance page. The two requested example specs were studied before authoring. Only new files under this directory were created; no Git commands were used.

## Execution and safety

Run only against a disposable initialized, unsealed, appropriately licensed Enterprise server with an administrative/root token. The OS plugin must already be installed and registered as **vault-plugin-secrets-os**, per its overview; `type: os` is not assumed. Registration/download is outside these specs.

These mount names must be **absent before execution**, with no concurrent users or runs:

- `auth/compat-saml-api/`
- `auth/compat-scep-api/`
- `compat-scep-pki/`
- `compat-os-api/`

Each file owns its fixtures and same-file dependencies. Unconditional final mount deletion is a best-effort cleanup even after failed setup; it does not restore pre-existing state. Never point these specs at existing mounts of those names. `compat-*-policy` names are inert token policy references; no ACL policies are installed or modified. Passwords and challenges are explicitly public throwaway fixture values.

## Implemented surfaces

### `00-saml.yaml` — 16 cases

- Mount lifecycle; configuration missing-required-fields negative; static IdP configuration create/read/PUT-update/read.
- Locally generated public RSA certificate embedded as a test input; private key discarded. Verified with OpenSSL. No IdP metadata server or network fetch is needed for the static configuration fixture.
- Subject/attribute constraints, groups attribute, token policies/type/TTL; role create/read/update/list/delete.
- Invalid subject matcher, missing SSO challenge, and missing token request fields.

**Documentation corrections and gaps:** the API documents `entity_id`, `idp_entity_id`, `idp_sso_url`, `idp_cert`, `idp_metadata_url`, and `acs_urls`; it does **not** document `allowed_redirect_uris` on SAML roles. The metadata URL parameter text refers to `idp_issuer`, whereas the actual parameter list names `idp_entity_id`; the latter is used. The sample role payload uses undocumented `ttl`; these specs use documented `token_ttl`. The configuration response example contains malformed JSON punctuation; only documented field values are asserted. The role list example is a bare array without an envelope, so the list case asserts success only. No config DELETE API is documented.

**Fixture-gated browser login:** a real IdP must be configured for the matching SP entity ID and ACS URL. Start with `POST /auth/<mount>/sso_service_url`, supplying a base64 SHA-256 client challenge (at least 44 bytes), role, client type, and configured ACS URL. Follow the returned SSO URL through IdP authentication; the IdP posts signed `SAMLResponse` and `RelayState` to `/callback`. Complete `/token` with the original verifier and returned poll ID. Signature/subject/attribute enforcement and token issuance require that fixture and flow-state handling; they are not claimed by the configuration suite. No invented `/login` endpoint, callback response status, or browser automation is asserted. Successful metadata-URL fetching is also fixture-gated. The negative requests are sent with the harness token and do not establish unauthenticated-access behavior.

### `10-scep.yaml` — 20 cases

- Auth mount lifecycle; required/enum validation; static-challenge role create/read/update/list/delete; Intune role create/list/delete.
- Separate PKI mount lifecycle; documented `/config/scep` write/read/update/read while disabled; invalid digest algorithm negative.
- Explicit batch tokens, display name and policy/TTL round trips. Role responses follow the documented `data` envelope.

**Important separation:** the SCEP auth plugin has role-based configuration, not a documented `/auth/scep/config`. `/auth/<mount>/login` is for PKI-delegated authentication, not ordinary direct client login. Protocol traffic belongs to a **PKI** mount, not the auth mount. PKI API documentation lists `/pki/scep` and `/pki/roles/:role/scep`; the operation guide additionally shows ACL paths ending in **`/scep/pkiclient.exe`**, not the suggested extensionless `/scep/pkiclient`.

**Protocol gap, not a harness query-string limitation:** the harness can send GET paths containing `?operation=GetCACaps`, `?operation=GetCACert`, or `?operation=PKIOperation`; SAML's list case already exercises a query string. However, the reviewed permitted docs do not specify those operations' complete request/response/error contracts. `GetCACert` is mentioned in the PKI configuration description, but an exact capabilities body, malformed-PKIOperation status, and operation-specific schema are not supplied. Consequently this suite does **not** manufacture protocol negative/shape expectations or an extensionless endpoint. Such tests remain a documented coverage gap. The docs link an RFC, but it was not used because research is restricted to developer.hashicorp.com.

**Fixture-gated protocol enrollment:** requires an RSA-backed PKI issuer, a suitable PKI role/path policy, auth accessor in PKI `delegated_auth_accessors`, matching `authenticators` config, ACL grants, and a SCEP client. Intune additionally requires Azure/Intune configuration. Configuration is intentionally kept disabled here to avoid relying on undocumented behavior for an enabled but incomplete PKI setup. No dynamic accessor substitution is invented. There is no documented DELETE for PKI SCEP config; mount removal performs cleanup. The API guide and overview describe relevant issuer/chain settings, but these tests do not claim cryptographic enrollment conformance.

### `20-os.yaml` — 27 cases

- Mount lifecycle with the documented external-plugin name; global config create/read/update/read.
- Hosts and accounts create/read/update/list/delete, including whole-map metadata replacement and missing required fields.
- Credential reads, credential-version response shape, missing reset password negative, stored-password reset/read-back, empty-list checks.

**No remote OS execution:** the host points to target-local `127.0.0.1:1`; it has the public host key from the API example. TOFU is false. Accounts set `verify_connection: false`; host and account set `rotation_period: 0` and `disable_automated_rotation: true`. The overview expressly says disabling connection verification defers the first SSH connection until rotation. The suite never calls `/rotate`. Reset only changes the stored credential and creates a version, not the remote host password. Thus these storage cases can run without a RHEL target, but not without the licensed registered plugin.

**Documentation corrections and gaps:** this is a host/account API, not a roles API. Password-policy references exist on hosts/accounts (account overrides host); policy creation/enforcement is not exercised because no rotation occurs. No role-policy endpoints or DELETE global config are invented. The reset table uses `/hosts/:host_ref/accounts/:name/reset`, while its curl example accidentally uses singular `account`; the table and overview's plural path are followed. The prose says a zero rotation period disables rotation despite also describing a minimum nonzero period; explicit zero plus the disable flag is used. Initial version numbering, nullable/unset TTL, and rotation timestamps are not asserted.

Restore (`POST .../versions/:version_id/restore`) is documented and local-only, but requires selecting a known returned version. It is recorded rather than hard-coding an unspecified initial version number. Real manual/scheduled/self/parent rotations, host-key mismatch, SSH failures, password-policy enforcement, forced host deletion with accounts, and retention behavior remain outside this suite. Rotation fixtures require a supported RHEL system, SSH and the documented passwd/chpasswd/sudo capabilities—not merely distribution of a key.

## Verification performed

From the repository root:

```sh
uv run --with pyyaml python3 -c "import yaml,glob; [yaml.safe_load(open(f)) for f in glob.glob('compat/specs/auth-os-saml/*.yaml')]"
```

Result: exit 0, all three YAML documents parsed.

From `compat/harness`:

```sh
go run . --target http://127.0.0.1:1 --token x --specs ../specs/auth-os-saml --format table
```

Result: **63 ERROR rows, all connection refused; no loader errors**. The command exited 1 as expected. This verifies loading, schema/field acceptance and request construction, not Enterprise runtime compatibility. No live Vault Enterprise server was exercised. The embedded SAML certificate also parsed successfully with `openssl x509 -noout -subject -dates`.
