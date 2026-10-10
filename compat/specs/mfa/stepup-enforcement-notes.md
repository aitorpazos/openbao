# MFA enforcement and enrollment: public-doc supplement

Sources were read on developer.hashicorp.com only; pages label themselves **v2.x (latest)**. No source-code inspection or server execution was performed. This is an additive supplement; existing specs remain unchanged. `mfa-stepup` is the compatibility suite grouping, not an assertion that Login MFA requires Enterprise.

## 1. Do not conflate the two enforcement systems

**Enterprise Step-up MFA** uses named methods under `sys/mfa/method/<type>/<name>` and references in ACL/Sentinel policies. An ACL example is `path "secret/foo" { capabilities = ["read"] mfa_methods = ["dev_team_duo", "sales_team_totp"] }`; **both** listed methods must validate. Configurations must live in the root namespace, but policies in any namespace can reference names and configurations can tie to mount accessors in any namespace. Credentials come from `X-Vault-MFA` in the exact documented format `mfa_method_name[:key[=value]]`. This is policy/path enforcement, not a documented auth-role or mount-tune `mfa_methods` field. [Enterprise overview](https://developer.hashicorp.com/vault/docs/enterprise/mfa)

Step-up can protect login with **Sentinel EGP**, as well as non-login resources. The FAQ explicitly classifies Step-up as single-phase, with two-phase marked N/A. Therefore there is **no documented Step-up challenge response or Step-up `/sys/mfa/validate` completion flow** to implement from these pages. Its login failure status/body is not specified by the overview/FAQ; do not borrow the Login MFA challenge contract. [FAQ](https://developer.hashicorp.com/vault/docs/auth/login-mfa/faq)

A Step-up method's `mount_accessor` is not mount-wide enforcement: the Duo API describes it as “The mount to tie this method to for use in automatic mappings”, using associated alias `Name` as the username. `username_format` maps that identity to the provider username. [Duo API](https://developer.hashicorp.com/vault/api-docs/system/mfa/duo#parameters)

**Login MFA** is configured through `identity/mfa/method/<type>` and `POST /identity/mfa/login-enforcement/:name`. Required `mfa_method_ids` are ORed within an enforcement; every matching enforcement must be satisfied. At least one of `auth_method_accessors`, `auth_method_types`, `identity_group_ids`, `identity_entity_ids` must be present. These are the documented binding selectors, not per-role fields. The API permits group/entity IDs in the current or child namespace. Enforcements listed are those visible in the current or parent namespaces. [Enforcement API](https://developer.hashicorp.com/vault/api-docs/secret/identity/mfa/login-enforcement)

Login MFA methods and enforcements are namespace-aware, usable in the defining namespace and children (Enterprise required for namespaces). Login MFA itself is available in Community. Token auth cannot be configured with built-in Login MFA. Docs describe effects on **any auth mount protected by MFA validation**, with userpass and LDAP examples; they do not provide a separate exhaustively enumerated userpass/AppRole/LDAP/cert/Kubernetes/JWT/Okta compatibility matrix. Do not confuse the supported MFA providers (TOTP, Duo, Okta, PingID) with auth-method types. [Login MFA](https://developer.hashicorp.com/vault/docs/auth/login-mfa), [FAQ](https://developer.hashicorp.com/vault/docs/auth/login-mfa/faq)

## 2. Auth API field audit: no role-binding cases justified

The following full API page main bodies were fetched and searched case-insensitively for `mfa` and `multi.factor`. Findings describe documentation coverage, not proof of undocumented runtime behavior. None documents a role/user configuration `mfa_methods` field for Step-up, so **zero auth-role endpoint specs** are added.

| Public API page | MFA-related entries found |
| --- | --- |
| [userpass](https://developer.hashicorp.com/vault/api-docs/auth/userpass) | `mfa_requirement: null` in the login response sample; no user configuration enforcement field. |
| [approle](https://developer.hashicorp.com/vault/api-docs/auth/approle) | No MFA matches. |
| [ldap](https://developer.hashicorp.com/vault/api-docs/auth/ldap) | No MFA matches. |
| [cert](https://developer.hashicorp.com/vault/api-docs/auth/cert) | No MFA matches. |
| [kubernetes](https://developer.hashicorp.com/vault/api-docs/auth/kubernetes) | No MFA matches. |
| [jwt (JWT/OIDC API)](https://developer.hashicorp.com/vault/api-docs/auth/jwt) | No MFA matches. Separate `/vault/api-docs/auth/oidc` returned 404. |
| [okta](https://developer.hashicorp.com/vault/api-docs/auth/okta) | Config `bypass_okta_mfa` (boolean, default false); login `totp`, `provider` (GOOGLE/OKTA), `nonce`. These concern Okta auth/provider MFA, not Step-up role binding. |
| [system/auth](https://developer.hashicorp.com/vault/api-docs/system/auth), [system/mounts](https://developer.hashicorp.com/vault/api-docs/system/mounts) | No MFA matches, including tune documentation. |

Okta `bypass_okta_mfa` is expressly useful with Vault's built-in MFA, but can also ignore statuses such as `PASSWORD_EXPIRED`; adding a bypass config case as if it enabled Step-up would misrepresent the API. [Okta API](https://developer.hashicorp.com/vault/api-docs/auth/okta)

## 3. Two-phase **Login MFA** wire notes (v2 scenario only)

Send the auth method's normal login request **without `X-Vault-MFA`**. After primary authentication, a matching enforcement causes the normal top-level response envelope to carry a warning and `auth.mfa_requirement`, rather than a usable token. Exact sample keys below are from [Login MFA, Two-Phase login](https://developer.hashicorp.com/vault/docs/auth/login-mfa#two-phase-login):

- Top level: `request_id`, `lease_id` (empty), `lease_duration` (0), `renewable` (false), `data` (null), `warnings` (array), `auth`.
- `auth.client_token` and `auth.accessor` are empty strings; `policies`, `token_policies`, `identity_policies`, `metadata` are null; `orphan` false; `entity_id` empty; `lease_duration` 0; `renewable` false.
- `auth.mfa_requirement.mfa_request_id` identifies the login to validate. It is **not** the top-level `request_id`, nor a documented `mfa_requirement_id`.
- `auth.mfa_requirement.mfa_constraints` maps enforcement names to objects containing `any`, an array of method descriptors with `type`, `id`, `uses_passcode`, and (in the example) `name`.
- `uses_passcode` is true for TOTP, false for Okta/PingID, and configurable for Duo via `use_passcode`.

**HTTP status:** the Login MFA page gives a response body, not an explicit challenge status line. **200 is the general API-derived expectation** (“Success with data”), not an endpoint-specific quoted guarantee. Do not assert 202/401/403 for the challenge from these documents. General errors have an `errors` string array; general 400 means missing/invalid data. [API conventions](https://developer.hashicorp.com/vault/api-docs)

Complete the pending login with `POST /v1/sys/mfa/validate`, JSON:

```json
{
  "mfa_request_id": "<auth.mfa_requirement.mfa_request_id>",
  "mfa_payload": {
    "<method UUID from constraints>": ["910201"]
  }
}
```

Both fields are required. The API spells the type of `mfa_payload` as `map<string|[]string>`, while prose specifies string-slice values and examples use arrays. Use arrays, not a guessed top-level `method_id`, `passcode`, `mfa_requirements`, or `mfa_requirement_id`. For a method without passcodes, use `[""]`. Since 1.13.0 names can replace UUID map keys and `passcode=` is optional for all supported methods (e.g. `["passcode=910201"]`). Names in other namespaces can be prefixed with the namespace path (`ns1/sample_mfa_method_name`). [Validate API](https://developer.hashicorp.com/vault/api-docs/system/mfa/validate), [Login MFA](https://developer.hashicorp.com/vault/docs/auth/login-mfa)

Failed MFA validation explicitly returns **403** with error details. Success is identical to a successful login, including the token and accessor, with sample `auth.mfa_requirement: null`; success 200 follows the general data-response convention. The FAQ says the new token is persisted and returned after validation passes. No executable login/validate scenario is added: it needs fresh captured IDs and valid credentials. Existing `sys-mfa-validate.yaml` already covers missing input. [Validate API](https://developer.hashicorp.com/vault/api-docs/system/mfa/validate), [FAQ](https://developer.hashicorp.com/vault/docs/auth/login-mfa/faq), [API conventions](https://developer.hashicorp.com/vault/api-docs)

Single-phase Login MFA instead supplies `X-Vault-MFA` and validates in the initial login; since 1.13.0 either `method_id:passcode` or `method_id:passcode=<value>` is allowed for all providers, method names are also accepted, and multiple headers may be supplied. This is separate from named Enterprise Step-up policy evaluation. [Login MFA](https://developer.hashicorp.com/vault/docs/auth/login-mfa#single-phase-login)

## 4. Named Step-up TOTP enrollment endpoint specification

All three entries below derive from [system TOTP API](https://developer.hashicorp.com/vault/api-docs/system/mfa/totp). Namespace/permission restrictions derive from [Enterprise overview](https://developer.hashicorp.com/vault/docs/enterprise/mfa): users with ACL permissions can self-generate; admins can generate/destroy only for entities in their own namespace.

### GET `/v1/sys/mfa/method/totp/:name/generate`

Required path `name` (string). Generates a secret on the **calling token's entity**, if absent, using the named configuration. Sample response: `data.barcode` and `data.url` strings (QR image encoding and otpauth URL in the example). Deferred positive fixture: configured named method, entity-backed token, proper ACL, entity without the method secret. A root token is not a substitute for this entity fixture.

**No executable negative added:** this endpoint has no required body parameters. Omitting the path name creates a different/unmatched route, not a documented 400 contract. Unknown-name, duplicate-enrollment, and non-entity-token status codes are not specified on this page. A claimed fixture-free “missing name -> 400” case would exceed the evidence.

### POST `/v1/sys/mfa/method/totp/:name/admin-generate`

Required path `name` and body `entity_id` (strings). Unlike generate, stores the secret on the **specified entity**, not the caller. Sample response has `data.barcode` and `data.url`. Deferred positive fixture: named method, existing target entity in same namespace, administrative ACL, no existing secret. The docs do **not** require the administrator token itself to be entity-backed.

Added `sys-mfa-totp-admin-generate.yaml`: **one executable missing-entity_id case**, using the general missing-input 400 convention, no exact error string. No configured method/entity fixtures are required to express it; validation-order behavior against a nonexistent method name remains unspecified and is called out in the YAML. [API conventions](https://developer.hashicorp.com/vault/api-docs)

### POST admin-destroy: unresolved route conflict

The endpoint table says `/sys/mfa/method/:name/admin-destroy`, but its curl sample says `/sys/mfa/method/totp/my_totp/admin-destroy`. Required fields are path `name` and body `entity_id` (strings). It deletes the target entity's TOTP secret; to overwrite a secret, explicitly delete first, then generate/admin-generate a new one. Deferred fixture: named method, target entity with secret, appropriate administrative ACL in same namespace. The API page does not provide a response example or endpoint-specific status.

**No executable case chooses between the contradictory routes**, even for missing `entity_id`: neither the general 400 convention nor a presumed implementation resolves routing. This preserves the ambiguity already documented in `sys-mfa-method-totp.yaml`. No empty YAML spec is emitted because v1 specifies one or more cases per file. [TOTP API, administratively destroy](https://developer.hashicorp.com/vault/api-docs/system/mfa/totp#administratively-destroy-totp-mfa-secret)

## 5. Boundaries and documentation uncertainties

- Login MFA GUI TOTP self-enrollment (`enable_self_enrollment`) is a distinct identity-MFA facility, not another spelling of named `/sys/.../generate`. Its setup page requires only one enabled enforcement (that enforcement may have multiple methods). Existing identity enrollment files are not duplicated here. [Login MFA self-enrollment](https://developer.hashicorp.com/vault/docs/auth/login-mfa#option-1-configure-totp-for-self-enrollment)
- The overview's named Step-up API never supplies the requested per-auth-role enforcement fields. No undocumented role writes or blanket auth-method support claims are invented. See the audited API sources above.
- The Login MFA sample contains a trailing comma in its method descriptor; preserve field semantics, not the malformed JSON syntax. The FAQ includes historically scoped 1.10 statements about unnamed Login MFA methods; prefer the explicit 1.13+ name support in current login/validate pages. [Login MFA](https://developer.hashicorp.com/vault/docs/auth/login-mfa), [Validate API](https://developer.hashicorp.com/vault/api-docs/system/mfa/validate), [FAQ](https://developer.hashicorp.com/vault/docs/auth/login-mfa/faq)
- No target URL/token or execution tool was supplied to this docs subtask. The executable negative is a specification, **not a claimed observed response**. Tool lint and read-back validate the authored artifact only.
