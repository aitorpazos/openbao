# Managed keys / Key Management conformance

## Public sources and version

All sources below were read from developer.hashicorp.com and display **v2.x (latest)**. This is a floating documentation label, not a claim of testing a particular binary version. No Vault implementation source was consulted.

- https://developer.hashicorp.com/vault/api-docs/system/managed-keys — read in full; registry LIST, Create/Update, Read, Test sign, Delete, and all backend parameters.
- https://developer.hashicorp.com/vault/api-docs/secret/key-management — read in full; local key lifecycle, provider configuration, and distribution lifecycle.
- https://developer.hashicorp.com/vault/api-docs/system/mounts — Enable/Disable secrets engine and Tune mount configuration, including `allowed_managed_keys`.
- https://developer.hashicorp.com/vault/api-docs — HTTP status codes, error response, and empty LIST semantics.
- https://developer.hashicorp.com/vault/docs/secrets/key-management — Enterprise ADP requirement and `vault secrets enable keymgmt`.
- https://developer.hashicorp.com/vault/docs/enterprise/managed-keys — Enterprise licensing, namespace and backend support.

400 assertions combine explicitly required fields/enums with the generic invalid/missing-data status contract; 404 assertions use the generic missing-resource/empty-list contract. These are documentation-derived expectations, not observed server results. No exact error wording is asserted. Empty LIST is documented as 404 with `errors: []`; successful writes accept 200 or 204. Registry LIST examples omit the envelope, so their assertions intentionally avoid inventing a `data.keys` location.

## Executable areas and safety

- `00-managed-key-registry.yaml`: supported-type LIST, missing-resource reads, unknown-type and missing-required-field validation. Names are `compat-mk-*`.
- `10-key-management-keys.yaml`: isolated `keymgmt` mount, local default RSA key create/read/list, unknown type/read, deletion protection, rotation, update, delete, and empty distribution list. Local key generation needs no external KMS.
- `20-key-management-providers.yaml`: separate isolated `keymgmt` mount, empty LIST, unknown read, missing provider/collection and unsupported-provider validation.

Use a root administrative token on an initialized, unsealed, disposable, appropriately licensed target. The two `compat-km-*` mounts and all reserved names must be absent before execution; no concurrent use. Cleanup disables only the reserved mounts and destroys their contents. Do not run on pre-existing mounts. Registry negatives do not intentionally persist configuration; inspect for unexpected `compat-mk-*` entries after a failing implementation accepts invalid input. There is no automatic deletion of such unexpected entries because deletion semantics and external side effects should not be guessed.

“Bare dev server” means no external provider fixtures, NOT an unlicensed Community binary: Key Management needs Enterprise ADP; managed keys need an appropriate Enterprise license, and `pkcs11` requires Enterprise plus HSMs. Validation ordering and license gates may prevent validation negatives from reaching the intended checks on an unsupported target.

## Registry contract corrections and fixture-gated coverage

The actual registry route is `/sys/managed-keys/:type/:name`, not `/sys/managed-keys/:name`. Documented types are **pkcs11, awskms, azurekeyvault, gcpckms**. There is no documented `kmip`, `kmwip`, generic `hsm`, `aws-kms`, `azure-km`, or `gcp-kms` type on this page. LIST is `/sys/managed-keys/:type`, not a key-collection API. The generic controls are `allow_generate_key`, `allow_replace_key`, `allow_store_key`, `any_mount`, and `usages`; defaults are string `"false"` for those flags and `sign,verify` for usages. `allow_delete`, `allow_replace`, `any_key_value`, and `min_ecdh` are not documented here.

Backend requirements from the registry API:

- PKCS11: named server `kms_library` via `library`, `key_label` or `key_id`, mechanism, PIN, slot or token label. Generation has mechanism-specific curve/key-bit requirements; optional controls include `force_rw_session`, `max_parallel`, `rsa_oaep_hash`. Unsupported mechanisms are not categorically invalid: the docs allow them but restrict automatic generation.
- AWS: `kms_key`, `key_type` (RSA/ECDSA), corresponding bits/curve; optional credentials with environment/profile fallback, region, endpoint. Generation requires an AWS alias; existing signing keys require SIGN_VERIFY usage.
- Azure: tenant, credentials or MSI, vault/key names, `key_type` RSA-HSM, generation bits; environment, resource and encryption mode options.
- GCP: crypto key, key ring, project, region, signing algorithm; credential file/environment or WIF, and crypto key version. Project/region also have environment fallback.

Positive POST/GET/update/DELETE and `POST /sys/managed-keys/:type/:name/test/sign` are **fixture-gated and deliberately not executable YAML cases**. They require real operator-owned cloud/HSM resources, credentials or workload identity, and PKCS11 host library configuration where applicable. Signing can generate a remote key when generation is enabled. Keep generation/replacement/storage disabled unless the fixture owner explicitly authorizes those effects; never put credentials in specs.

Mount permission uses `config.allowed_managed_keys` at enable and `allowed_managed_keys` at tune, containing registry entry **names**. `any_mount` bypasses the per-mount grant. No `managed_key_id` mount field or `key-name` tune field is established by these sources. A managed entry cannot be deleted while listed in any mount's allowed keys. A future fixture workflow must create an entry, associate a dedicated mount, check deletion refusal, clear the association, then delete the entry. Missing-entry DELETE idempotency and exact refusal messages are unspecified and untested. The API page says root namespace only, whereas its prose and the conceptual page discuss namespace-bound entries; these specs deliberately stay in root and do not resolve that discrepancy by inference.

## Key Management distribution: documented but fixture-gated

Relative to a dedicated `keymgmt` mount, the overview documents:

| Methods | Route | Purpose |
| --- | --- | --- |
| POST, GET, DELETE | `kms/:name` | Configure/read/delete provider |
| LIST | `kms` | Provider inventory |
| LIST | `key/:name/kms` | Providers receiving a local key |
| POST, GET, DELETE | `kms/:name/key/:key_name` | Distribute/read/remove remote copy |
| LIST | `kms/:name/key` | Distributed-key inventory |

Provider creation requires `provider` (`azurekeyvault`, `awskms`, `gcpckms`) and provider-specific `key_collection`; both are immutable after creation. Credentials are optional because environment credentials may be used. `key_collection` is a configuration field, not a separate endpoint. Distribution requires at least one purpose (encrypt, decrypt, sign, verify, wrap, unwrap) and protection `hsm` (default) or `software`. Distribution parameters cannot be changed afterward. The docs currently limit a key to one provider. Reads return remote name, protection, purpose and a version mapping, not private key material. There is no separate reader endpoint in this overview.

Positive provider CRUD/distribution and related negative tests need an owned cloud destination and compatible key type/purpose/protection, following the provider-specific public docs linked by the overview. Those provider-specific details were not promoted to assertions here. Missing-purpose or invalid-protection requests against a nonexistent provider would conflate resource lookup with field validation, so are omitted. The fixture workflow should distribute a local key, read/list both directions, rotate and check remote versions, remove the remote copy, then delete the local key (after `deletion_allowed=true`) and provider. A distributed key prevents local deletion; a nonempty provider prevents provider deletion. Removing a remote copy leaves the local key intact. Remote cleanup may be destructive and must be explicitly authorized.

Remaining gaps: nondefault local algorithms, exhaustive type validation, credentials redaction, provider immutability enforcement, external propagation timing, mount-use cryptographic integration, namespace discrepancies, and HSM/cloud signing are not claimed as covered. No undocumented config, status, reader, or key-collection routes were invented.
