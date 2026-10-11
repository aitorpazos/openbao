# PKI / Transit Enterprise conformance specifications

## Sources and clean-room boundary

All API contracts originate in public documentation on `developer.hashicorp.com`.
The four complete rendered pages were retrieved and reviewed, including their
parameter lists and response examples. Each currently displays **v2.x (latest)**;
that is the label recorded in every YAML, not a claim about compatibility with all
historical Vault releases. These moving latest pages contain newer additions such
as PKI export-key management and SLH-DSA; a licensed older release may legitimately
lack them.

| Source (version label for every row: **v2.x (latest)**) | Contract used |
| --- | --- |
| https://developer.hashicorp.com/vault/api-docs/secret/pki-external-ca | External ACME accounts, roles, DNS providers, orders, lookup/caching |
| https://developer.hashicorp.com/vault/api-docs/secret/pki/issuance | ACME and Enterprise EST/CMPv2/SCEP configuration and protocol paths |
| https://developer.hashicorp.com/vault/api-docs/secret/pki | CIEPS, metadata, managed keys, export keys; other Enterprise sections inventoried below |
| https://developer.hashicorp.com/vault/api-docs/secret/transit | Enterprise key types, CMAC, Ed25519 variants, managed keys, seal entropy |
| https://developer.hashicorp.com/vault/api-docs/system/mounts | Enable/disable mounts and `external_entropy_access` |
| https://developer.hashicorp.com/vault/api-docs#http-status-codes | 200/204 success, 400 invalid/missing data, empty LIST = 404 |
| https://developer.hashicorp.com/vault/api-docs#error-response | `errors` array of strings |

The established format was taken from `auth-os-saml/10-scep.yaml` and
`enterprise-config/00-group-policy-application.yaml`. No Vault source was read and
no git commands were used. Local OpenBao MPL transit implementation/tests were
consulted **only to identify existing capabilities**, not to derive Vault contracts.
No existing repository file was changed. This directory contains specifications,
not implementation changes.

## Files and execution scope

* `00-external-ca.yaml`: **21 cases**.
* `10-issuance.yaml`: **33 cases**.
* `20-transit.yaml`: **42 cases**.
* Total: **96 cases**; dependencies refer only to cases within the same file.

Use an initialized, unsealed, disposable target with an administrative/root token
and an appropriate Enterprise license when measuring Vault. The external CA plugin
must be available as `pki-external-ca`. The mounts `compat-pkica-external`,
`compat-pkica-issuance`, and `compat-transit-ent` **must not exist before a run**.
Do not run concurrently. Last cases unconditionally disable these mounts, including
all their keys/configuration; this is not restoration of pre-existing state.
Never aim these specs at production mounts. All fixture resource names are reserved
`compat-pkica-*` / `compat-transit-*` names.

The transit seal-source success cases require a Vault target whose entropy
augmentation has been configured externally; the mount requests
`external_entropy_access=true`. OpenBao accepts these source names with platform
fallback. A successful shape assertion does **not** prove an HSM supplied entropy.
Do not use these specs to certify randomness or cryptographic implementation quality.

Block external networking during the ordinary configuration suite if possible.
No successful ACME registration, DNS-update test, CIEPS issuance, real domain
validation or managed KMS operation is included. The DNS CRUD fixture uses a dummy
TSIG secret copied from the public example and `127.0.0.1:1`; it is configuration
only. Malformed CIEPS requests use loopback URLs, not public services.

## 1. External CA: actual documented surface

The source describes an **external ACME client secrets engine**, not an AWS Private
CA intermediary issuer API. There is no documented `ACMPCAIssuer`,
`config/issuance`, or provider-intermediate endpoint on this page; none was invented.
Route53 is a **DNS challenge provider**, not a CA provider.

Runnable coverage:

* Required-input negatives for ACME account creation/import and role creation.
* Required-identifier negatives for Route53, Azure DNS and Google Cloud DNS.
* RFC2136 DNS configuration create/read/list/update/delete, round-trip TTL/algorithm,
  global DNS list `keys`/`key_info`, and empty list after deletion.
* Recent-order lookback range rejection below one hour and above 168 hours.
* Response shapes use documented fields without fixed timestamps/UUIDs.

### Fixture-gated backlog (deliberately not executable cases)

The harness has no generic response-value capture/interpolation, conditional
fixture selection, asynchronous polling, or ACME client/JWS engine. “Fixture-gated”
here means **not issued by the YAML suite**, not an unsupported `skip` or `fixture`
field pretending to implement a gate. Future opt-in integration specs need:

1. A private disposable ACME directory, trusted CA bundle, contacts, optional EAB
   credentials, and an account fixture `compat-pkica-account`.
2. Controlled validation domains and HTTP-01/TLS-ALPN-01 responders, or a disposable
   DNS zone plus explicitly provided Route53/Azure/GCP/RFC2136 credentials.
3. Response capture of order IDs and account state plus bounded polling, with
   credential/domain ownership and cleanup verified outside this static suite.

Documented endpoints to cover once those fixtures exist (paths relative to mount):

* `POST config/acme-account/:name` and `POST .../:name/import`; `GET`, `PUT`,
  `DELETE config/acme-account/:name`; `LIST config/acme-account`;
  `POST config/acme-account/:name/rotate-key`. Account read/create shape includes
  `name`, `directory_url`, `email_contacts`, `active_key_version`, `account_keys`,
  and timestamps. PUT only updates trust/nameserver; delete deactivates upstream
  and cannot succeed while referenced by roles. Rotation returns old/new versions.
* `POST/GET/DELETE role/:name`, `LIST role`: `acme_account_name` is required and
  immutable after creation. Test its allowed-domain/challenge/key/CSR enums with
  a **real account**, rather than confuse a missing-account error with enum handling.
* `POST dns/test/workflow`: creates real TXT records. Never run merely to check
  credentials without authorization; keep `omit_cleanup=false` and verify cleanup.
* `POST role/:name/new-order`: exactly one of `identifiers` / `csr`; returns
  `data.order_id`. `GET role/:name/order/:order_id/status` reports workflow state,
  challenge map, timestamps, identifiers, last error and serial.
* `GET .../challenge`, `POST .../fulfilled-challenge`, `GET .../fetch-cert`,
  `POST .../revoke`, `LIST role/:name/active-orders`, `GET role/:name/cached`.
  Cache selection requires exactly one minimum-validity criterion. Certificate
  shape includes chain, certificate, format, validity and serial; generated-key
  identifier workflows may return the private key. CSR workflows must not be
  conflated with identifier workflows.
* `GET lookup/cert/:serial`, `GET lookup/order/:order_id`, `LIST lookup/orders`,
  `LIST lookup/orders/recent`. Recent results are capped at 500 and ordered newest
  first. Do not assert arbitrary UUIDs or undocumented missing-record statuses.

Order status is the internal workflow state; `challenge_status` comes from the
upstream ACME server. They are explicitly not interchangeable in the source.

## 2. Enterprise issuance protocols and main PKI additions

**ACME itself is not Enterprise-only.** The Enterprise portion includes CIEPS
`external-policy` directories. Regular ACME account/EAB endpoints are inventoried
in the issuance source but not duplicated here as an Enterprise feature.

Runnable coverage:

* EST disabled configuration/read/update, audit field validation, Sentinel parsing
  toggle. `default_mount=false`, with no globally unique EST labels registered.
* CMPv2 disabled configuration/read/update, invalid path policy and disabled
  validation enum, Sentinel/audit fields. No certificate validation is disabled.
* SCEP log-level validation, round-trip and empty-string reset (documented from
  1.20.1). Existing SCEP role/basic-PKI configuration coverage remains in
  `auth-os-saml/10-scep.yaml`; this adds rather than replaces it.
* Disabled ACME external-policy directory returns documented 404. That case alone
  can also pass on an implementation lacking the directory and is not a positive
  Enterprise-support detector.
* CIEPS default read shape and HTTPS/trust requirements. Missing trust can also
  account for the insecure-URL request's rejection; no error text/order is asserted.
* `no_store_metadata` role round-trips independently from `no_store`.
* Missing managed-key references on root/intermediate `kms` generation.
* Export-key algorithm rejection, creation/public-key shape, listing and name
  uniqueness. Mount cleanup removes the key; no CA private key is exported.

### Protocol and main-page gaps

* EST documents `est/{cacerts,simpleenroll,simplereenroll}` and role-qualified
  variants; `cacerts` is unauthenticated. It does not specify a complete wire
  response example/HTTP method table here. No guessed JSON `data.certificate`,
  content-type, disabled status or `csrattrs` endpoint is asserted. Positive EST
  needs an issuer and delegated auth accessors; default `.well-known/est` registration
  and labels are cluster-wide and intentionally avoided.
* CMPv2 uses `cmp` / `roles/:role/cmp`, **not** `/cmpv2`. Its signed ASN.1 messages,
  certificate authentication, nonces and response validation need a protocol fixture.
* SCEP uses `scep` / `roles/:role/scep`; no invented `/scep/pkiclient` API is used.
  GetCACert/GetCACaps/PKIOperation and Intune validation require protocol/auth/cloud
  fixtures beyond the configuration contract. No real Intune secret is supplied.
* ACME new-account/order authorization and EAB/account-management lifecycle require
  actual protocol-created state. Enabled directory JSON keys are not enumerated in
  these API docs, so the suite does not invent an RFC schema from memory. The page's
  directory discussion allows `external-policy(:policy)` even though its configuration
  parameter list omits that alternative; no extra enum rejection is inferred.
* CIEPS successful issue/sign/sign-intermediate needs an HTTPS external policy
  service, trust/client certificates and issuer. The main PKI page explicitly
  documents the `external-policy` paths; configuration-only negatives do not prove
  end-to-end integration.
* Certificate metadata creation/read/list needs actual issued serials and response
  capture. Batch certificate retrieval has an envelope-omitting sample; no guessed
  field placement or missing-serial behavior is tested.
* Export-key read/delete and CA export/wrapped-key import need dynamic UUID/public
  key capture; no `name` path alias is presumed. Management is Enterprise; managed
  HSM-backed CA keys explicitly cannot be exported. No insecure fake PEM is used as
  a successful fixture.
* Issuer chain-validation bypass flags, cross-cluster revocation queues, unified
  CRL/OCSP, metadata/CMP nonce tidy and replication behavior remain uncovered.
  These need a separate issuer/replication/time fixture suite, not a claim of full
  main-PKI-page coverage. Managed key happy paths require KMS/HSM provisioning and
  mount authorization; missing-reference negatives alone cannot distinguish an
  unsupported managed-key implementation from correct validation.

## 3. Transit Enterprise extensions

The transit source explicitly marks these additions Enterprise:

* `managed_key` with `managed_key_name` / `managed_key_id` (including rotate).
* AES-128/192/256 CMAC key types, generation and `cmac-key` export; `cmac` input to
  verify and `mac_length` selection.
* `ml-dsa` + `parameter_set`, hybrid PQC/EC types, SLH-DSA parameter sets.
* AES-128/256 CBC and its `iv` encryption parameter.
* Ed25519ph via SHA-512 + `prehashed=true`, and Ed25519ctx/ph `signature_context`.
* Seal-sourced entropy augmentation.

**Not newly classified as Enterprise:** ordinary import/import_version/BYOK export,
`exportable`, `allow_plaintext_backup`, key rotation controls, RSA padding, CSR and
certificate-chain endpoints. The current page does not document an `allow_import`
parameter or an Enterprise `key_config` object. Those were not invented. Multiple
and derived data-key endpoints are not Enterprise-badged on this page and are not
included simply because an implementation might lack them.

Runnable coverage includes positive key create/read shapes for all three CMAC
sizes, both CBC sizes, one ML-DSA parameter set, one hybrid and one SLH-DSA set;
CMAC single/batch generation, URL MAC length precedence, export and negatives; CBC
random-IV encryption and wrong-length rejection; managed/PQC required-field
negatives; Ed25519ctx/ph signing shapes, malformed context rejection and a known
Ed25519ph signature verification plus wrong-context rejection; seal/all random
response shape and invalid encoding.

The known signature is a computed test fixture, **not fabricated Vault output**.
It was generated and successfully verified with PyNaCl/libsodium using
`crypto_sign_seed_keypair(bytes(range(32)))`, the message
`b"compat-transit-message"`, and `crypto_sign_ed25519ph_*`. Python `hashlib.sha512`
computed the prehash used in the request. Cryptography serialized the public key
as PEM SubjectPublicKeyInfo. No key material from a user or production system is
included. Ordinary sign-shape tests alone cannot detect an ignored context; the
negative/context-sensitive verification tests strengthen that boundary.

### OpenBao capability reconnaissance (not Vault contract sources)

Only this repository's MPL code/tests were inspected:

* `internal/builtin/logical/transit/path_keys.go`: OpenBao has `mldsa-44`,
  `mldsa-65`, `mldsa-87`, and `external-key`. The documented Vault spellings are
  `ml-dsa` + `parameter_set` and `managed_key`; algorithms with related purposes
  are **not API aliases**. Specs retain Vault spelling rather than asserting an
  OpenBao-specific request passes.
* The key-type switch has no CMAC, CBC, hybrid or SLH-DSA cases. Searches of the
  transit directory found no `signature_context`, `Ed25519ph` or `Ed25519ctx`
  exposure. `prehashed` exists for other signing workflows; this does not establish
  full Ed25519 variant compatibility. These are static observations, not a live
  conformance result.
* `path_random.go`, `path_random_test.go`, and
  `internal/helper/random/random_api.go` accept `seal` and `all`, produce
  `random_bytes`, and test source selection in the path. `seal` adds a warning and
  falls back to platform entropy; `all` uses platform entropy. The new specs assert
  the documented successful response, **not an expected unsupported error**. They
  should pass on current OpenBao without claiming entropy augmentation exists.
* General in-tree transit behavior is not re-specified. Existing Ed25519 creation
  and public-key import appear only as prerequisites for Enterprise variant tests.

### Remaining transit gaps

Real managed-key signing/verifying, rotation references and PKCS#11 encrypt/decrypt
need provisioned managed keys, credentials and mount allow-lists. Cloud-managed
keys must not be assumed to support encryption: the source says only PKCS#11
currently supports transit encrypt/decrypt. CMAC verify/known-answer import,
CBC decrypt/rewrap round-trips and full PQC signature verification need wrapped
import or response capture/cryptographic validation. The suite tests creation and
shape, not mathematical correctness of every algorithm. The SLH-DSA list contains
an apparent `slh-dsa-shake-128` spelling inconsistency; the selected fixture uses
explicitly documented `slh-dsa-sha2-128s` and does not silently correct other names.

## Verification performed

From the repository root:

```sh
uv run --with pyyaml python3 -c "import yaml,glob; [yaml.safe_load(open(f)) for f in glob.glob('compat/specs/pki-transit-ent/*.yaml')]"
```

Result: **exit 0**, every YAML parsed.

From `compat/harness`:

```sh
go run . --target http://127.0.0.1:1 --token x --specs ../specs/pki-transit-ent --format table
```

Result: **96 ERROR**, all `dial tcp 127.0.0.1:1: connect: connection refused`;
process exit 1, expected for transport errors. **No loader/schema/dependency
errors, no PASS/FAIL/SKIP rows.** A second invocation programmatically counted the
rows and checked that every row was an ERROR containing connection refused.
This verifies harness loading/request construction only. No licensed live target
was exercised, and no live conformance pass is claimed.
