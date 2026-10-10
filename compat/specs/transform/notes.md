# Transform compatibility surface

## Provenance and scope

This suite was authored only from the following public HashiCorp Developer
pages, each of which displayed **`v2.x (latest)`** when consulted:

- **[API]** https://developer.hashicorp.com/vault/api-docs/secret/transform —
  endpoint tables, required/default parameters, and sample response shapes.
- **[Engine]** https://developer.hashicorp.com/vault/docs/secrets/transform —
  Setup, Usage, resource relationships, builtin resources and deletion behavior.
- **[Tokenization]** https://developer.hashicorp.com/vault/docs/secrets/transform/tokenization —
  stateful operation, convergence, stores, key management and snapshot/restore.
- **[HTTP]** https://developer.hashicorp.com/vault/api-docs#http-status-codes —
  success and missing-data status conventions.

Every `[API]`, `[Engine]`, `[Tokenization]` or `[HTTP]` citation below means the
URL above **and the displayed version `v2.x (latest)`**, not an observed server
version. No Vault source, binaries, or private documentation were consulted.
No Git commands were used. Only files in `compat/specs/transform/` were written.
The local `compat/README.md` was read first for harness syntax/capabilities.

The API surface is consolidated on the Transform API page: role, template,
alphabet, FPE, tokenization and batch operations are **sections**, not separate
API subpages linked by that page. Its linked Engine documentation and the
Engine's Tokenization subpage were followed. We did not invent URL paths named
`fpe-encode`, `fpe-decode`, `sources` or `tokenization/roles`. [API; Engine]

## Files and cases

| File | Cases | Coverage |
| --- | ---: | --- |
| `alphabets.yaml` | 7 | LIST and GET of all six documented builtin alphabets |
| `templates.yaml` | 8 | Two missing-required-field negatives, create/read/update/read/list/delete |
| `roles.yaml` | 6 | Create/read/update/read/filtered-list/delete |
| `fpe-encode-decode.yaml` | 8 | Missing template; FPE and role fixtures; missing encode/decode value; encode shape; cleanup |
| `tokenization.yaml` | 12 | Configuration create/read/update/read/list, authorized role, missing encode/decode/validate/metadata value, cleanup |
| `tokenization-stores.yaml` | 4 | Three progressively incomplete SQL store requests and defensive cleanup |
| **Total** | **45** | `feature: transform` throughout |

Counts were checked from the authored files; all six YAML writes passed the
file tool's syntax lint. No harness or server requests were run. Syntax lint is
not runtime compatibility verification.

## Documented surface map

Paths below are relative to `/v1/transform`. These are documentation-derived
mappings, not assertions that every mapped endpoint has a runnable case.

| Group | Documented methods and paths | Fields/behavior and coverage decision | Source |
| --- | --- | --- | --- |
| Roles | POST/GET/DELETE `role/:name`; LIST `role` | Body `transformations` defaults to `[]`; LIST has glob `filter`. CRUD and filtered LIST covered. | [API], Create/Update/Read/List/Delete role |
| Templates | POST/GET/DELETE `template/:name`; LIST `template` | Required `type` (`regex`) and `pattern`; optional `alphabet`, `encode_format`, `decode_formats`. CRUD, list and missing type/pattern covered. | [API], template sections |
| Alphabets | POST/GET/DELETE `alphabet/:name`; LIST `alphabet` | Creation requires `alphabet`; read data has `alphabet`. Suite limits itself to builtin reads and LIST; custom CRUD deferred. | [API], alphabet sections |
| FPE config | POST `transformations/fpe/:name` | Required `template`; `tweak_source`, `allowed_roles`, `deletion_allowed`. Missing template and internal-tweak fixture covered. | [API], Create/Update FPE transformation |
| Masking config | POST `transformations/masking/:name` | Required `template`; `masking_character`, `allowed_roles`. Mapped, not tested; outside this suite's FPE/tokenization focus. | [API], Create/Update masking transformation |
| Tokenization config | POST `transformations/tokenization/:name` | `mapping_mode`, immutable `convergent`, `max_ttl`, `allowed_roles`, `stores`, `deletion_allowed`; no required body fields. Self-contained CRUD fixture covered. | [API], Create/Update tokenization transformation |
| Shared transformations | GET/DELETE `transformation/:name`; LIST `transformation` | Common read sample includes `type`, `allowed_roles`, `templates`, `tweak_source`. Tokenization tests assert only common type/allowed_roles, not FPE-only fields. Shared list/delete covered. | [API], Read/List/Delete transformation |
| Deprecated config | POST `transformation/:name` | Deprecated since 1.6 in favor of type-specific writes; `type`, `template` (ignored for tokenization), type-specific options. Not exercised. | [API], Create/Update transformation DEPRECATED (1.6) |
| Encode | POST `encode/:role_name` | Required scalar `value`, optional `transformation`; FPE `tweak`; tokenization `ttl`, `expiration`, `metadata`; `batch_input` and per-item `reference`. Missing value covered with actual FPE and tokenization roles; one FPE encode shape check. | [API], Encode |
| Decode | POST `decode/:role_name(/:decode_format)` | Required scalar `value`, optional transformation/tweak; optional FPE decode format; batches. Missing value covered for both transform types. | [API], Decode |
| Token validity | POST `validate/:role_name` | Required `value`; optional transformation, batch_input/reference. Missing value covered. | [API], Validate token |
| Tokenization check | POST `tokenized/:role_name` | Required plaintext `value`; optional transformation and batches. Mapped, deferred. | [API], Check tokenization |
| Token lookup | POST `tokens/:role_name` | Required plaintext `value`; expiration or min/max expiration; transformation and batches. Needs convergent config, or exportable mapping plus external storage; deferred. | [API], Lookup token; [Tokenization], Token lookup |
| Token deletion | DELETE `tokens/:role_name` | Required **`token`**, not `value`; transformation and batches. Needs generated token to test meaningfully; deferred. | [API], Delete token |
| Plaintext deletion | DELETE `tokenized/:role_name` | Required `value`, expiration selection, transformation and batches; same convergence/exportable-external restriction as lookup; deferred. | [API], Delete token by plaintext |
| Metadata | POST `metadata/:role_name` | Required `value`, transformation, batches; missing value covered. | [API], Retrieve token metadata |
| External stores | POST/GET/DELETE `stores/:name`; LIST `stores` | Required write fields `type=sql`, `driver`, `connection_string`, `username`, `password`; options supported_transformations, schema and connection limits/lifetime. Missing-data writes and delete covered; connected CRUD/list deferred. | [API], store sections |
| SQL schema | POST `stores/:name/schema` | Required username/password; transformation_type defaults tokenization. Deferred: requires explicit SQL fixture and DDL credentials. | [API], Create/Update store schema |
| Wrapping key | GET `wrapping_key` | RSA public key for BYOK. Mapped but not tested. | [API], Get wrapping key |
| FPE import | POST `transformations/fpe/:name/import` | Required ciphertext/template; hash_function, tweak_source, allowed_roles. Deferred cryptographic import fixture. | [API], Import key for FPE transformation |
| Tokenization import | POST `transformations/tokenization/:name/import` | Required ciphertext; hash_function, allow_rotation, mapping_mode, max_ttl, allowed_roles, stores. Deferred cryptographic import fixture. | [API], Import key for tokenization transformation |
| Tokenization import version | POST `transformations/tokenization/:name/import_version` | Required ciphertext; hash_function; existing imported-key transformation prerequisite. Deferred. | [API], Import key version for tokenization transformation |
| State snapshot | POST `transformations/tokenization/snapshot/:name` | limit/continuation; protected values and continuation in response. Deferred stateful capture. | [API], Snapshot tokenization state |
| State restore | POST `transformations/tokenization/restore/:name` | Required values from a prior snapshot; idempotent restore, matching mapping modes required. Deferred stateful capture. | [API], Restore tokenization state |
| Decoded export | POST `transformations/tokenization/export-decoded/:name` | exportable mapping required; limit/continuation; plaintext is base64. Deferred; no sensitive export exercised. | [API], Export decoded tokenization state |
| Tokenization keys | LIST `tokenization/keys/`; GET `tokenization/keys/:transform_name` | Config read includes latest_version, min_available_version, min_decryption_version, auto_rotate_period, name. Mapped, not tested. | [API], List/Read tokenization key configuration |
| Key config/rotation | POST `tokenization/keys/:transform_name/config`; POST `tokenization/keys/:transform_name/rotate` | min_decryption_version and auto_rotate_period (zero disables; nonzero minimum one hour); rotation creates a new encode key version. Deferred lifecycle fixtures. | [API], Update tokenization key config; Rotate tokenization key |
| Key trim | POST `tokenization/keys/:transform_name/trim` | Required min_available_version; irreversible removal bounded by min_decryption_version/latest_version. Deferred destructive lifecycle test. | [API], Trim tokenization key version |

## Corrected assumptions and documentation ambiguities

- **Alphabets are not globally read-only.** Custom alphabets have CRUD endpoints.
  The six documented builtins are `builtin/numeric`, `builtin/alphalower`,
  `builtin/alphaupper`, `builtin/alphanumericlower`,
  `builtin/alphanumericupper`, and `builtin/alphanumeric`. The suite asserts
  their presence via successful GETs, without guessing literal contents or
  array ordering. `[Engine]`, Provided builtin resources, documents these names;
  `[API]`, Read alphabet, documents the string response field.
- **Roles are not transformation configuration objects.** Only `transformations`
  is documented in role bodies. `template` belongs to FPE/masking configuration;
  `templates` appears in the shared transformation read sample; `max_ttl` and
  `deletion_allowed` belong to transformation configuration; `ttl` belongs to
  tokenization encode. `lowercase`, `uppercase`, `prefix`, `suffix` and plural
  `patterns` are not documented request fields on these endpoints. Do not
  manufacture validation requirements or unknown-field rejection tests. [API]
- The encode `expiration` prose calls max_ttl the "role's" value, but the actual
  role parameter section omits it and tokenization creation documents it. The
  suite places max_ttl only on the tokenization transformation and defers a TTL
  wire-format assertion. [API], Create/Update role, Create/Update tokenization
  transformation, Encode
- The store LIST table says `/transform/stores`, while its curl sample uses
  singular `/transform/store`. The metadata table says `/transform/metadata`,
  while its sample curl uses `/transform/encode`. Prefer method/path tables;
  do not spec the sample typos as aliases. [API], List stores, Retrieve token
  metadata
- The decode batch sample labels result fields `encoded_value`, despite scalar
  decode using `decoded_value`. The token lookup/deletion sample repeats
  `min_expiration` where its parameter list distinguishes min/max. Some snapshot
  and trim curl samples repeat slashes/path prefixes. No assertions are based
  on these inconsistent sample details. [API], Decode, Lookup token, Delete
  token by plaintext, Snapshot/Restore tokenization state, Trim key version
- Required-field 400s derive from the combination of each endpoint's
  `<required>` annotations [API] and missing-data status semantics [HTTP]. The
  Transform page does not publish exact error messages or validation order.
  It has not been verified whether a live implementation supplies defaults for
  any fields marked required (notably template type). Such discrepancies should
  be triaged as doc-vs-runtime findings, not silently resolved using source.
- Successful writes/deletes accept 200 or 204 because warnings can change a
  no-content response to 200; reads require 200 and actual data. [HTTP]

## Execution prerequisites, isolation and deferrals

The suite assumes a pre-enabled `transform/` mount and a token with sufficient
read/write/list/delete permissions. Enabling/disabling the mount is deliberately
outside the suite; it must not destroy unrelated data. `[API]` assumes this
mount path; `[Engine]`, Setup, documents enabling it. These authoring-time tests
were not run against any server.

All fixture names are suite-owned `compat-tf-*`; do not run concurrent copies
against the same mount. Each file is independent of other files. Cases execute
in file order, with explicit dependencies on all relevant setup writes and
unconditional cleanup at the end. Deletes are ordered role before
transformation; FPE/tokenization fixtures set deletion_allowed=true. This
follows `[Engine]`, Deletion behavior, and `[API]`, transformation creation.
Only successful fixtures and defensive store cleanup are deleted; builtin
resources and unrelated names are untouched. An interrupted run should be
cleaned up before retrying missing-required-field **creation** cases, otherwise
an existing object can turn a creation request into a partial update. Normal
completed runs clean up their resources and are repeatable.

The basic engine is self-contained: FPE uses builtins and an internally sourced
tweak; tokenization uses `builtin/internal`. Neither requires KMS, TOTP, HSM or
SQL. Only optional external SQL storage needs an external database; BYOK needs
wrapped key material, not necessarily an HSM. [API; Engine; Tokenization]

A real encode/decode round trip is deliberately **not claimed**. The local
harness v1 has no response-variable capture/substitution, so it cannot forward
fresh ciphertext or tokens into decode. Example ciphertext in public docs is
not a portable test vector for a newly generated transformation key. The suite
therefore limits FPE success to encoded-value shape and tokenization data
operations to missing-value negatives with valid authorized configuration.
Templates and roles have real request/readback assertions, but were not executed
here. [API], Encode/Decode examples; [Engine], Setup/Usage

Batch operations are parameters on the same role-based endpoints, not a
separate `/batch` route. They accept per-item values/transformation/reference
and override scalar parameters as described in [API]. Batch negative HTTP
status and mixed-success behavior are not clearly specified there; coupled
with the inconsistent decode response sample, this makes precise batch
assertions inappropriate without stronger public documentation. They remain
mapped but deferred, rather than guessing that an invalid batch must produce
an overall 400.

Future coverage can add captured FPE/tokenization round trips, optional decode
formats and tweak variants, TTL expiry, batch semantics, token lookup/deletion,
SQL stores, snapshot/restore/export, and key import/rotation/trim. No runtime
result, encoded value, token or SQL response has been fabricated.
