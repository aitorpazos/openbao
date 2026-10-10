# Seal wrapping — documented surface (v2.x (latest))

All claims sourced from public docs, retrieved 10 Oct 2026. Sources:

- https://developer.hashicorp.com/vault/docs/enterprise/sealwrap ("Wrap seals with encryption", Enterprise; page label v2.x (latest))
- https://developer.hashicorp.com/vault/api-docs/system/mounts (v2.x (latest))
- https://developer.hashicorp.com/vault/api-docs/system/auth (v2.x (latest))

## 1. What the docs define

**Feature shape.** Seal wrapping adds an extra encryption layer for supported
seals (Enterprise Plus / HSM-class license). No dedicated API endpoint is
documented for it — it is a protection mechanism plus a mount configuration
surface.

**Always wrapped.** With a supporting seal, core Critical Security Parameters
are always seal-wrapped: the recovery key, any stored key shares, the root
key, the keyring, "and more". On upgrade from a pre-wrap version these values
are wrapped lazily on next read. [enterprise/sealwrap]

**Mount opt-in.** A backend mount may enable seal wrapping at mount time via
the `seal_wrap` configuration value set to true. "(This value cannot currently
be changed later.)" Backend authors choose which of their values to wrap.
Examples of backend usage documented: LDAP/RADIUS/Okta/AWS auth config
storage; PKI issuers+keys; SSH CA keys; KMIP managed objects + CA keys;
Transit keys and policy. [enterprise/sealwrap]

**Enable/disable.** `disable_sealwrap = true` in the server config file. Lazy
downgrade: keys change wrap status as they are read/written. Does NOT affect
root-key protection (root key stays wrapped). Config-file surface only — no
API to toggle. [enterprise/sealwrap]

**Replication.** Transparent: wrapping happens below replication; each cluster
wraps with its own seal. [enterprise/sealwrap]

## 2. API surface (system backend)

**Secret mounts.** POST /sys/mounts/:path documents `seal_wrap (bool: false)`
under the note: "Additionally, the following options are allowed in Vault
open-source, but relevant functionality is only supported in Vault Enterprise:"
(alongside `local` and `external_entropy_access`). [api-docs/system/mounts,
Enable secrets engine → Parameters]

**Auth mounts.** The POST /sys/auth/:path parameter list does NOT document
`seal_wrap`; only the LIST response sample shows the field (per auth-mount
entry, e.g. `"seal_wrap": false`). Per clean-room discipline: response-shape
assertions only for auth mounts, no create-param case. [api-docs/system/auth]

**Responses.** Both /sys/mounts and /sys/auth response samples carry
`seal_wrap` as a boolean directly on each mount entry (NOT inside `config`),
alongside `local`, `options`, `type`, `uuid`, etc. [both API pages]

**Tune.** The /sys/mounts tune parameters do not list `seal_wrap` — consistent
with "cannot be changed later" (mount-time only). [api-docs/system/mounts,
Tune a mount; enterprise/sealwrap]

## 3. Executable spec decisions

- Secret-mount create with `seal_wrap: true` → 204; single-mount read shows
  `data.seal_wrap == true`. This tests the community surface: the field must
  be accepted and reported. The actual wrapping of stored values requires a
  supported seal (Enterprise Plus class) and is NOT asserted by these specs.
- Default create (field omitted) → read shows `data.seal_wrap == false`.
- Cleanup deletes the created mounts (204) so the suite is idempotent.
- Auth-mount case asserts response shape only (presence + boolean type on the
  pre-existing `token/` mount in /sys/auth list).

## 4. Implementation implications for OpenBao (non-spec notes)

- The community surface is the `seal_wrap` field lifecycle: accepted at mount
  create, persisted in the mount table, reported in reads/list. This must work
  regardless of seal support.
- Actual wrapping requires a seal with an encryption primitive reachable at
  runtime (PKCS#11 / cloud KMS auto-unseal class). OpenBao's barrier already
  encrypts all values with its own keys; adding a true second wrap layer under
  a supported seal is an implementation task deferred from this spec cycle —
  these specs neither test nor require it.
- `disable_sealwrap` config-file flag + lazy semantics are documented but not
  API-observable; out of scope for executable specs.
