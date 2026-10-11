# Sentinel-shaped policy gate — clean-room compatibility notes

## Sources

| ID | Page | Notes |
|----|------|-------|
| POL | https://developer.hashicorp.com/vault/api-docs/system/policies | API page; List/Read/Create/Update/Delete for RGP and EGP |
| SENT | https://developer.hashicorp.com/vault/docs/enterprise/sentinel | Enforcement levels, evaluation order, overriding, RGP attachment, EGP paths |

Discovery fetched the two pages above directly. The API page documents
`/sys/policies/{acl,rgp,egp}` management endpoints. The enterprise guide
documents the enforcement semantics; the linked "Properties" and "Examples"
pages were not fetched for this feature (see Deviations).

## Documented API surface (from POL)

- `LIST /sys/policies/egp` — sample response `{"keys": ["breakglass"]}`; prose
  states EGP lists also carry `name_path_map` mapping names to paths and glob
  status (the sample does not show it; this implementation emits it).
- `GET /sys/policies/egp/:name` — sample `{enforcement_level, name, paths,
  policy}`.
- `POST /sys/policies/egp/:name` — `name` (URL), `policy` (string, "can be
  base64-encoded to avoid string escaping"), `enforcement_level` (required,
  one of `advisory`, `soft-mandatory`, `hard-mandatory`), `paths` (required;
  string or array; "Glob characters can denote suffixes"; a path of `*`
  affects all authenticated and login requests).
- `DELETE /sys/policies/egp/:name` — deletes from all configured paths.
- RGP: identical CRUD under `/sys/policies/rgp` without `paths` (RGPs are
  tied to tokens/entities/groups, not paths).

## Documented enforcement semantics (from SENT)

- Enforcement levels: `advisory` (allowed to fail; educational),
  `soft-mandatory` (must pass unless an override is specified),
  `hard-mandatory` (must pass).
- Evaluation order: (1) token ACL policies must grant; (2) RGPs on the token
  must pass; (3) EGPs on the requested path — exact match plus any
  prefix-matching EGPs on less-specific paths — must pass. Any failure
  denies.
- Root tokens are not subject to Sentinel policy checks (like ACLs).
- Overrides: `X-Vault-Policy-Override: true` header (or the CLI flag);
  "override requests are visible in Vault's audit log; in addition, override
  requests and their eventual status ... are logged as warnings in Vault's
  server logs."
- EGPs can apply to unauthenticated (login) paths; unauthenticated requests
  skip ACL/RGP and evaluate EGPs.
- RGP names cannot share the ACL policy name space; RGPs attach to tokens
  like ACL policies.
- Multiple distinct EGPs may apply to one path; all are evaluated.

## Implementation

- New additive package `internal/vault/sentinel` (policy codec, store,
  evaluator, path matching) and `internal/vault/core_sentinel.go` /
  `internal/vault/logical_system_sentinel.go` (enforcement + API). Core-file
  hooks are listed in PATCHES.md.
- EGPs are stored under `core/sentinel/egp/<name>`, RGPs under
  `core/sentinel/rgp/<name>`, via the system barrier view; reads are served
  from a 30-second TTL cache to bound cross-node staleness (writes happen on
  the active node).
- The gate runs inside `performPolicyChecks` after the ACL block, which
  already returns early for root tokens (root bypass) and skips ACL for
  unauthenticated requests (`opts.Unauth`), matching the documented flow.
- Denials produce a 403 whose error text names the policy and enforcement
  level. The API pages do not document a denial error shape; this text is an
  implementation choice.
- Overrides only relax `soft-mandatory`; overrides and hard denials are
  logged as warnings (server log); the `policy_override` request flag is
  already audit-logged by the existing audit formatter.

## Documented deviation: policy document language

The proprietary Sentinel policy language is not reimplemented. The `policy`
field accepts a documented declarative condition subset (JSON):

- Top level: `{"when": <condition>}`.
- Conditions: `all` (array), `any` (array), `not` (object), or one subject.
- Subjects: `request.path`, `request.operation`, `request.mount_point`,
  `request.data.<key>` (dotted keys index nested objects; top-level keys are
  matched case-insensitively), `token.policies`, `token.metadata.<key>`.
- Operators: `equals` (bare value or explicit), `not_equals`, `matches`
  (trailing-glob prefix semantics like EGP paths), `in`, `contains` (scalar
  or array of values that must all be present), `exists`,
  `less_than`/`greater_than`/`less_than_equal`/`greater_than_equal` (numeric).
- Bare values are equality except on `request.path`, where bare values use
  the documented EGP glob semantics (trailing `*` prefix match).
- Write time: documents failing to parse as this subset are rejected (400).
  Stored documents round-trip verbatim through read.

The evaluator's condition subset is this fork's documented contract, not a
claimed Vault Enterprise wire contract. Anything the public docs do not
specify (error shapes, list shapes beyond the sample) is noted above.

## Scope notes

- RGP enforcement uses token policy names only. RGPs derived from identity
  entity/group membership are a follow-up (documented in SENT as attachable
  to entities/groups; identity-based MFA integration likewise).
- `request.mount_point` is populated when the router has set it; on paths
  checked before routing it is absent and `exists` reflects that.
- EGP list response includes `name_path_map` (prose-documented, not shown in
  the API sample); the spec treats it as optional.

## Harness

- `egp-crud.yaml` / `rgp-crud.yaml`: full CRUD + validation surface.
- Harness
  `enforcement.yaml`: uses the harness's token-capture capability
  (`capture_token` / `use_captured_token`, added with this feature) to
  exercise hard/soft/advisory denials, soft-mandatory override via the
  documented header, prefix+exact EGP stacking, RGP denial via token policy
  attachment, and root bypass.
- Live verification on a dev server: full enforcement spec green (0 FAIL);
  unauthenticated EGP evaluation verified manually — a hard-mandatory
  always-failing EGP on `auth/<userpass-mount>/login/*` denies an
  unauthenticated login attempt (the auth flow maps the denial to HTTP 400
  with `permission denied`; authed-path denials are 403 — the API pages do
  not document a denial status for login paths). Removing the EGP restores
  the login success (200).
