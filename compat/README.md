# Vault Enterprise Compatibility Harness

Part of the OpenBao enterprise-parity project: reimplement Vault Enterprise
features in OpenBao with wire-level API compatibility, validated by a
spec-driven conformance harness.

## Methodology (clean-room rules)

1. Specs are derived ONLY from public documentation (developer.hashicorp.com)
   and documented public API behavior. Every spec file cites its source URL.
2. No BSL-licensed Vault source may be used as implementation input.
   OpenBao's CONTRIBUTING.md requires clean-room, original work for parity
   features; BSL source (Vault post-2023) is off-limits.
3. No decompilation or binary analysis of Vault Enterprise. Ever.
4. Implementation code reads specs and docs — never Vault Enterprise source.

## Layout

    compat/
      README.md     this document: methodology + spec format
      specs/        one YAML file per endpoint, grouped by feature
        core/       endpoints OpenBao shares with Vault today
        mfa/        step-up MFA (Enterprise-only; OpenBao target work)
      harness/      Go runner (separate module, stdlib + yaml.v3 only)

## Spec format (v1)

YAML, one file per endpoint, one or more cases per file. Cases run in file
order. See `specs/core/*.yaml` for examples.

```yaml
api: sys-health                   # unique stable id (snake-case)
feature: core                     # grouping; drives FEATURE_ABSENT verdicts
source: https://developer.hashicorp.com/vault/api-docs/system/health
source_version: "2.1.x"           # docs version the spec was derived from
notes: >
  Optional free text.

cases:
  - id: health-ok                 # unique within file
    depends: [other-case-id]      # optional: SKIP this case if a listed case FAILED
    request:
      method: GET
      path: /v1/sys/health        # full path including /v1 prefix
      body: {}                    # optional; sent as JSON when present
      headers: {}                 # optional extra headers
    expect:
      status: 200                 # int or list of ints (any accepted)
      body_schema: {}             # optional JSON-schema subset (below)
      exact: {foo: bar}           # optional: deep-equal on a subset (dotted keys OK)
      errors_contain: ["^bad"]    # optional: regex against response errors[] (negative cases)
      body: null                  # optional: assert empty body (204-style)
      absent: [data.kv]           # optional: dotted keys that must NOT be present
                                  # (missing ancestors count as absent)

# Capture + substitution (one spec file = one run; slots are file-scoped):
#   capture_token: true              # shorthand for capture: {token: auth.client_token}
#   capture: {accessor: wrap_info.accessor}   # named slots from dotted response paths
#   use_captured_token: true         # send slot "token" as X-Vault-Token
#   use_captured_token: accessor     # send the named slot instead
# Body strings beginning with "$" are substituted from the captured slots:
#   body: {accessor: "$accessor"}    # unknown "$name" is passed through
#                                    # literally (e.g. regex groups "$1-$2")
```

### body_schema subset

```yaml
{type: object, properties: {..recurses..}, required: [k1, k2],
 items: {..}, enum: [...], const: <value>, pattern: "<regex>"}
# additionalProperties accepted but ignored in v1
```

### Verdicts

| Verdict        | Meaning                                                        |
|----------------|----------------------------------------------------------------|
| PASS           | all assertions matched                                         |
| FAIL           | mismatch; detail printed per case                              |
| FEATURE_ABSENT | case has a non-empty `feature`, target returned **404**, and the spec does not itself accept 404 (documented empty-list 404s evaluate normally) |
| SKIP           | `depends` unmet (or auth persona unavailable)                  |
| ERROR          | transport failure: connection refused, timeout, bad JSON       |

FEATURE_ABSENT is informational: the target may lack a specced feature
(today's OpenBao vs Vault Enterprise). The harness distinguishes
"feature not implemented" from "wrong behavior". Exit code 1 if any FAIL or
ERROR exists; `--strict` additionally fails on FEATURE_ABSENT (for targets
expected to be feature-complete).

## Running

```sh
cd compat/harness
go run . --target http://127.0.0.1:8200 \
         --token "$BAO_TOKEN" \
         --specs ../specs \
         --filter feature=core \
         --format table        # or json
```

Targets: any Vault/OpenBao HTTP API — an OpenBao build, a Vault Community
build, or (when legitimately licensed) a Vault Enterprise build. `--token`,
`BAO_TOKEN`, or `VAULT_TOKEN` supply the `X-Vault-Token` header.

## Roadmap

- v2: scenario specs — multi-step flows with variable capture (the step-up
  login flow: login -> `mfa_requirement_id` -> `sys/mfa/validate`).
- v2: golden-file response snapshots + diff mode.
- Per-feature reports wired into CI (GitHub Actions on the fork).

## Contribution

Code in this tree follows OpenBao's MPL-2.0. The clean-room rules above are
project requirements here and match OpenBao's own CONTRIBUTING.md — a
prerequisite for any future upstream PR.
