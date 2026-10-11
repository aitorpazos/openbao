# Internal UI namespace listing

## Public contract sources

- **[UI]** https://developer.hashicorp.com/vault/api-docs/system/internal-ui-namespaces — **v2.x (latest)**.
- **[NS]** https://developer.hashicorp.com/vault/api-docs/system/namespaces — **v2.x (latest)**; fixture creation/deletion.
- **[HTTP]** https://developer.hashicorp.com/vault/api-docs — **v2.x (latest)**; `X-Vault-Namespace` relative routing, authentication/error envelope, and success/error status conventions.

Only public developer.hashicorp.com documentation defines expectations. No HashiCorp Vault source was consulted. Local implementation and execution findings below are separate baseline observations.

## Surface and traceability

[UI] describes an **authenticated GET** `/sys/internal/ui/namespaces` returning namespaces accessible to the supplied token. No explicit capability on this internal UI path is required. Its sample returns `data.keys: string[]`, including both parent and nested paths (`software/`, `software/eng/`, etc.), and explicitly excludes the root namespace. Internal endpoints make **no backwards-compatibility guarantees**.

`00-internal-ui.yaml` contains six cases:

- Create `compat-ui-list` and then `nested` within it using `X-Vault-Namespace: compat-ui-list/` [NS, HTTP]. Names must not already exist; use only a disposable target.
- Authenticated root-context GET: require `data.keys` array of slash-terminated non-root paths and unordered membership of both `compat-ui-list/` and `compat-ui-list/nested/` [UI]. The regex rejects empty/root-only paths. No fixed ordering, namespace IDs, request IDs, or exact namespace count is asserted.
- GET without token: require 403 and the error envelope [UI authentication requirement; HTTP status/envelope]. Explicit `no_auth` and empty token header prevent accidental root-token injection.
- Delete child, then parent [NS]. Accept 200/204 per [HTTP]. Cleanup depends only on creation, not on successful listing/authentication assertions.

The populated fixture avoids inventing undocumented empty-list/omission behavior. This root-token suite **does not prove restricted-token filtering or the lack of an explicit UI-path policy requirement**. Those need a separately provisioned restricted-token fixture; no dynamic token capture is attempted here. Reserved fixture resources can remain if deletion is asynchronous or a case fails; stop/discard the entire disposable target after the run.

## Current OpenBao observation

`internal/vault/logical_system_paths.go` registers the GET endpoint and its keys response field. The schema comment says keys can be omitted when no namespaces exist, which is not used to weaken the populated-fixture expectation. No implementation file was modified.

## Verification and actual live baseline

PyYAML parsed the file. From `compat/harness`:

```text
go run . --target http://127.0.0.1:1 --token x --specs ../specs/namespaces-ui --format table
```

All six cases loaded and produced connection-refused ERRORs; no loader/schema errors.

Built the repository with `go build -o /tmp/bao-dr-spec .` and ran a disposable in-memory dev server on `127.0.0.1:25441` using `-dev-no-store-token`. Health confirmed initialized/unsealed. Two harness runs produced the same counts:

| File | PASS | FAIL | FEATURE_ABSENT | SKIP | ERROR |
|---|---:|---:|---:|---:|---:|
| `00-internal-ui.yaml` | 3 | 3 | 0 | 0 | 0 |

- PASS: parent creation 200, child creation 200, child deletion 200.
- FAIL: listing 200 omitted `compat-ui-list/nested/` from `data.keys`.
- FAIL: unauthenticated request returned **500**, expected 403. Direct follow-up response body was `{"errors":["client token empty"]}`.
- FAIL: immediate parent deletion returned **400**, expected 200/204. Child deletion is asynchronous in the fork, so this is a fixture cleanup race, not a namespace-listing contract gap. A later manual parent-delete retry returned 200 with `data.status: in-progress`. The suite does not silently broaden the documented successful cleanup expectation to 400; the v1 harness has no polling/delay primitive used here.

The first two FAILs identify listing/authentication compatibility gaps in the tested binary; the third must be interpreted as a cleanup timing issue. No changes were made to mask these outcomes. The server was terminated after verification, discarding the in-memory fixture.
