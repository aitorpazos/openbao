# DR operation-token route/schema/validation

## Public contract sources

- **[DR]** https://developer.hashicorp.com/vault/api-docs/system/replication/replication-dr — **v2.x (latest)**; read generation progress, start token generation, cancel generation, provide key share, delete DR operation token, reindex, and Merkle check sections.
- **[HTTP]** https://developer.hashicorp.com/vault/api-docs — **v2.x (latest)**; authentication, HTTP status codes, and `errors` array envelope. Invalid/missing input is 400; denied authentication is 403; bodyless successful operations accept 200 or 204 because warnings can produce 200.

Only public developer.hashicorp.com documentation defines expected behavior. No HashiCorp Vault source was consulted. Local OpenBao observations below are baseline evidence, not sources for expectations.

## Scope and traceability

`00-operation-token.yaml` contains 14 cases:

- GET `.../secondary/generate-operation-token/attempt`: top-level `started`, `nonce`, `progress`, `required`, `encoded_token`, `pgp_fingerprint`, and `complete` types from [DR]'s read-progress sample. No fixed nonce, threshold, progress, or state is required.
- POST the same route with a deliberately malformed base64 PGP public key: 400/error shape from [DR]'s parameter type plus [HTTP]. **An empty body is valid**, since `pgp_key` is optional; no invented required OTP assertion.
- DELETE the attempt: successful cancellation, accepting 200/204 [DR, HTTP]. This clears an attempt; use an isolated disposable fixture, never an operator's active ceremony.
- POST `.../generate-operation-token/update`: required `key` and `nonce` omissions produce 400 [DR, HTTP]. Dummy values are not real key shares or nonces. These are general invalid-input probes, not claims about validation order or precise error messages; no attempt is initiated, so an implementation may also reject absent attempt state.
- POST `.../secondary/operation-token/delete`, `.../secondary/reindex`, and `.../secondary/merkle-check`: required `dr_operation_token` omitted, expecting 400/error shape [DR, HTTP]. Reindex supplies documented boolean defaults but never a valid operation token; no successful maintenance operation is attempted.
- Five unauthenticated 403/error-shape probes cover attempt GET/POST/DELETE, update POST, and token-revocation POST [DR, HTTP].

**Route correction:** [DR] documents **POST `/sys/replication/dr/secondary/operation-token/delete`**, not `generate-operation-token/delete`, and does not document a DELETE method for token revocation. No invented route/method is asserted.

**Authentication qualification:** latest [DR] marks the generation and revocation endpoints *conditionally unauthenticated*: no-token access is permitted only when HCL `enable_unauthenticated_access` includes `generate-operation-token`. This suite requires that opt-in to be absent. Otherwise use a DR-secondary-supported batch token, DR operation token, or root token generated on the primary. The no-auth cases remove the harness token explicitly; they must not be interpreted as rejecting the documented opt-in mode.

## Preconditions and intentional exclusions

Full contract verification needs an initialized/unsealed supported DR secondary, root namespace, valid administrative authentication, and no competing generation attempt. The generic dev smoke test below has DR disabled and is not that fixture. Missing-input 400 expectations remain documentation-derived rather than weakened to 404 or state errors for the current implementation.

This suite does not submit actual shares, start a successful generation, decode an OTP/PGP token, revoke a real issued token, or change replication roles. Successful start/update response shapes and the actual key-share ceremony belong to the separate implementation/ceremony lane. Successful reindex warnings and the `data.merkle_corruption_report` response documented in [DR] require valid operation-token fixtures and are likewise not claimed here. GET is the successful response-schema probe; all invalid-input cases require the documented error-envelope schema.

## Current OpenBao observation and live baseline

At inspection/build time, searches of `internal/vault` found no `generate-operation-token` or `operation-token` routes. `logical_system_replication.go` contained general `replication/merkle-check`, not the documented DR-secondary route. Concurrent replication implementation work may change this snapshot; no implementation files were modified.

Built successfully with `go build -o /tmp/bao-dr-spec .`, then ran a fresh in-memory dev server on `127.0.0.1:25441` with `-dev-no-store-token`. Health confirmed initialized, unsealed, and DR disabled. Actual harness result:

| File | PASS | FAIL | FEATURE_ABSENT | SKIP | ERROR |
|---|---:|---:|---:|---:|---:|
| `00-operation-token.yaml` | 5 | 0 | 9 | 0 | 0 |

All nine authenticated probes returned 404; the five unauthenticated probes returned 403. **The five PASS results do not prove route implementation**: authentication middleware can reject an unknown path before dispatch. Route/validation and read-progress shape implementation remain unverified/absent in this binary. The server was terminated after testing.

PyYAML parsed the file. From `compat/harness`, `go run . --target http://127.0.0.1:1 --token x --specs ../specs/dr-ops --format table` loaded every case: 14 connection-refused ERRORs, no loader/schema errors. Live invocation used the same command with the disposable dev URL/token.
