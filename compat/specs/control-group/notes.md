# Control-group conformance scope

## Public sources and provenance

All pages below were fetched directly from `developer.hashicorp.com`; each displayed **`v2.x (latest)`**. This is a rolling documentation label, not a binary version tested. No HashiCorp Vault source, private material, or git commands were used. The census and existing SCIM, rotation-policy and SPIFFE specs informed inventory/format only; the local harness was read for execution capabilities, not as upstream API evidence.

| Source | Evidence used |
| --- | --- |
| https://developer.hashicorp.com/vault/api-docs/system/config-control-group | Enterprise settings: GET/POST/DELETE `/sys/config/control-group`; `max_ttl` in seconds or duration form; read example `{"max_ttl":"4h"}`. |
| https://developer.hashicorp.com/vault/api-docs/system/control-group | POST `/sys/control-group/authorize` and `/sys/control-group/request`, both with required string `accessor`; response examples below. |
| https://developer.hashicorp.com/vault/docs/enterprise/control-groups | Enterprise gating, policy `control_group` factors, identity groups/approvals, controlled capabilities, wrapping-token/accessor approval workflow, ACL and Sentinel integration. |
| https://developer.hashicorp.com/vault/api-docs#http-status-codes | 200 with data, 204 without data; accept both for writes because warnings may produce 200; 400 for missing/invalid data. |
| https://developer.hashicorp.com/vault/api-docs#error-response | Errors are an object containing `errors`, an array of strings; no endpoint-specific error wording assumed. |
| https://developer.hashicorp.com/vault/api-docs/system/wrapping-wrap | Shared POST wrapping API, arbitrary user data and `X-Vault-Wrap-TTL` header; not a documented control-group creation parameter. |
| https://developer.hashicorp.com/vault/api-docs/system/wrapping-unwrap | POST unwrap; wrapping token supplied either as client token or body `token`, never both. |

## Runnable inventory

- `00-config.yaml`: invalid TTL object; create with duration; GET; update with numeric seconds; GET; update with another duration; GET; unconditional DELETE cleanup. No named resources or external services required.
- `10-request-validation.yaml`: missing required accessor at authorize and request endpoints; 400 and documented error-array schema only. No cleanup required.

Use an initialized, unsealed, disposable target with an appropriate Enterprise license when testing Vault and an administrative root-namespace token. Configuration is singleton state: it **must be absent initially**, and there must be no concurrent runs or other control-group consumers. Cleanup removes configuration, not a saved pre-test value. Never run the configuration suite on a production or preconfigured server. The suite does not change activation flags, policies, identity groups, or auth mounts.

Configuration read examples omit an HTTP envelope. As in the existing rotation-policy and SPIFFE specs, GET assertions are intentionally limited to 200/object rather than guessing whether `max_ttl` is top-level or under `data`. This means these cases prove route/operation acceptance, not TTL persistence or enforcement. Exact duration normalization, initial defaults, and read-after-delete status/shape are not specified by the settings page and are deferred. No accepted 404 fallback masks absence of the settings feature.

## Corrections to the proposed research outline

The fetched control-group API page documents **only authorize and request**, each taking **`accessor`**. It does not document `/claim`, `/investigate`, per-path GET/PUT/DELETE `/sys/control-group/:path`, `access_token`, `request_id` plus `selections`, or a special access-token header flow. The settings page documents `max_ttl`, not `unsealed_managers`. Its write method is POST; no separate PUT case is inferred.

Consequently no speculative claim/investigate/unknown-path tests are included. Neither control-group API page specifies the status for a bogus, unknown, expired, or consumed accessor. Generic 404 invalid-path guidance and the unwrap page do not establish that status for a syntactically valid control-group endpoint. Missing **required accessor** is the documented-input negative used instead; do not fabricate a garbage access token or assume 400/404 equivalence. No post-delete 404 is inferred for singleton settings.

## Fixture contract for approval and unwrap coverage

This section is deferred coverage, **not executable placeholder cases or claimed PASS results**. Fixtures must use actual server-returned values, not the UUIDs shown in documentation examples.

1. Provision an isolated secret path with known test data, a requesting entity/token and distinct approving entities/tokens. Create an identity group containing eligible approvers and an ACL policy granting the requester access subject to a `control_group` factor, following the concepts page's group/approval examples. Reserve and clean up all fixture mounts, policies, identities, groups, and tokens; do not use the administrator token to stand in for the constrained requester.
2. Request the protected path as the requester to obtain the documented limited-duration response-wrapping token and its accessor. Capture both securely. The concepts page describes **policy-triggered** wrapping; the shared `/sys/wrapping/wrap` page does not promise that passing a `control_group` parameter creates such a request.
3. POST the actual accessor to `/sys/control-group/request`. The API example documents `data.approved` (boolean), `data.request_path` (string), `data.request_entity` (`id` and `name` strings), and `data.authorizations` (array of objects with `entity_id` and `entity_name` strings). Bind path/entity comparisons to the fixture, not the example values; avoid inventing empty-array versus null behavior before approvals.
4. POST the accessor to `/sys/control-group/authorize` as eligible approvers. The example response has `data.approved` (boolean). Exercise a multiple-approval factor to observe incomplete and completed authorization, then query request status and check the actual authorizer entries. The concepts page says all factors must be satisfied before unwrap. Additional factors, group overlap and controlled capabilities are separate fixture scenarios, not established by these negative tests.
5. After approval, POST `/sys/wrapping/unwrap` and compare the original response with fixture data. Supply the wrapping token in exactly one place: `X-Vault-Token`, or body `token` with a different authorized client token. The unwrap page warns that using it in both locations revokes it without retrieving the value. Rejected/expired/reused-token status assertions need further explicit documentary evidence; none is guessed here.
6. Dispose of the isolated fixture and configuration even if approvals fail. TTL expiry, Sentinel rules, multiple factors and capability-dependent approvals remain separate integration gaps.

## Harness findings and verification boundaries

Inspection of `compat/harness/main.go` shows arbitrary request headers are supported (so `X-Vault-Wrap-TTL` can be sent). However, capture only extracts `auth.client_token`; it does not capture `wrap_info.token`, a wrapping accessor, entity IDs, or interpolate captured values into bodies/paths. Only one captured auth token is retained per spec. A general fixture/capture facility or securely materialized external fixture specs are needed for the multi-identity approval sequence. Do not check live tokens into this directory. No harness changes are part of this task.

Dependencies are same-file only. The current runner skips dependencies only on `FAIL`, not `ERROR` or `FEATURE_ABSENT`; cleanup is deliberately unconditional. Missing-input PASS results are not proof of a working approval engine.

Validation uses PyYAML parsing and the real harness against `http://127.0.0.1:1` solely to exercise strict loading and request construction. Connection-refused ERRORs are expected and do **not** constitute a live Vault/OpenBao conformance result. No licensed server or approval fixture has been exercised by this authoring task.
