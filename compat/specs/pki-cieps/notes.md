# pki-cieps — manual provisioning & live-verified scenarios

The auto-run suite (`10-cieps.yaml`) covers the config CRUD, sign/issue wire
shapes and the disabled-service error against a running CIEPS mock. The
scenarios below require reconfiguring the external policy URL between cases
(mock modes via query parameters) and were **live-verified on a dev server
(2026-10-12)**; they are documented here as the reproducible procedure.

## Mock service

`compat/harness/ciepsmock` implements the documented CIEPS v1 webhook
contract (request/response, UUID echo, error/certificate semantics) with a
self-generated signing CA. It is built and run manually:

```
cd compat/harness/ciepsmock && go build -o /tmp/ciepsmock .
mkdir -p /tmp/cieps-mock && cd /tmp/cieps-mock
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem \
  -days 2 -subj '/CN=CIEPS Mock CA'
openssl req -newkey rsa:2048 -nodes -keyout leaf.key -out leaf.csr -subj '/CN=127.0.0.1'
printf 'subjectAltName=IP:127.0.0.1,DNS:localhost\n' > ext.cnf
openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -out leaf.pem \
  -days 2 -extfile ext.cnf
/tmp/ciepsmock -tls-addr 127.0.0.1:8433 -http-addr 127.0.0.1:8434 \
  -cert /tmp/cieps-mock/leaf.pem -key /tmp/cieps-mock/leaf.key
```

`http://127.0.0.1:8434/status` reports the last received request for manual
verification of the `vault_request_key_values` contract (issuance_mode,
mount, requested_issuer_name, vault_generated_private_key).

## Live-verified scenarios (each reconfigures the URL)

Configure the mount (`compat-pkica-cieps` in the suite) with
`POST /v1/<mount>/config/external-policy` `{enabled: true,
external_service_url: "https://127.0.0.1:8433<QUERY>",
trusted_ca: <ca.pem contents>}`, then sign with
`POST /v1/<mount>/external-policy/sign` `{csr: <cieps-leaf.csr contents>}`.

| query            | documented contract                                            | observed |
|------------------|----------------------------------------------------------------|----------|
| (none)           | certificate issued, re-signed by the configured issuer          | 200; `openssl verify` OK against issuing_ca; pubkey == CSR pubkey; Issuer DN == issuer subject; AKI == issuer SKI |
| `?error=1`       | error-only response rejects the request with the verbatim message | 400 `mock: policy rejected the request` |
| `?both=1`        | certificate + error: certificate issued, error becomes a warning | 200 + warning in response |
| `?nonjson=1`     | non-JSON 200 body → internal error, never surfaced verbatim     | 500 `failed to parse the external policy service response` |
| `?mismatch=1`    | request_uuid not echoed → internal error                        | 500 `did not echo the request UUID` |
| `?status=503`    | non-200 → only the status code is surfaced                      | 500 `the external policy service returned status code 503` (mock's verbatim message absent) |
| `?store=1&lease=1` | store_certificate stores the cert; generate_lease (requires store) creates a lease | 200 with lease_id; cert readable at `/v1/<mount>/cert/<serial>` |
| `enabled: false` | friendly rejection before any service contact                   | 400 `the external policy service is not enabled; configure it via pki/config/external-policy first` |

Issue mode additionally generates key material in Vault, builds the CSR on
the user's behalf (documented behavior for `user_request_key_values.csr`),
sends `vault_generated_private_key=true`, and returns `private_key` +
`private_key_type`. Verified for rsa-2048 and ec-256 with
`openssl pkey -pubout` == `openssl x509 -pubkey`.

## Config validation (live-verified)

- Non-HTTPS URL with `enabled: true` → 400
  `external_service_url must be an HTTPS URL`.
- Enabling without any trust material → 400
  `trusted_ca or trusted_leaf_certificate_bundle is required`.
- Enabling with an unparseable `trusted_ca` → 400
  `invalid trust certificate bundle`.
- Trust material is accepted as a PEM bundle (CA chain) and stored verbatim.
