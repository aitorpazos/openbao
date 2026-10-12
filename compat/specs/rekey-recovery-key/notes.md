# Recovery-key rekey conformance specifications

## Sources and version

Public HashiCorp documentation was fetched and reviewed, including the rendered
parameter lists and examples. Every page displayed **v2.x (latest)**. This moving
label is not a claim about older Vault releases. No Vault implementation source
was consulted. These files add specifications only; they do not implement routes.

| Source (all **v2.x (latest)**) | Contract |
| --- | --- |
| https://developer.hashicorp.com/vault/api-docs/system/rekey-recovery-key | Recovery rekey, verification, backup routes and parameters |
| https://developer.hashicorp.com/vault/api-docs/system/seal-status | Fixture probe: initialized, sealed, recovery_seal |
| https://developer.hashicorp.com/vault/api-docs/system/init | Recovery shares/threshold initialization and auto-unseal constraints |
| https://developer.hashicorp.com/vault/docs/configuration/seal/transit | Transit seal configuration: address, token, key_name, mount_path |
| https://developer.hashicorp.com/vault/api-docs#http-status-codes | 200/204 success and 400 invalid/missing data |
| https://developer.hashicorp.com/vault/api-docs#error-response | errors array of strings |

Although this work belongs to an Enterprise compatibility inventory, do not infer
that every recovery-capable seal is Enterprise-only. The transit configuration
page explicitly says all Vault versions support transit auto-unseal; seal wrapping
requires Enterprise. The recovery API page conditions applicability on a seal
supporting recovery keys and requires the **root namespace**.

## Files and scope

* `00-rekey.yaml`: **18 cases** — recovery-seal fixture gate, idle/configured
  progress, required parameters, threshold ordering, malformed PGP input,
  verification-enabled start, concurrent-start rejection, update required-input
  negatives, recent cancellation without its required nonce, wrong-nonce
  cancellation, unchanged progress, and nonce-captured cleanup.
* `10-verification.yaml`: **7 cases** — optional verification-state fixture gate,
  read progress, required-input negatives, reset verification and read afterward.
* `20-backup.yaml`: **3 cases** — optional PGP-backup fixture gate, read and delete.
* Total: **26 cases**. Dependencies are file-local and backward-referencing.

| Documented method/path (relative to `/v1`) | Executable coverage / limitation |
| --- | --- |
| GET `/sys/rekey-recovery-key/init` | Idle and started configuration/progress |
| POST `/sys/rekey-recovery-key/init` | Start with verification; input and concurrent-start negatives |
| DELETE `/sys/rekey-recovery-key/init` | Missing-nonce rejection for a recent operation; successful cancellation is external cleanup |
| POST `/sys/rekey-recovery-key/update` | Required-input negatives; successful share submission needs external operator-held shares |
| GET `/sys/rekey-recovery-key/verify` | Optional active-verification fixture and progress |
| DELETE `/sys/rekey-recovery-key/verify` | Optional fixture reset response and subsequent progress |
| POST `/sys/rekey-recovery-key/verify` | Optional fixture required-input negatives; threshold completion deferred |
| GET `/sys/rekey/recovery-key-backup` | Optional existing-backup fixture and read shape |
| DELETE `/sys/rekey/recovery-key-backup` | Optional fixture deletion |

**Documentation inconsistency:** the start-rekey `backup` prose mentions
`sys/rekey-recovery-key/backup`, but the backup method tables and curl examples use
`sys/rekey/recovery-key-backup`. These specs use the latter, without inventing an
alias. The samples place response fields at the top level, so the schemas do too;
backup envelope differences should be investigated rather than silently accepted.
No exact error-message strings, UUIDs, fingerprints or generated keys are asserted.
The backup schema checks the nonce and keys-map shape, not encrypted-value content.

The current page adds a nonce requirement when cancelling an operation started
within the last ten minutes. `recent-cancel-requires-nonce` deliberately asserts
that current contract, not older behavior. Complete `00-rekey.yaml` within that
window. The docs also condition unauthenticated access on HCL
`enable_unauthenticated_access` including `rekey`; these specs always supply the
administrative token and do not test that optional authorization configuration.

## Fixture contract and safety

**Critical listener requirement:** the recovery rekey routes
(`/sys/rekey-recovery-key/init|update|verify`) are registered by the HTTP layer
only when the target's listener configuration explicitly sets
`disable_unauthed_rekey_endpoints = false`. Without it — including on plain dev
servers — every rekey-recovery-key route returns 404 `unsupported path`, and
`initial-progress` FAILs while everything depending on it SKIPs. A conforming
target HCL looks like:

```hcl
listener "tcp" {
  address     = "127.0.0.1:8210"
  tls_disable = 1
  disable_unauthed_rekey_endpoints = false
}
storage "inmem" {}
seal "transit" {
  address    = "http://127.0.0.1:8200"
  key_name   = "compat-rekey-key"
  mount_path = "transit/"
  token      = "compat-harness"
}
```

The sealing target is a separate dev server with the `transit` engine mounted
and the referenced key created first. Initialize the sealed target with
`recovery_shares`/`recovery_threshold` only (`secret_shares`/`secret_threshold`
are rejected for a transit seal) — it auto-unseals and returns only recovery
shares plus a root token.

**Disposable targets only. Never run against production recovery state or backups.**
Use an initialized, unsealed target, root namespace, and an administrative/root
token (and a suitable license if required by the Vault deployment). Do not run
concurrently with other rekey operations. No key material is stored in these specs.

### Main suite

`00-rekey.yaml` requires a recovery-capable seal, current recovery threshold **1**,
and **no** pending recovery rekey or verification. It requests a new **2-of-2**
sharing configuration with verification enabled. No valid recovery share is ever
submitted, so this suite cannot complete a rotation.

On a supporting target, it **leaves an attempt pending**. After the run, GET
`/v1/sys/rekey-recovery-key/init`, retain its `nonce`, then DELETE that same path
with JSON `{"nonce":"<actual returned nonce>"}`. Check that `started` is false.
Do not substitute a static example nonce. Alternatively destroy the entire
explicitly disposable in-memory target. Cleanup is not represented as a promise
that a nonce-less DELETE would work against the latest documented API.

A Shamir dev server is **not** this fixture: `recovery_seal` is false. The seal
probe intentionally FAILs, and every main-suite case directly depends on it and
therefore SKIPs. The harness only skips dependencies with verdict **FAIL**;
SKIP, FEATURE_ABSENT and ERROR do not propagate. This is why direct fixture
references are repeated. Dead-target runs still issue every request.

### Verification-only fixture

Run `10-verification.yaml` **alone**, not after expecting `00-rekey.yaml` to
provide its fixture. On a disposable recovery-capable target:

1. Start a 2-of-2 recovery rekey with `require_verification=true`.
2. Submit the current recovery shares to `/update` with the actual init nonce
   until the current threshold is met. Securely retain the returned new shares.
3. Require verification to be active, with a nonempty verification nonce, `n=2`,
   `t=2`, `progress=0` before running this file.
4. The file sends no valid new share. DELETE verify resets verification only; the
   entire rekey remains pending. Cancel via DELETE init with its actual nonce,
   preserving the original recovery keys, or destroy the disposable instance.

The static suite verifies reset shape/zero progress, but not that the new nonce
actually differs or that a nonzero prior progress was cleared. Those relational
checks require a dynamic driver and a partial valid-share submission.

### Backup-only fixture

Run `20-backup.yaml` against a disposable target with a pre-created recovery-rekey
PGP backup. Provision valid binary-exported, base64-encoded public keys (one per
share), set `backup=true`, then authorize rekey with the actual current shares.
Retain recoverable shares independently. The file permanently deletes the backup.
Never supply an important pre-existing backup merely to get a passing result.

A default whole-directory run does **not** provision verification or PGP-backup
fixtures. Their gate cases intentionally accept HTTP 400/404 *at the status
layer only*, then require successful-response fields so missing fixtures produce
**FAIL**, and every dependent operation SKIPs. These FAILs are fixture diagnostics,
not evidence that a supplied valid fixture violates the API. An error-only body
cannot PASS either gate. No negative GET-after-delete status is asserted because
the recovery page does not specify the absent-backup response.

### Deliberately deferred integration checks

No successful rotation, partial-share progress, repeated-share handling, nonce
identity comparison, new-share verification completion, PGP encrypt/decrypt
round trip, ordered fingerprints, encrypted-backup contents, backup removal
persistence, or recovery-key validity after cancellation is claimed. A dynamic
integration driver must retain actual keys and nonces, securely submit thresholds,
and compare state across calls. The harness has named string capture, but these
static cases intentionally contain no externally supplied shares or capture
substitutions: every case must reach the connection-refused transport check in a
dead-target validation run. Placeholder material is used only in negative cases,
never to simulate successful cryptography.

## Live verification on the local OpenBao checkout (updated)

Built the repository with `go build -o /tmp/bao-rekey-fix .` and the harness from
`compat/harness`. The running binary reported version `2.0.0-HEAD`. Results
measure this local build, not a released Vault/OpenBao version. No licensed
Vault server was available, so no Vault success-path verification is claimed.

With the corrected fixture (listener property set, transit-sealed target
initialized with `recovery_shares:1,recovery_threshold:1`), the full recovery
rekey ceremony was driven live over the API:

* `POST /sys/rekey-recovery-key/init` `{secret_shares:1,secret_threshold:1}` →
  200 with a fresh UUID `nonce`, `started:true`, `t:1`, `n:1`, `progress:0`,
  `required:1`.
* `POST /sys/rekey-recovery-key/update` `{key:<current recovery share>,nonce}`
  → 200 `complete:true` with one new plaintext recovery share.
* Cancellation semantics: a recent attempt cannot be cancelled without its
  nonce (400) or with a wrong nonce (400); cancelling with the captured nonce
  returns 204. This matches the documented ten-minute rule and is implemented
  in-tree.
* `POST /init` with missing shares/threshold or `threshold > shares` returns
  **400** (the invalid-configuration status was corrected from 500 to the
  documented 400 convention).
* Verification flow (fixture for `10-verification.yaml`): start 2-of-2 with
  `require_verification:true`, authorize with the current share; the update
  response carries the two new plaintext shares plus a verification nonce, and
  `GET /sys/rekey-recovery-key/verify` then returns
  `{nonce, started:true, t:2, n:2, progress:0}`. Empty/missing-key submissions
  return 400; a wrong verification nonce returns 400; submitting one valid new
  share advances `progress` to 1; submitting the second returns
  `{complete:true}`.
* Backup flow (fixture for `20-backup.yaml`): start 2-of-2 with
  `pgp_keys:[<base64 binary PGP public key>,...]` and `backup:true`, authorize;
  the update response carries `complete:true`, `backup:true`, PGP fingerprints,
  and PGP-**encrypted** (not plaintext) shares. `GET /sys/rekey/
  recovery-key-backup` then returns 200 `{nonce, keys}`; DELETE returns 204 and
  a subsequent GET returns 400 `no backed-up keys found`.
* A sign-only PGP key (no encryption subkey) is rejected at authorization time
  with a PGP encryption error; the pending attempt survives and can be
  cancelled with its nonce. Use an encryption-capable key (`gpg --quick-generate-key
  '<uid>' rsa2048 encr 0`, export binary, base64).

Re-run from `compat/harness`:

```sh
go run . --target http://127.0.0.1:1 --token compat-harness \
  --specs ../specs/rekey-recovery-key --format table
go run . --target "$TARGET" --token "$TOKEN" \
  --specs ../specs/rekey-recovery-key --format table
# For independently prepared optional fixtures, pass a single file:
go run . --target "$TARGET" --token "$TOKEN" \
  --specs ../specs/rekey-recovery-key/10-verification.yaml --format table
```

Whole-directory runs against a target without the optional verification/backup
fixtures intentionally produce one FAIL per gate (see the fixture sections
above); the fixture-gated cases SKIP. Dead-target validation: all rows ERROR
with `connection refused`, zero loader/schema/dependency errors. Temporary
servers are stopped after verification; private initialization material and the
token-bearing HCL are removed. No real secrets, generated recovery shares, or
root tokens are committed in this directory.
